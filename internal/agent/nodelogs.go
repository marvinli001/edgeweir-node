package agent

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/nodelog"
	"github.com/marvinli001/edgeweir-node/internal/upgrade"
)

// Node logs (feature node-logs-v1): the agent's own warnings, errors and
// events (Config.NodeLogs), and those the supervisor keeps of itself and of
// OpenResty, go into nodelogs-spool.json in sealed batches and up to the
// console with ReportNodeLogs, like the access logs. Nothing about the
// upload itself becomes an entry (it would feed itself while the console
// is unreachable).

const (
	nodeLogsBatchSize  = 200
	maxNodeLogsPending = 5000
	maxNodeLogsSpool   = 4 << 20
	// A batch is sealed when it is full or the oldest entry waited this
	// long.
	nodeLogsSealAfter = 5 * time.Second
	nodeLogsInterval  = time.Second
	// A console that answers Unimplemented (older than node-logs-v1) is
	// asked again this often; the spool keeps the entries meanwhile.
	nodeLogsUnsupportedRetry = 10 * time.Minute
	nodeLogsCursorRetry      = 30 * time.Second
)

type nodeLogsBatch struct {
	Sequence           uint64          `json:"sequence"`
	Entries            []nodelog.Entry `json:"entries"`
	DroppedRateLimited uint32          `json:"dropped_rate_limited,omitempty"`
	DroppedOverflow    uint32          `json:"dropped_overflow,omitempty"`
}

func (b nodeLogsBatch) sequence() uint64                  { return b.Sequence }
func (b nodeLogsBatch) numbered(seq uint64) nodeLogsBatch { b.Sequence = seq; return b }
func (b nodeLogsBatch) size() int                         { return len(b.Entries) }

// firstMinute is zero: node logs have no watermark.
func (b nodeLogsBatch) firstMinute() time.Time { return time.Time{} }

func (b nodeLogsBatch) request() *nodev1.ReportNodeLogsRequest {
	req := &nodev1.ReportNodeLogsRequest{BatchSequence: b.Sequence,
		DroppedRateLimited: b.DroppedRateLimited, DroppedOverflow: b.DroppedOverflow}
	for _, e := range b.Entries {
		req.Entries = append(req.Entries, e.Proto())
	}
	return req
}

// supervisorLogs reads the supervisor's buffer.
type supervisorLogs struct {
	client   *upgrade.Client
	instance string
	// last is the number of the last entry read.
	last uint64
	// The drop counters of the last read (marks) and the drops since the
	// last acknowledgement already put into a batch.
	marks          [2]uint64
	since, counted [2]uint64
	unacked        bool
}

// nodeLogsUpload is the state of nodeLogsLoop.
type nodeLogsUpload struct {
	a    *Agent
	log  *slog.Logger
	logs *nodelog.Collector
	sp   *spool[nodeLogsBatch]
	file *spoolFile[nodeLogsBatch]
	// synced: the console's cursor is known (batches are numbered).
	synced      bool
	retryAt     time.Time
	unsupported bool
	pending     []nodelog.Entry
	// Entries dropped since the last batch; own are the collector's
	// counters already counted.
	limited, overflow uint64
	own               [2]uint64
	sealedAt          time.Time
	sup               *supervisorLogs
	// supChecked: the supervisor's capabilities are known.
	supChecked bool
	now        func() time.Time
}

func (a *Agent) nodeLogsLoop(ctx context.Context) {
	if a.cfg.NodeLogs == nil {
		return
	}
	u := a.newNodeLogsUpload()
	ticker := time.NewTicker(nodeLogsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// What is buffered goes to disk for the next start.
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			u.collect(sctx)
			u.seal(sctx, true)
			cancel()
			return
		case <-ticker.C:
		}
		u.collect(ctx)
		u.seal(ctx, false)
		u.upload(ctx)
	}
}

func (a *Agent) newNodeLogsUpload() *nodeLogsUpload {
	u := &nodeLogsUpload{a: a, log: a.log.With(nodelog.Skip), logs: a.cfg.NodeLogs, now: time.Now}
	u.sp = &spool[nodeLogsBatch]{a: a, path: filepath.Join(a.cfg.StateDir, "nodelogs-spool.json"), what: "node logs", rpc: "ReportNodeLogs",
		maxBytes: maxNodeLogsSpool, maxPending: maxNodeLogsPending, batchSize: nodeLogsBatchSize,
		log: u.log, onDrop: func(n int) { u.overflow += uint64(n) }}
	file, err := u.sp.load(a.channel.Identity().NodeID)
	if err != nil {
		u.log.Warn("cannot read the node logs spool; starting a new one", "err", err)
		file = &spoolFile[nodeLogsBatch]{NodeID: a.channel.Identity().NodeID}
	}
	u.file = file
	u.sealedAt = u.now()
	return u
}

// collect takes the agent's new entries and the supervisor's.
func (u *nodeLogsUpload) collect(ctx context.Context) {
	u.pending = append(u.pending, u.logs.Take(maxNodeLogsPending)...)
	limited, overflow := u.logs.Dropped()
	u.limited += limited - u.own[0]
	u.overflow += overflow - u.own[1]
	u.own = [2]uint64{limited, overflow}
	u.checkSupervisor(ctx)
	if s := u.sup; s != nil {
		for range 10 {
			rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			page, err := s.client.ReadLogs(rctx, s.instance, s.last)
			cancel()
			if err != nil {
				u.log.Debug("cannot read the supervisor's node logs", "err", err)
				break
			}
			if page.Instance != s.instance {
				// A new supervisor (or the first read): its numbers.
				s.instance, s.last, s.counted = page.Instance, 0, [2]uint64{}
			}
			u.pending = append(u.pending, page.Entries...)
			s.last = page.Last
			s.marks = [2]uint64{page.RateLimitedMark, page.OverflowMark}
			s.since = [2]uint64{page.DroppedRateLimited, page.DroppedOverflow}
			if len(page.Entries) > 0 {
				s.unacked = true
			}
			if len(page.Entries) < 200 {
				break
			}
		}
		// Drops since the last acknowledgement not yet in a batch.
		for i := range 2 {
			if s.since[i] > s.counted[i] {
				if i == 0 {
					u.limited += s.since[i] - s.counted[i]
				} else {
					u.overflow += s.since[i] - s.counted[i]
				}
				s.counted[i] = s.since[i]
				s.unacked = true
			}
		}
	}
	if over := len(u.pending) - maxNodeLogsPending; over > 0 {
		u.pending = u.pending[over:]
		u.overflow += uint64(over)
	}
}

// checkSupervisor finds out once whether the supervisor keeps OpenResty's
// error log for the agent.
func (u *nodeLogsUpload) checkSupervisor(ctx context.Context) {
	if u.supChecked {
		return
	}
	sock := u.a.cfg.SupervisorSocket
	if sock == "" {
		u.supChecked = true
		return
	}
	client := upgrade.NewClient(sock)
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	caps, err := client.Capabilities(cctx)
	cancel()
	if err != nil {
		return // asked again next time
	}
	u.supChecked = true
	switch {
	case caps.Logs:
		u.sup = &supervisorLogs{client: client}
	case caps.Engine:
		// The supervisor (an older version, kept across self-upgrades)
		// runs OpenResty but keeps no log of it.
		u.a.log.Info("OpenResty's error log reaches the console after the node service restarts (the supervisor predates node logs)",
			nodelog.EventKey, nodelog.EventEngineLogsUnavailable)
	}
}

// seal puts the pending entries into the spool when a batch is full, the
// oldest waited nodeLogsSealAfter or force is set, and lets the supervisor
// drop what is on disk now.
func (u *nodeLogsUpload) seal(ctx context.Context, force bool) {
	if len(u.pending) == 0 && u.limited == 0 && u.overflow == 0 && (u.sup == nil || !u.sup.unacked) {
		u.sealedAt = u.now()
		return
	}
	sealAfter := u.a.cfg.NodeLogsSealAfter
	if sealAfter <= 0 {
		sealAfter = nodeLogsSealAfter
	}
	if !force && len(u.pending) < nodeLogsBatchSize && u.now().Sub(u.sealedAt) < sealAfter {
		return
	}
	limited, overflow := u.limited, u.overflow
	entries := u.pending
	if len(entries) > 0 || limited > 0 || overflow > 0 {
		ok := u.sp.add(u.file, u.synced, func(last uint64) ([]nodeLogsBatch, bool) {
			return packNodeLogs(last, entries, limited, overflow)
		})
		if !ok {
			return
		}
		if err := u.sp.save(u.file); err != nil {
			u.log.Error("node logs spool write failed; upload paused", "err", err)
			return
		}
	}
	u.pending, u.limited, u.overflow = nil, 0, 0
	u.sealedAt = u.now()
	if s := u.sup; s != nil && s.unacked {
		actx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := s.client.AckLogs(actx, upgrade.LogsAck{Instance: s.instance, Upto: s.last, RateLimitedMark: s.marks[0], OverflowMark: s.marks[1]})
		cancel()
		if err != nil {
			u.log.Debug("cannot acknowledge the supervisor's node logs", "err", err)
			return
		}
		s.counted, s.since, s.unacked = [2]uint64{}, [2]uint64{}, false
	}
}

// packNodeLogs puts entries into batches of at most nodeLogsBatchSize,
// numbered after last; the drops go with the last batch (one without
// entries when there are none).
func packNodeLogs(last uint64, entries []nodelog.Entry, limited, overflow uint64) (batches []nodeLogsBatch, ok bool) {
	for {
		if last >= maxSpoolSequence {
			return nil, false
		}
		n := min(nodeLogsBatchSize, len(entries))
		last++
		batches = append(batches, nodeLogsBatch{Sequence: last, Entries: entries[:n]})
		entries = entries[n:]
		if len(entries) == 0 {
			break
		}
	}
	b := &batches[len(batches)-1]
	b.DroppedRateLimited = uint32(min(limited, math.MaxUint32))
	b.DroppedOverflow = uint32(min(overflow, math.MaxUint32))
	return batches, true
}

// upload reads the console's cursor once and sends the sealed batches.
func (u *nodeLogsUpload) upload(ctx context.Context) {
	if u.now().Before(u.retryAt) {
		return
	}
	client := u.a.channel.Client()
	if !u.synced {
		cctx, cancel := context.WithTimeout(ctx, u.a.cfg.RPCTimeout)
		resp, err := client.ReportNodeLogs(cctx, connect.NewRequest(&nodev1.ReportNodeLogsRequest{}))
		cancel()
		if err != nil {
			u.failed(err)
			return
		}
		if err := u.sp.sync(u.file, resp.Msg.GetBatchSequence()); err != nil {
			u.log.Error("node logs spool cannot be synced; starting a new one", "err", err)
			u.file = &spoolFile[nodeLogsBatch]{NodeID: u.file.NodeID, Last: resp.Msg.GetBatchSequence()}
			if err := u.sp.save(u.file); err != nil {
				return
			}
		}
		u.synced, u.unsupported = true, false
	}
	var sendErr error
	u.file = u.sp.upload(ctx, u.file, func(ctx context.Context, b nodeLogsBatch) (uint64, error) {
		cctx, cancel := context.WithTimeout(ctx, u.a.cfg.RPCTimeout)
		defer cancel()
		resp, err := client.ReportNodeLogs(cctx, connect.NewRequest(b.request()))
		if err != nil {
			sendErr = err
			return 0, err
		}
		return resp.Msg.GetBatchSequence(), nil
	})
	if sendErr != nil {
		u.failed(sendErr)
	}
}

// failed waits before the next attempt; a console without ReportNodeLogs
// is asked again after nodeLogsUnsupportedRetry.
func (u *nodeLogsUpload) failed(err error) {
	if connect.CodeOf(err) == connect.CodeUnimplemented {
		if !u.unsupported {
			u.log.Info("the console does not accept node logs yet; keeping them for a newer console")
		}
		u.unsupported, u.synced = true, false
		retry := u.a.cfg.NodeLogsUnsupportedRetry
		if retry <= 0 {
			retry = nodeLogsUnsupportedRetry
		}
		u.retryAt = u.now().Add(retry)
		return
	}
	if !errors.Is(err, context.Canceled) {
		u.log.Debug("node logs upload failed", "err", err)
	}
	if !u.synced {
		u.retryAt = u.now().Add(nodeLogsCursorRetry)
	}
}
