package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maxStatsSpoolBytes = 32 << 20
const maxStatsPending = 10000
const statsBatchSize = 1000

// statsLossHold is how long the watermark stays at the first minute of
// dropped statistics (the longest offline threshold of the console's usage
// settings is 24 hours).
const statsLossHold = 24 * time.Hour

// statsBatch is one ReportStatsV2 call: the sites' buckets and the
// layer-4 applications' (at most statsBatchSize together).
type statsBatch struct {
	Sequence uint64                  `json:"sequence"`
	Stats    []*nodev1.MinuteStats   `json:"stats"`
	L4       []*nodev1.L4MinuteStats `json:"l4,omitempty"`
}

func (b statsBatch) size() int { return len(b.Stats) + len(b.L4) }

// firstMinute is the earliest minute of the batch's buckets (zero for none).
func (b statsBatch) firstMinute() time.Time {
	var first time.Time
	for _, m := range b.Stats {
		if t := m.GetMinute().AsTime(); first.IsZero() || t.Before(first) {
			first = t
		}
	}
	for _, m := range b.L4 {
		if t := m.GetMinute().AsTime(); first.IsZero() || t.Before(first) {
			first = t
		}
	}
	return first
}

type statsSpool struct {
	NodeID  string       `json:"node_id"`
	Last    uint64       `json:"last"`
	Batches []statsBatch `json:"batches"`
	// Loose holds buckets drained before the console's cursor was read
	// (no sequence yet); they are numbered after it.
	Loose []statsBatch `json:"loose,omitempty"`
	// LostFrom is the first minute of buckets dropped for the spool limits
	// (Unix seconds, 0 for none): the watermark stays there for
	// statsLossHold.
	LostFrom int64 `json:"lost_from,omitempty"`
}

func (s *statsSpool) pending() int {
	n := 0
	for _, b := range s.Batches {
		n += b.size()
	}
	for _, b := range s.Loose {
		n += b.size()
	}
	return n
}

// dropOldest drops the oldest unsent batch (sequenced ones first, they are
// older) and records the first minute it held. It returns the buckets
// dropped (0 when there was nothing).
func (s *statsSpool) dropOldest() int {
	var b statsBatch
	switch {
	case len(s.Batches) > 0:
		b, s.Batches = s.Batches[0], s.Batches[1:]
	case len(s.Loose) > 0:
		b, s.Loose = s.Loose[0], s.Loose[1:]
	default:
		return 0
	}
	if first := b.firstMinute(); !first.IsZero() && (s.LostFrom == 0 || first.Unix() < s.LostFrom) {
		s.LostFrom = first.Unix()
	}
	return b.size()
}

func (a *Agent) statsPath() string { return filepath.Join(a.cfg.StateDir, "traffic-spool.json") }

// loadStatsSpool reads the spool from disk; one that is unreadable or of
// another identity starts over.
func (a *Agent) loadStatsSpool() *statsSpool {
	id := a.channel.Identity().NodeID
	state := &statsSpool{NodeID: id}
	info, err := os.Stat(a.statsPath())
	if err != nil {
		if !os.IsNotExist(err) {
			a.log.Warn("cannot read the statistics spool; starting a new one", "err", err)
		}
		return state
	}
	if info.Size() > maxStatsSpoolBytes {
		a.log.Warn("discarding an oversized statistics spool")
		return state
	}
	raw, err := os.ReadFile(a.statsPath())
	if err == nil {
		err = json.Unmarshal(raw, state)
	}
	if err != nil || state.NodeID != id {
		a.log.Warn("discarding unreadable or previous-identity statistics spool")
		return &statsSpool{NodeID: id}
	}
	return state
}

// syncStatsSpool reads the console's cursor and drops the batches it
// acknowledged; then the loose buckets are numbered after it.
func (a *Agent) syncStatsSpool(ctx context.Context, state *statsSpool) error {
	// Reading the authenticated cursor also recovers safely after a lost/corrupt
	// local sequence file: fresh batches must never reuse an accepted sequence.
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	defer cancel()
	resp, err := a.channel.Client().ReportStatsV2(cctx, connect.NewRequest(&nodev1.ReportStatsV2Request{}))
	if err != nil {
		return err
	}
	cursor := resp.Msg.GetBatchSequence()
	last := max(state.Last, cursor)
	var remaining []statsBatch
	previous := cursor
	for _, batch := range state.Batches {
		if batch.Sequence <= cursor {
			continue
		}
		if batch.Sequence <= previous || batch.Sequence > last || batch.size() > statsBatchSize {
			return fmt.Errorf("invalid statistics spool ordering")
		}
		remaining = append(remaining, batch)
		previous = batch.Sequence
	}
	for _, batch := range state.Loose {
		if last >= 9223372036854775807 {
			return fmt.Errorf("statistics sequence exhausted")
		}
		last++
		batch.Sequence = last
		remaining = append(remaining, batch)
	}
	state.Last, state.Batches, state.Loose = last, remaining, nil
	return a.saveStatsSpool(state)
}

func (a *Agent) saveStatsSpool(state *statsSpool) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	for len(raw) > maxStatsSpoolBytes {
		n := state.dropOldest()
		if n == 0 {
			break
		}
		a.log.Warn("dropping oldest unsent statistics batch: spool size limit", "buckets", n,
			"lost_from", time.Unix(state.LostFrom, 0).UTC())
		if raw, err = json.Marshal(state); err != nil {
			return err
		}
	}
	return fsutil.WriteFileAtomic(a.statsPath(), raw, 0600)
}

// statsLoop drains the data plane every StatsInterval into the spool on
// disk, also while the console is unreachable (the data plane keeps
// undrained counters for two hours only), and uploads the spool in order.
// It persists the sequence and immutable payload before making a call. A
// lost acknowledgement, failed local ACK write, or agent restart resends
// the same sequence. New counters stay in Lua while a drained batch awaits
// a disk write. A crash before that write may lose the in-memory batch.
// When it stops, it drains everything, the current minute included, into
// the spool: Run stops nginx only after that.
//
// Once every batch is acknowledged, the loop reports its statistics watermark
// (complete_until) with an empty cursor query: the start of the minute in
// which the last successful drain began. The data plane drains every minute
// before the minute of its own clock at drain time, which is not earlier, so
// every minute before the watermark has been uploaded. While the plan has
// layer-4 applications, their minutes are drained too (from the stream
// subsystem) and travel in the same batches; a drain counts as successful
// only when both succeeded. After buckets were dropped for the spool
// limits, the watermark stays at their first minute for statsLossHold.
func (a *Agent) statsLoop(ctx context.Context) {
	state := a.loadStatsSpool()
	synced := false
	dirty := false
	var drained, reported time.Time
	ticker := time.NewTicker(a.cfg.StatsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			a.flushStats(state, synced)
			return
		case <-ticker.C:
		}
		if !synced {
			if err := a.syncStatsSpool(ctx, state); err != nil {
				a.logRPCError("statistics spool initialization failed", err)
			} else {
				synced = true
			}
		}
		if !dirty {
			boundary := time.Now().UTC().Truncate(time.Minute)
			sites, l4, complete := a.drainStats(ctx, false)
			if complete {
				drained = boundary
			}
			if !a.spoolStats(state, synced, sites, l4) {
				return
			}
			dirty = len(sites)+len(l4) > 0
		}
		if state.LostFrom != 0 && time.Since(time.Unix(state.LostFrom, 0)) > statsLossHold {
			a.log.Info("statistics watermark released after dropped buckets", "lost_from", time.Unix(state.LostFrom, 0).UTC())
			state.LostFrom, dirty = 0, true
		}
		if dirty {
			if err := a.saveStatsSpool(state); err != nil {
				a.log.Error("statistics spool write failed; upload paused", "err", err)
				continue
			}
			dirty = false
		}
		if !synced {
			continue
		}
		for len(state.Batches) > 0 {
			batch := state.Batches[0]
			cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
			resp, err := a.channel.Client().ReportStatsV2(cctx, connect.NewRequest(&nodev1.ReportStatsV2Request{Stats: batch.Stats, L4Stats: batch.L4, BatchSequence: batch.Sequence}))
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					a.logRPCError("ReportStats failed; will retry the same batch", err)
				}
				break
			}
			if resp.Msg.GetBatchSequence() != batch.Sequence {
				a.log.Warn("statistics acknowledgement sequence mismatch")
				break
			}
			candidate := &statsSpool{NodeID: state.NodeID, Last: state.Last, Batches: state.Batches[1:], LostFrom: state.LostFrom}
			if err := a.saveStatsSpool(candidate); err != nil {
				a.log.Error("cannot persist statistics acknowledgement; batch will be retried", "err", err)
				break
			}
			state = candidate
			a.markConnected()
		}
		watermark := drained
		if state.LostFrom != 0 && time.Unix(state.LostFrom, 0).Before(watermark) {
			watermark = time.Unix(state.LostFrom, 0).UTC()
		}
		if len(state.Batches) == 0 && !dirty && watermark.After(reported) {
			cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
			_, err := a.channel.Client().ReportStatsV2(cctx, connect.NewRequest(&nodev1.ReportStatsV2Request{CompleteUntil: timestamppb.New(watermark)}))
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					a.logRPCError("reporting the statistics watermark failed; will retry", err)
				}
				continue
			}
			reported = watermark
		}
	}
}

// spoolStats adds drained buckets to the spool: numbered batches once the
// console's cursor is known, loose ones before. Beyond maxStatsPending
// buckets the oldest batches are dropped. It returns false when the
// sequence is exhausted.
func (a *Agent) spoolStats(state *statsSpool, synced bool, sites []*nodev1.MinuteStats, l4 []*nodev1.L4MinuteStats) bool {
	if synced {
		batches, ok := packStats(state.Last, sites, l4)
		if !ok {
			a.log.Error("statistics sequence exhausted")
			return false
		}
		if len(batches) > 0 {
			state.Batches = append(state.Batches, batches...)
			state.Last = batches[len(batches)-1].Sequence
		}
	} else if batches, _ := packStats(0, sites, l4); len(batches) > 0 {
		for i := range batches {
			batches[i].Sequence = 0
		}
		state.Loose = append(state.Loose, batches...)
	}
	for state.pending() > maxStatsPending {
		n := state.dropOldest()
		a.log.Warn("dropping oldest unsent statistics batch: bucket limit", "buckets", n,
			"lost_from", time.Unix(state.LostFrom, 0).UTC())
	}
	return true
}

// flushStats runs as the loop stops: every counter of the data plane, the
// current minute's included, goes to the spool, since nginx stops next and
// its counters with it. The next start uploads them.
func (a *Agent) flushStats(state *statsSpool, synced bool) {
	fctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sites, l4, _ := a.drainStats(fctx, true)
	if !a.spoolStats(state, synced, sites, l4) {
		return
	}
	if err := a.saveStatsSpool(state); err != nil {
		a.log.Error("cannot save the last statistics before stopping", "err", err)
		return
	}
	if n := len(sites) + len(l4); n > 0 {
		a.log.Info("statistics saved before stopping", "buckets", n)
	}
}

// drainStats takes the completed minutes out of the data plane (with all,
// the current one too): the sites', and the layer-4 applications' while
// the plan has some. complete reports that every drain succeeded (the
// watermark may advance).
func (a *Agent) drainStats(ctx context.Context, all bool) (sites []*nodev1.MinuteStats, l4 []*nodev1.L4MinuteStats, complete bool) {
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	items, err := a.dp.DrainStats(dctx, all)
	if err != nil {
		a.log.Debug("cannot drain data plane stats", "err", err)
	}
	var l4Items []dataplane.L4MinuteStats
	var l4Err error
	if a.planHasL4() {
		if l4Items, l4Err = a.dp.DrainL4Stats(dctx, all); l4Err != nil {
			a.log.Debug("cannot drain layer-4 stats", "err", l4Err)
		}
	}
	return convertStats(items), convertL4Stats(l4Items), err == nil && l4Err == nil
}

// packStats puts buckets into batches of at most statsBatchSize (sites
// first), numbered after last. ok is false when the sequence would
// overflow.
func packStats(last uint64, sites []*nodev1.MinuteStats, l4 []*nodev1.L4MinuteStats) (batches []statsBatch, ok bool) {
	for len(sites) > 0 || len(l4) > 0 {
		if last >= 9223372036854775807 {
			return nil, false
		}
		n := min(statsBatchSize, len(sites))
		m := min(statsBatchSize-n, len(l4))
		last++
		batches = append(batches, statsBatch{Sequence: last, Stats: sites[:n], L4: l4[:m]})
		sites, l4 = sites[n:], l4[m:]
	}
	return batches, true
}

// planHasL4 reports whether the plan in effect has layer-4 applications
// (nginx.conf then has the stream subsystem their statistics come from).
func (a *Agent) planHasL4() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.plan != nil && len(a.plan.L4Apps) > 0
}

// convertL4Stats converts the stream subsystem's buckets (application ids
// are checked like everywhere else in the data plane).
func convertL4Stats(items []dataplane.L4MinuteStats) []*nodev1.L4MinuteStats {
	out := make([]*nodev1.L4MinuteStats, 0, len(items))
	for _, m := range items {
		if !configir.ValidID(m.AppID) || m.Minute <= 0 {
			continue
		}
		out = append(out, &nodev1.L4MinuteStats{
			Minute:         timestamppb.New(time.Unix(m.Minute, 0).UTC()),
			AppId:          m.AppID,
			Connections:    m.Connections,
			Refused:        m.Refused,
			PeakConcurrent: m.PeakConcurrent,
			BytesReceived:  m.BytesReceived,
			BytesSent:      m.BytesSent,
		})
	}
	return out
}
