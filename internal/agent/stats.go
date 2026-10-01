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

// statsBatch is one ReportStatsV2 call: the sites' buckets and the
// layer-4 applications' (at most statsBatchSize together).
type statsBatch struct {
	Sequence uint64                  `json:"sequence"`
	Stats    []*nodev1.MinuteStats   `json:"stats"`
	L4       []*nodev1.L4MinuteStats `json:"l4,omitempty"`
}

func (b statsBatch) size() int { return len(b.Stats) + len(b.L4) }

type statsSpool struct {
	NodeID  string       `json:"node_id"`
	Last    uint64       `json:"last"`
	Batches []statsBatch `json:"batches"`
}

func (a *Agent) statsPath() string { return filepath.Join(a.cfg.StateDir, "traffic-spool.json") }
func (a *Agent) initStatsSpool(ctx context.Context) (*statsSpool, error) {
	id := a.channel.Identity().NodeID
	state := &statsSpool{NodeID: id}
	if info, err := os.Stat(a.statsPath()); err == nil && info.Size() <= maxStatsSpoolBytes {
		raw, err := os.ReadFile(a.statsPath())
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, state); err != nil || state.NodeID != id {
			a.log.Warn("discarding unreadable or previous-identity statistics spool")
			state = &statsSpool{NodeID: id}
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	// Reading the authenticated cursor also recovers safely after a lost/corrupt
	// local sequence file: fresh batches must never reuse an accepted sequence.
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	defer cancel()
	resp, err := a.channel.Client().ReportStatsV2(cctx, connect.NewRequest(&nodev1.ReportStatsV2Request{}))
	if err != nil {
		return nil, err
	}
	cursor := resp.Msg.GetBatchSequence()
	state.Last = max(state.Last, cursor)
	var remaining []statsBatch
	previous := cursor
	for _, batch := range state.Batches {
		if batch.Sequence <= cursor {
			continue
		}
		if batch.Sequence <= previous || batch.Sequence > state.Last || batch.size() > statsBatchSize {
			return nil, fmt.Errorf("invalid statistics spool ordering")
		}
		remaining = append(remaining, batch)
		previous = batch.Sequence
	}
	state.Batches = remaining
	if err := a.saveStatsSpool(state); err != nil {
		return nil, err
	}
	return state, nil
}
func (a *Agent) saveStatsSpool(state *statsSpool) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	for len(raw) > maxStatsSpoolBytes && len(state.Batches) > 0 {
		a.log.Warn("dropping oldest unsent statistics batch: spool size limit", "buckets", state.Batches[0].size())
		state.Batches = state.Batches[1:]
		raw, err = json.Marshal(state)
		if err != nil {
			return err
		}
	}
	return fsutil.WriteFileAtomic(a.statsPath(), raw, 0600)
}

// statsLoop persists the sequence and immutable payload before making a call.
// A lost acknowledgement, failed local ACK write, or agent restart resends the
// same sequence. New counters stay in Lua while a drained batch awaits a disk write. A crash
// before that write may lose the in-memory batch.
//
// Once every batch is acknowledged, the loop reports its statistics watermark
// (complete_until) with an empty cursor query: the start of the minute in
// which the last successful drain began. The data plane drains every minute
// before the minute of its own clock at drain time, which is not earlier, so
// every minute before the watermark has been uploaded. While the plan has
// layer-4 applications, their minutes are drained too (from the stream
// subsystem) and travel in the same batches; a drain counts as successful
// only when both succeeded.
func (a *Agent) statsLoop(ctx context.Context) {
	var state *statsSpool
	dirty := false
	var drained, reported time.Time
	ticker := time.NewTicker(a.cfg.StatsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if state == nil {
			var err error
			state, err = a.initStatsSpool(ctx)
			if err != nil {
				a.logRPCError("statistics spool initialization failed", err)
				continue
			}
		}
		if !dirty {
			boundary := time.Now().UTC().Truncate(time.Minute)
			sites, l4, complete := a.drainStats(ctx)
			if complete {
				drained = boundary
			}
			batches, ok := packStats(state.Last, sites, l4)
			if !ok {
				a.log.Error("statistics sequence exhausted")
				return
			}
			if len(batches) > 0 {
				state.Batches = append(state.Batches, batches...)
				state.Last = batches[len(batches)-1].Sequence
				dirty = true
			}
			pending := 0
			for _, b := range state.Batches {
				pending += b.size()
			}
			for pending > maxStatsPending {
				n := state.Batches[0].size()
				state.Batches = state.Batches[1:]
				pending -= n
				a.log.Warn("dropping oldest unsent statistics batch: bucket limit", "buckets", n)
			}
		}
		if dirty {
			if err := a.saveStatsSpool(state); err != nil {
				a.log.Error("statistics spool write failed; upload paused", "err", err)
				continue
			}
			dirty = false
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
			candidate := &statsSpool{NodeID: state.NodeID, Last: state.Last, Batches: state.Batches[1:]}
			if err := a.saveStatsSpool(candidate); err != nil {
				a.log.Error("cannot persist statistics acknowledgement; batch will be retried", "err", err)
				break
			}
			state = candidate
			a.markConnected()
		}
		if len(state.Batches) == 0 && !dirty && drained.After(reported) {
			cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
			_, err := a.channel.Client().ReportStatsV2(cctx, connect.NewRequest(&nodev1.ReportStatsV2Request{CompleteUntil: timestamppb.New(drained)}))
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					a.logRPCError("reporting the statistics watermark failed; will retry", err)
				}
				continue
			}
			reported = drained
		}
	}
}

// drainStats takes the completed minutes out of the data plane: the
// sites', and the layer-4 applications' while the plan has some. complete
// reports that every drain succeeded (the watermark may advance).
func (a *Agent) drainStats(ctx context.Context) (sites []*nodev1.MinuteStats, l4 []*nodev1.L4MinuteStats, complete bool) {
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	items, err := a.dp.DrainStats(dctx)
	if err != nil {
		a.log.Debug("cannot drain data plane stats", "err", err)
	}
	var l4Items []dataplane.L4MinuteStats
	var l4Err error
	if a.planHasL4() {
		if l4Items, l4Err = a.dp.DrainL4Stats(dctx); l4Err != nil {
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
