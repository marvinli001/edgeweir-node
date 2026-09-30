package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maxStatsSpoolBytes = 32 << 20
const maxStatsPending = 10000
const statsBatchSize = 1000

type statsBatch struct {
	Sequence uint64                `json:"sequence"`
	Stats    []*nodev1.MinuteStats `json:"stats"`
}
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
		if batch.Sequence <= previous || batch.Sequence > state.Last || len(batch.Stats) > statsBatchSize {
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
		a.log.Warn("dropping oldest unsent statistics batch: spool size limit", "buckets", len(state.Batches[0].Stats))
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
// every minute before the watermark has been uploaded.
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
			dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			items, err := a.dp.DrainStats(dctx)
			cancel()
			if err != nil {
				a.log.Debug("cannot drain data plane stats", "err", err)
			} else {
				drained = boundary
			}
			converted := convertStats(items)
			for len(converted) > 0 {
				if state.Last >= 9223372036854775807 {
					a.log.Error("statistics sequence exhausted")
					return
				}
				n := min(statsBatchSize, len(converted))
				state.Last++
				state.Batches = append(state.Batches, statsBatch{Sequence: state.Last, Stats: converted[:n]})
				converted = converted[n:]
				dirty = true
			}
			pending := 0
			for _, b := range state.Batches {
				pending += len(b.Stats)
			}
			for pending > maxStatsPending {
				n := len(state.Batches[0].Stats)
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
			resp, err := a.channel.Client().ReportStatsV2(cctx, connect.NewRequest(&nodev1.ReportStatsV2Request{Stats: batch.Stats, BatchSequence: batch.Sequence}))
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
