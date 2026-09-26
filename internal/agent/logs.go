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
)

const maxLogsSpoolBytes = 32 << 20
const maxLogsPending = 10000
const logsBatchSize = 1000

type logsBatch struct {
	Sequence uint64              `json:"sequence"`
	Logs     []*nodev1.AccessLog `json:"logs"`
}
type logsSpool struct {
	NodeID  string      `json:"node_id"`
	Last    uint64      `json:"last"`
	Batches []logsBatch `json:"batches"`
}

func (a *Agent) logsPath() string { return filepath.Join(a.cfg.StateDir, "logs-spool.json") }
func (a *Agent) initLogsSpool(ctx context.Context) (*logsSpool, error) {
	id := a.channel.Identity().NodeID
	state := &logsSpool{NodeID: id}
	if info, err := os.Stat(a.logsPath()); err == nil && info.Size() <= maxLogsSpoolBytes {
		raw, err := os.ReadFile(a.logsPath())
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, state); err != nil || state.NodeID != id {
			a.log.Warn("discarding unreadable or previous-identity access logs spool")
			state = &logsSpool{NodeID: id}
		}
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	// Reading the authenticated cursor also recovers safely after a lost/corrupt
	// local sequence file: fresh batches must never reuse an accepted sequence.
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	defer cancel()
	resp, err := a.channel.Client().ReportLogs(cctx, connect.NewRequest(&nodev1.ReportLogsRequest{}))
	if err != nil {
		return nil, err
	}
	cursor := resp.Msg.GetBatchSequence()
	state.Last = max(state.Last, cursor)
	var remaining []logsBatch
	previous := cursor
	for _, batch := range state.Batches {
		if batch.Sequence <= cursor {
			continue
		}
		if batch.Sequence <= previous || batch.Sequence > state.Last || len(batch.Logs) > logsBatchSize {
			return nil, fmt.Errorf("invalid access logs spool ordering")
		}
		remaining = append(remaining, batch)
		previous = batch.Sequence
	}
	state.Batches = remaining
	if err := a.saveLogsSpool(state); err != nil {
		return nil, err
	}
	return state, nil
}
func (a *Agent) saveLogsSpool(state *logsSpool) error {
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	for len(raw) > maxLogsSpoolBytes && len(state.Batches) > 0 {
		a.log.Warn("dropping oldest unsent access logs batch: spool size limit", "buckets", len(state.Batches[0].Logs))
		state.Batches = state.Batches[1:]
		raw, err = json.Marshal(state)
		if err != nil {
			return err
		}
	}
	return fsutil.WriteFileAtomic(a.logsPath(), raw, 0600)
}

// logsLoop persists the sequence and immutable payload before making a call.
// A lost acknowledgement, failed local ACK write, or agent restart resends the
// same sequence. New records stay in Lua while a drained batch awaits a disk write. A crash
// before that write may lose the in-memory batch.
func (a *Agent) logsLoop(ctx context.Context) {
	drain, ok := a.dp.(interface {
		DrainLogs(context.Context) ([]*nodev1.AccessLog, error)
	})
	if !ok {
		return
	}
	var state *logsSpool
	dirty := false
	ticker := time.NewTicker(min(a.cfg.StatsInterval, 10*time.Second))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if state == nil {
			var err error
			state, err = a.initLogsSpool(ctx)
			if err != nil {
				a.logRPCError("access logs spool initialization failed", err)
				continue
			}
		}
		if !dirty {
			dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			items, err := drain.DrainLogs(dctx)
			cancel()
			if err != nil {
				a.log.Debug("cannot drain data plane logs", "err", err)
			}
			converted := items
			for len(converted) > 0 {
				if state.Last >= 9223372036854775807 {
					a.log.Error("access logs sequence exhausted")
					return
				}
				n := min(logsBatchSize, len(converted))
				state.Last++
				state.Batches = append(state.Batches, logsBatch{Sequence: state.Last, Logs: converted[:n]})
				converted = converted[n:]
				dirty = true
			}
			pending := 0
			for _, b := range state.Batches {
				pending += len(b.Logs)
			}
			for pending > maxLogsPending {
				n := len(state.Batches[0].Logs)
				state.Batches = state.Batches[1:]
				pending -= n
				a.log.Warn("dropping oldest unsent access logs batch: bucket limit", "buckets", n)
			}
		}
		if dirty {
			if err := a.saveLogsSpool(state); err != nil {
				a.log.Error("access logs spool write failed; upload paused", "err", err)
				continue
			}
			dirty = false
		}
		for len(state.Batches) > 0 {
			batch := state.Batches[0]
			cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
			resp, err := a.channel.Client().ReportLogs(cctx, connect.NewRequest(&nodev1.ReportLogsRequest{Logs: batch.Logs, BatchSequence: batch.Sequence}))
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					a.logRPCError("ReportLogs failed; will retry the same batch", err)
				}
				break
			}
			if resp.Msg.GetBatchSequence() != batch.Sequence {
				a.log.Warn("access logs acknowledgement sequence mismatch")
				break
			}
			candidate := &logsSpool{NodeID: state.NodeID, Last: state.Last, Batches: state.Batches[1:]}
			if err := a.saveLogsSpool(candidate); err != nil {
				a.log.Error("cannot persist access logs acknowledgement; batch will be retried", "err", err)
				break
			}
			state = candidate
			a.markConnected()
		}
	}
}
