package agent

import (
	"context"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

const maxLogsSpoolBytes = 32 << 20
const maxLogsPending = 10000
const logsBatchSize = 1000

type logsBatch struct {
	Sequence uint64              `json:"sequence"`
	Logs     []*nodev1.AccessLog `json:"logs"`
}

func (b logsBatch) sequence() uint64              { return b.Sequence }
func (b logsBatch) numbered(seq uint64) logsBatch { b.Sequence = seq; return b }
func (b logsBatch) size() int                     { return len(b.Logs) }

// firstMinute is zero: access logs have no watermark.
func (b logsBatch) firstMinute() time.Time { return time.Time{} }

func (a *Agent) logsSpool() *spool[logsBatch] {
	return &spool[logsBatch]{a: a, path: filepath.Join(a.cfg.StateDir, "logs-spool.json"), what: "access logs", rpc: "ReportLogs",
		maxBytes: maxLogsSpoolBytes, maxPending: maxLogsPending, batchSize: logsBatchSize}
}

// initLogsSpool reads the spool and the console's cursor, and drops the
// batches the console acknowledged.
func (a *Agent) initLogsSpool(ctx context.Context, sp *spool[logsBatch]) (*spoolFile[logsBatch], error) {
	state, err := sp.load(a.channel.Identity().NodeID)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	defer cancel()
	resp, err := a.channel.Client().ReportLogs(cctx, connect.NewRequest(&nodev1.ReportLogsRequest{}))
	if err != nil {
		return nil, err
	}
	if err := sp.sync(state, resp.Msg.GetBatchSequence()); err != nil {
		return nil, err
	}
	return state, nil
}

// packLogs puts records into batches of at most logsBatchSize, numbered
// after last. ok is false when the sequence would overflow.
func packLogs(last uint64, logs []*nodev1.AccessLog) (batches []logsBatch, ok bool) {
	for len(logs) > 0 {
		if last >= maxSpoolSequence {
			return nil, false
		}
		n := min(logsBatchSize, len(logs))
		last++
		batches = append(batches, logsBatch{Sequence: last, Logs: logs[:n]})
		logs = logs[n:]
	}
	return batches, true
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
	sp := a.logsSpool()
	var state *spoolFile[logsBatch]
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
			state, err = a.initLogsSpool(ctx, sp)
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
			if !sp.add(state, true, func(last uint64) ([]logsBatch, bool) { return packLogs(last, items) }) {
				return
			}
			dirty = len(items) > 0
		}
		if dirty {
			if err := sp.save(state); err != nil {
				a.log.Error("access logs spool write failed; upload paused", "err", err)
				continue
			}
			dirty = false
		}
		state = sp.upload(ctx, state, func(ctx context.Context, b logsBatch) (uint64, error) {
			cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
			defer cancel()
			resp, err := a.channel.Client().ReportLogs(cctx, connect.NewRequest(&nodev1.ReportLogsRequest{Logs: b.Logs, BatchSequence: b.Sequence}))
			if err != nil {
				return 0, err
			}
			return resp.Msg.GetBatchSequence(), nil
		})
	}
}
