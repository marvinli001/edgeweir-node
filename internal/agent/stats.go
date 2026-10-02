package agent

import (
	"context"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
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

func (b statsBatch) sequence() uint64 { return b.Sequence }

func (b statsBatch) numbered(seq uint64) statsBatch { b.Sequence = seq; return b }

func (a *Agent) statsSpool() *spool[statsBatch] {
	return &spool[statsBatch]{a: a, path: filepath.Join(a.cfg.StateDir, "traffic-spool.json"), what: "statistics", rpc: "ReportStats",
		maxBytes: maxStatsSpoolBytes, maxPending: maxStatsPending, batchSize: statsBatchSize}
}

// loadStatsSpool reads the spool from disk; one that cannot be read
// starts over.
func (a *Agent) loadStatsSpool(sp *spool[statsBatch]) *spoolFile[statsBatch] {
	id := a.channel.Identity().NodeID
	state, err := sp.load(id)
	if err != nil {
		a.log.Warn("cannot read the statistics spool; starting a new one", "err", err)
		return &spoolFile[statsBatch]{NodeID: id}
	}
	return state
}

// syncStatsSpool reads the console's cursor and drops the batches it
// acknowledged; then the loose buckets are numbered after it.
func (a *Agent) syncStatsSpool(ctx context.Context, sp *spool[statsBatch], state *spoolFile[statsBatch]) error {
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	defer cancel()
	resp, err := a.channel.Client().ReportStatsV2(cctx, connect.NewRequest(&nodev1.ReportStatsV2Request{}))
	if err != nil {
		return err
	}
	return sp.sync(state, resp.Msg.GetBatchSequence())
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
	sp := a.statsSpool()
	state := a.loadStatsSpool(sp)
	synced := false
	dirty := false
	var drained, reported time.Time
	ticker := time.NewTicker(a.cfg.StatsInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			a.flushStats(sp, state, synced)
			return
		case <-ticker.C:
		}
		if !synced {
			if err := a.syncStatsSpool(ctx, sp, state); err != nil {
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
			if !spoolStats(sp, state, synced, sites, l4) {
				return
			}
			dirty = len(sites)+len(l4) > 0
		}
		if state.LostFrom != 0 && time.Since(time.Unix(state.LostFrom, 0)) > statsLossHold {
			a.log.Info("statistics watermark released after dropped buckets", "lost_from", time.Unix(state.LostFrom, 0).UTC())
			state.LostFrom, dirty = 0, true
		}
		if dirty {
			if err := sp.save(state); err != nil {
				a.log.Error("statistics spool write failed; upload paused", "err", err)
				continue
			}
			dirty = false
		}
		if !synced {
			continue
		}
		state = sp.upload(ctx, state, func(ctx context.Context, b statsBatch) (uint64, error) {
			cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
			defer cancel()
			resp, err := a.channel.Client().ReportStatsV2(cctx, connect.NewRequest(&nodev1.ReportStatsV2Request{Stats: b.Stats, L4Stats: b.L4, BatchSequence: b.Sequence}))
			if err != nil {
				return 0, err
			}
			return resp.Msg.GetBatchSequence(), nil
		})
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

// spoolStats adds drained buckets to the spool (see spool.add).
func spoolStats(sp *spool[statsBatch], state *spoolFile[statsBatch], synced bool, sites []*nodev1.MinuteStats, l4 []*nodev1.L4MinuteStats) bool {
	return sp.add(state, synced, func(last uint64) ([]statsBatch, bool) { return packStats(last, sites, l4) })
}

// flushStats runs as the loop stops: every counter of the data plane, the
// current minute's included, goes to the spool, since nginx stops next and
// its counters with it. The next start uploads them.
func (a *Agent) flushStats(sp *spool[statsBatch], state *spoolFile[statsBatch], synced bool) {
	fctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sites, l4, _ := a.drainStats(fctx, true)
	if !spoolStats(sp, state, synced, sites, l4) {
		return
	}
	if err := sp.save(state); err != nil {
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
		if last >= maxSpoolSequence {
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
