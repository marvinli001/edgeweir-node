package probe

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marvinli001/edgeweir-node/internal/controlplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1/nodev1connect"
)

// Round settings when the console leaves them out, and their bounds
// (proto: interval 5-60 s, timeout 500-10000 ms, attempts 1-10).
const (
	DefaultInterval = 10 * time.Second
	DefaultTimeout  = 3 * time.Second
	DefaultAttempts = 3
)

// Settings are the timing of one round.
type Settings struct {
	Interval time.Duration
	Timeout  time.Duration
	Attempts int
}

// SettingsFrom takes the round settings from a GetProbeTargets response:
// zero values get the defaults, others are clamped to the proto's bounds.
func SettingsFrom(r *nodev1.GetProbeTargetsResponse) Settings {
	s := Settings{Interval: DefaultInterval, Timeout: DefaultTimeout, Attempts: DefaultAttempts}
	if v := r.GetIntervalSeconds(); v > 0 {
		s.Interval = time.Duration(min(max(v, 5), 60)) * time.Second
	}
	if v := r.GetTimeoutMs(); v > 0 {
		s.Timeout = time.Duration(min(max(v, 500), 10000)) * time.Millisecond
	}
	if v := r.GetAttempts(); v > 0 {
		s.Attempts = int(min(v, 10))
	}
	return s
}

// Runner runs probe rounds: GetProbeTargets, probe, ReportProbeResults,
// then the next round interval_seconds after the start of this one (at
// once when a round took longer). Errors back off exponentially.
type Runner struct {
	// Client returns the ProbeService client (it changes when the
	// credentials are reloaded).
	Client func() nodev1connect.ProbeServiceClient
	// Info describes this process in GetProbeTargets.
	Info *nodev1.ProbeInfo
	// SkipNodeID: targets of this node are left out (a node never probes
	// itself).
	SkipNodeID string
	// Renew renews the client certificate when the console asks for it
	// (renew_certificate) or NeedsRenewal reports it due. Nil when the
	// certificate is renewed elsewhere (a node renews through NodeService).
	Renew        func(ctx context.Context, reason string)
	NeedsRenewal func() bool
	Prober       *Prober
	Log          *slog.Logger
	// RPCTimeout bounds each call (default 30s); BackoffMin and BackoffMax
	// bound the wait after a failed round (default 1s and 60s).
	RPCTimeout time.Duration
	BackoffMin time.Duration
	BackoffMax time.Duration
}

func (r *Runner) log() *slog.Logger {
	if r.Log == nil {
		return slog.Default()
	}
	return r.Log
}

// Run runs rounds until ctx is done.
func (r *Runner) Run(ctx context.Context) {
	minWait, maxWait := r.BackoffMin, r.BackoffMax
	if minWait <= 0 {
		minWait = time.Second
	}
	if maxWait < minWait {
		maxWait = max(60*time.Second, minWait)
	}
	backoff := minWait
	for {
		start := time.Now()
		interval, err := r.Round(ctx)
		if ctx.Err() != nil {
			return
		}
		wait := time.Until(start.Add(interval))
		if err != nil {
			wait = backoff/2 + rand.N(backoff/2+1)
			msg := "probe round failed; retrying in " + wait.Round(time.Millisecond).String()
			if controlplane.IsAuthError(err) {
				r.log().Error(msg+": the console rejected this probe's credentials (deleted or disabled, or the certificate expired?)", "err", err)
			} else {
				r.log().Warn(msg, "err", err)
			}
			backoff = min(backoff*2, maxWait)
		} else {
			backoff = minWait
		}
		t := time.NewTimer(max(wait, 0))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

func (r *Runner) rpcContext(ctx context.Context) (context.Context, context.CancelFunc) {
	d := r.RPCTimeout
	if d <= 0 {
		d = 30 * time.Second
	}
	return context.WithTimeout(ctx, d)
}

// Round runs one round and returns the interval until the next one.
func (r *Runner) Round(ctx context.Context) (time.Duration, error) {
	cctx, cancel := r.rpcContext(ctx)
	resp, err := r.Client().GetProbeTargets(cctx, connect.NewRequest(&nodev1.GetProbeTargetsRequest{Info: r.Info}))
	cancel()
	if err != nil {
		return 0, fmt.Errorf("GetProbeTargets: %w", err)
	}
	msg := resp.Msg
	if r.Renew != nil {
		switch {
		case msg.GetRenewCertificate():
			r.Renew(ctx, "requested by the console")
		case r.NeedsRenewal != nil && r.NeedsRenewal():
			r.Renew(ctx, "less than 1/3 of the certificate lifetime left")
		}
	}
	s := SettingsFrom(msg)
	targets := make([]*nodev1.ProbeTarget, 0, len(msg.GetTargets()))
	unsupported := 0
	for _, t := range msg.GetTargets() {
		switch {
		case r.SkipNodeID != "" && t.GetNodeId() == r.SkipNodeID:
		case !Supported(t):
			unsupported++
		default:
			targets = append(targets, t)
		}
	}
	if unsupported > 0 {
		r.log().Warn("probe targets left out: not an IP literal, port or known method", "count", unsupported)
	}
	started := time.Now()
	results := r.Prober.ProbeAll(ctx, targets, s.Timeout, s.Attempts)
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	cctx, cancel = r.rpcContext(ctx)
	defer cancel()
	rep, err := r.Client().ReportProbeResults(cctx, connect.NewRequest(&nodev1.ReportProbeResultsRequest{
		StartedAt: timestamppb.New(started),
		Results:   results,
	}))
	if err != nil {
		return 0, fmt.Errorf("ReportProbeResults: %w", err)
	}
	lost := 0
	for _, res := range results {
		if res.GetLost() > 0 {
			lost++
		}
	}
	r.log().Debug("probe round reported", "targets", len(results), "with_losses", lost,
		"accepted", rep.Msg.GetAccepted(), "took", time.Since(started).Round(time.Millisecond), "interval", s.Interval)
	return s.Interval, nil
}
