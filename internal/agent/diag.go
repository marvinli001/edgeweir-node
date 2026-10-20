package agent

import (
	"context"
	"strings"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/diag"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/version"
)

// maxClockRTT: a heartbeat slower than this does not measure the clock
// (the offset is off by up to half the round trip).
const maxClockRTT = 10 * time.Second

// clockSample is the node's clock against the console's.
type clockSample struct {
	// Positive: the node's clock is ahead.
	offset time.Duration
	rtt    time.Duration
	at     time.Time
}

// measureClock compares the console's time in an answer with the middle of
// the request's round trip on the node's clock; nil for an answer without
// it or a round trip over maxClockRTT.
func measureClock(sent, received, console time.Time) *clockSample {
	rtt := received.Sub(sent)
	if console.IsZero() || rtt < 0 || rtt > maxClockRTT {
		return nil
	}
	// Wall clock only: console carries no monotonic reading.
	mid := sent.Round(0).Add(rtt / 2)
	return &clockSample{offset: mid.Sub(console), rtt: rtt, at: received}
}

// noteReport records a heartbeat the console answered.
func (a *Agent) noteReport(resp *nodev1.ReportStatusResponse, sent, received time.Time, interval time.Duration) {
	var console time.Time
	if t := resp.GetConsoleTime(); t != nil && t.IsValid() {
		console = t.AsTime()
	}
	clock := measureClock(sent, received, console)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reportOK = received
	a.reportInterval = interval
	a.latestRevision = resp.GetLatestRevision()
	if clock != nil {
		a.clock = clock
	}
}

// noteReportError records a heartbeat that failed.
func (a *Agent) noteReportError(err error, at time.Time) {
	msg := err.Error()
	if len(msg) > 512 {
		msg = msg[:512]
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reportErr, a.reportErrAt = msg, at
}

// diagStatus is what the diagnostics socket answers.
func (a *Agent) diagStatus() diag.Status {
	st := diag.Status{Version: version.Version, StartedAt: a.startedAt}
	if ch := a.connectedCh.Load(); ch != nil {
		if id := ch.Identity(); id != nil {
			st.NodeID, st.ClusterID, st.NodeName = id.NodeID, id.ClusterID, id.NodeName
			st.CertificateNotAfter = id.Certificate.NotAfter
		}
	}
	if f := a.follow.Load(); f != nil {
		if cs := f.Status(); cs != nil {
			st.Console = &diag.Console{
				URL:         cs.GetCurrent().GetUrl(),
				ServerName:  cs.GetCurrent().GetServerName(),
				FallbackURL: cs.GetFallback().GetUrl(),
				OnFallback:  cs.GetOnFallback(),
				FailedURL:   cs.GetFailed().GetUrl(),
				ErrorCode:   cs.GetErrorCode(),
				Error:       cs.GetError(),
			}
			if t := cs.GetFailedAt(); t != nil {
				st.Console.FailedAt = t.AsTime()
			}
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	st.Report = diag.Report{
		LastOK:          a.reportOK,
		LastError:       a.reportErr,
		LastErrorAt:     a.reportErrAt,
		IntervalSeconds: int(a.reportInterval / time.Second),
	}
	st.Config = diag.Config{
		AppliedRevision:     a.applied.GetRevision(),
		LatestRevision:      a.latestRevision,
		State:               strings.ToLower(strings.TrimPrefix(a.state.String(), "APPLY_STATE_")),
		Message:             a.message,
		DataPlaneHealthy:    a.dpHealthy,
		CertificateFailures: len(a.certUse.report()),
	}
	if c := a.clock; c != nil {
		st.Clock = &diag.Clock{OffsetMillis: c.offset.Milliseconds(), RTTMillis: c.rtt.Milliseconds(), MeasuredAt: c.at}
	}
	return st
}

// serveDiagSocket serves the diagnostics socket (Config.DiagSocket) until
// ctx ends.
func (a *Agent) serveDiagSocket(ctx context.Context) error {
	if a.cfg.DiagSocket == "" {
		return nil
	}
	return diag.Serve(ctx, a.cfg.DiagSocket, a.diagStatus, a.log)
}
