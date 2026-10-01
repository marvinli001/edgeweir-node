package agent

import (
	"context"
	"crypto/x509"
	"os"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/healthcheck"
)

// Active health checks (internal/healthcheck): the agent probes the
// origins of the sites whose pool has an active check and installs the
// origins it finds down in the data plane (PUT /v1/origins/active) on
// every change, at least every ActiveHealthRefresh (30 s) and after an
// nginx restart (the marks live in a shared dict). Every push replaces
// the whole set; the marks expire after max(90 s, 3 x the longest
// interval), so they never outlive an agent that stopped pushing.

// maxActiveMarks is the data plane's bound of one push.
const maxActiveMarks = 10000

// newHealthChecker builds the checker of the agent: the trust store of
// HTTPS origins (--trusted-ca or the system bundle, like nginx) and AAAA
// lookups as for the data plane.
func (a *Agent) newHealthChecker() *healthcheck.Checker {
	opts := a.cfg.ActiveHealth
	if opts.RootCAs == nil {
		opts.RootCAs = a.trustStore()
	}
	opts.IPv6 = opts.IPv6 || a.cfg.Render.ResolverIPv6
	opts.OnChange = func() {
		a.triggerActiveHealth()
		if a.connectedCh.Load() != nil {
			a.triggerReport()
		}
	}
	return healthcheck.New(opts)
}

// trustStore reads the CA bundle that verifies HTTPS origins. Without one
// verification fails, as it does for nginx (fail closed).
func (a *Agent) trustStore() *x509.CertPool {
	pool := x509.NewCertPool()
	path := a.cfg.Render.TrustedCA
	if path == "" {
		return pool
	}
	raw, err := os.ReadFile(path)
	switch {
	case err != nil:
		a.log.Error("cannot read the CA bundle for HTTPS origins; active checks of verified HTTPS origins fail", "file", path, "err", err)
	case !pool.AppendCertsFromPEM(raw):
		a.log.Error("no certificate in the CA bundle for HTTPS origins; active checks of verified HTTPS origins fail", "file", path)
	}
	return pool
}

func (a *Agent) triggerActiveHealth() {
	select {
	case a.activeCh <- struct{}{}:
	default:
	}
}

// activeHealthLoop pushes the active checks' marks when they change and
// refreshes them every ActiveHealthRefresh; a failed push is retried
// after DataPlaneInterval.
func (a *Agent) activeHealthLoop(ctx context.Context) {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.activeCh:
		}
		next := a.cfg.ActiveHealthRefresh
		if err := a.pushActiveHealth(ctx); err != nil {
			a.log.Warn("cannot install the active health marks; retrying", "err", err)
			next = min(next, a.cfg.DataPlaneInterval)
		}
		t.Reset(next)
	}
}

// pushActiveHealth installs the origins the active checks find down.
// Without checks it only clears marks the data plane may still hold (from
// this or an earlier agent).
func (a *Agent) pushActiveHealth(ctx context.Context) error {
	a.activeMu.Lock()
	defer a.activeMu.Unlock()
	if !a.health.Active() && !a.activeMarks {
		return nil
	}
	down := a.health.Down()
	if len(down) > maxActiveMarks {
		a.log.Warn("more origins down than the data plane holds; the rest stay in rotation", "down", len(down), "limit", maxActiveMarks)
		down = down[:maxActiveMarks]
	}
	doc := &dataplane.ActiveHealth{TTL: uint32(a.health.TTL() / time.Second), Down: make([]dataplane.ActiveOrigin, 0, len(down))}
	now := map[healthcheck.Key]bool{}
	for _, k := range down {
		doc.Down = append(doc.Down, dataplane.ActiveOrigin{SiteID: k.SiteID, OriginID: k.OriginID})
		now[k] = true
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := a.dp.PutActiveHealth(cctx, doc); err != nil {
		return err
	}
	a.activeMarks = len(doc.Down) > 0
	for k := range a.activeDown {
		if !now[k] {
			a.log.Info("origin healthy again (active health check)", "site_id", k.SiteID, "origin_id", k.OriginID)
		}
	}
	lastErrors := map[healthcheck.Key]string{}
	for _, s := range a.health.Statuses() {
		lastErrors[s.Key] = s.LastError
	}
	for k := range now {
		if !a.activeDown[k] {
			a.log.Warn("origin down (active health check)", "site_id", k.SiteID, "origin_id", k.OriginID, "error", lastErrors[k])
		}
	}
	a.activeDown = now
	return nil
}
