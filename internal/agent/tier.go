package agent

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/pki"
	"github.com/marvinli001/edgeweir-node/internal/render"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Tiered cache (ADR-0073): nginx authenticates both ways with the node
// certificate. The agent copies it, its key and the node CA under the
// nginx prefix (names by the certificate's fingerprint, so a renewal
// changes nginx.conf), measures the round trip time to the console's
// latency targets and reports them with the heartbeat.

const (
	// tierLatencyInterval is how often the targets are measured.
	tierLatencyInterval = time.Minute
	// tierLatencyAttempts TCP handshakes per target and round; the fastest counts.
	tierLatencyAttempts = 3
	tierLatencyTimeout  = 3 * time.Second
	// tierLatencyMaxAge drops results not renewed for this long.
	tierLatencyMaxAge = 5 * time.Minute
	// tierLatencyParallel targets are measured at once.
	tierLatencyParallel = 16
)

// tierUpperCapable reports whether cert may serve TLS to lower tiers (its
// extended key usages include serverAuth).
func tierUpperCapable(cert *x509.Certificate) bool {
	return cert != nil && slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
}

// tierFeatures are the tiered cache's features of this node:
// tier-upper-v1 once its certificate can serve TLS.
func (a *Agent) tierFeatures() []string {
	if a.channel == nil {
		return nil
	}
	if id := a.channel.Identity(); id != nil && tierUpperCapable(id.Certificate) {
		return []string{configir.FeatureTierUpper}
	}
	return nil
}

// prepareTier writes the copies of the node certificate, key and CA that
// nginx.conf names for plan's tiered cache and fills in their paths. Without
// an identity (not enrolled) the node takes no part in the tiered cache:
// its sites fetch from the origins.
func (a *Agent) prepareTier(plan *configir.Plan) error {
	t := plan.Tier
	if t == nil || (!t.Lower && !t.Listen) {
		return nil
	}
	store := identity.Store{Dir: a.cfg.StateDir}
	certPEM, certErr := os.ReadFile(store.Path(identity.CertFile))
	keyPEM, keyErr := os.ReadFile(store.Path(identity.KeyFile))
	caPEM, caErr := os.ReadFile(store.Path(identity.CAFile))
	var cert *x509.Certificate
	if certErr == nil {
		cert, certErr = pki.ParseCertificatePEM(certPEM)
	}
	if err := firstErr(certErr, keyErr, caErr); err != nil {
		plan.Warnings = append(plan.Warnings, "tiered cache off: node certificate unavailable: "+err.Error())
		plan.Tier = nil
		for i := range plan.Sites {
			plan.Sites[i].Tier = nil
		}
		return nil
	}
	if t.Listen && !tierUpperCapable(cert) {
		// Lower tiers would refuse it: the console names only tier-upper-v1
		// nodes, so this is a plan made before a renewal took effect.
		plan.Warnings = append(plan.Warnings, "tiered cache: this node's certificate cannot serve lower tiers until it is renewed")
		t.Listen = false
		t.Clients = nil
	}
	sum := sha256.Sum256(cert.Raw)
	certPath, keyPath, caPath := render.TierFiles(a.cfg.Render.Prefix, hex.EncodeToString(sum[:]))
	dir := filepath.Dir(certPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create tier certificate directory: %w", err)
	}
	user := a.cfg.Render.User
	if err := chownToUser(user, dir); err != nil {
		return err
	}
	if err := letWorkersIn(user, dir); err != nil {
		return err
	}
	for _, f := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{{certPath, certPEM, 0o644}, {keyPath, keyPEM, 0o600}, {caPath, caPEM, 0o644}} {
		if err := writeIfChanged(f.path, f.data, f.mode); err != nil {
			return fmt.Errorf("write tier certificate: %w", err)
		}
		if err := chownToUser(user, f.path); err != nil {
			return err
		}
	}
	t.CertPath, t.KeyPath, t.CAPath = certPath, keyPath, caPath
	pruneTierFiles(dir, certPath, keyPath, caPath)
	return nil
}

// pruneTierFiles removes the copies of earlier certificates.
func pruneTierFiles(dir string, keep ...string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if !slices.Contains(keep, p) {
			_ = os.Remove(p)
		}
	}
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// reapplyAfterRenewal renders the current plan again when the tiered cache
// uses the node certificate, so that nginx serves and presents the renewed
// one.
func (a *Agent) reapplyAfterRenewal(ctx context.Context) {
	a.mu.Lock()
	plan := a.plan
	a.mu.Unlock()
	if plan == nil || plan.Tier == nil {
		return
	}
	if err := a.applyPlan(ctx, plan); err != nil {
		a.log.Warn("cannot serve the renewed certificate to the tiered cache", "err", err)
	}
}

// tierLatencies holds the latest measurement of each target.
type tierLatencies struct {
	mu      sync.Mutex
	results map[string]*nodev1.TierLatency
}

func (l *tierLatencies) set(r *nodev1.TierLatency) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.results == nil {
		l.results = map[string]*nodev1.TierLatency{}
	}
	l.results[r.GetTargetId()] = r
}

// report returns the results of the targets still configured, measured in
// the last tierLatencyMaxAge, sorted by target id.
func (l *tierLatencies) report(targets []configir.TierLatencyTarget, now time.Time) []*nodev1.TierLatency {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []*nodev1.TierLatency
	for _, t := range targets {
		r := l.results[t.ID]
		if r != nil && now.Sub(r.GetMeasuredAt().AsTime()) <= tierLatencyMaxAge {
			out = append(out, r)
		}
	}
	return out
}

// tierTargets are the latency targets of the applied plan.
func (a *Agent) tierTargets() []configir.TierLatencyTarget {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.plan == nil || a.plan.Tier == nil {
		return nil
	}
	return a.plan.Tier.LatencyTargets
}

// tierLatencyLoop measures the latency targets every tierLatencyInterval.
func (a *Agent) tierLatencyLoop(ctx context.Context) {
	t := time.NewTimer(jittered(10 * time.Second))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.measureTierTargets(ctx, a.tierTargets())
		t.Reset(jittered(tierLatencyInterval))
	}
}

func (a *Agent) measureTierTargets(ctx context.Context, targets []configir.TierLatencyTarget) {
	sem := make(chan struct{}, tierLatencyParallel)
	var wg sync.WaitGroup
	for _, target := range targets {
		sem <- struct{}{}
		wg.Go(func() {
			defer func() { <-sem }()
			a.tierLatency.set(measureTierTarget(ctx, a.originDialer(), target))
		})
	}
	wg.Wait()
}

// originDialer resolves and connects like the origin layer would: the
// names through the system resolver, every address checked against the
// origin address policy.
func (a *Agent) originDialer() func(ctx context.Context, host string, port uint32) (net.Conn, error) {
	var allowed []string
	a.mu.Lock()
	if a.plan != nil {
		allowed = a.plan.OriginAllowedCIDRs
	}
	a.mu.Unlock()
	policy, _, _ := configir.NewAddressPolicy(allowed)
	return func(ctx context.Context, host string, port uint32) (net.Conn, error) {
		var d net.Dialer
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if policy.Forbidden(ip.Unmap()) {
				continue
			}
			return d.DialContext(ctx, "tcp", net.JoinHostPort(ip.Unmap().String(), strconv.FormatUint(uint64(port), 10)))
		}
		return nil, fmt.Errorf("no usable address for %s", host)
	}
}

// measureTierTarget returns the fastest of tierLatencyAttempts TCP
// handshakes to target.
func measureTierTarget(ctx context.Context, dial func(context.Context, string, uint32) (net.Conn, error), target configir.TierLatencyTarget) *nodev1.TierLatency {
	best := time.Duration(-1)
	for range tierLatencyAttempts {
		actx, cancel := context.WithTimeout(ctx, tierLatencyTimeout)
		start := time.Now()
		conn, err := dial(actx, target.Host, target.Port)
		took := time.Since(start)
		cancel()
		if err != nil {
			continue
		}
		_ = conn.Close()
		if best < 0 || took < best {
			best = took
		}
	}
	r := &nodev1.TierLatency{TargetId: target.ID, MeasuredAt: timestamppb.Now()}
	if best >= 0 {
		r.Ok = true
		r.RttMs = uint32(max(best.Milliseconds(), 1))
	}
	return r
}
