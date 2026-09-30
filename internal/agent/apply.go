package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/render"
)

// permanentError marks failures that will recur for the same configuration
// (hash mismatch, validation, nginx -t); such revisions are not retried
// until a new revision appears or rejectRetryAfter has passed.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

const rejectRetryAfter = 5 * time.Minute

// applyPlan makes the data plane serve plan:
//   - render nginx.conf; if it changed (structural change: listeners, cache
//     zones, resolver) or the engine is not running: write it next to the
//     live file, `openresty -t`, install it and reload;
//   - push the site table through the control socket (hot update, no reload).
func (a *Agent) applyPlan(ctx context.Context, plan *configir.Plan) (resultErr error) {
	a.activationMu.Lock()
	defer a.activationMu.Unlock()
	for _, listener := range plan.Listeners {
		if listener.TLS {
			if err := a.ensureBootstrapCertificate(); err != nil {
				return err
			}
			break
		}
	}
	conf, err := render.Render(a.cfg.Render, plan)
	if err != nil {
		return &permanentError{err}
	}
	for _, z := range plan.CacheZones {
		dir := filepath.Join(a.cfg.Render.CacheDir, z.Name)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create cache dir: %w", err)
		}
		if err := chownToUser(a.cfg.Render.User, dir); err != nil {
			return err
		}
	}

	a.mu.Lock()
	current := a.conf
	previousTable := a.desired
	a.mu.Unlock()
	touched := false
	defer func() {
		if resultErr == nil || !touched {
			return
		}
		recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.cfg.ReloadTimeout+a.cfg.PushTimeout+5*time.Second)
		defer cancel()
		var restoreErr error
		if current != nil && !bytes.Equal(current, conf) {
			restoreErr = fsutil.WriteFileAtomic(a.cfg.ConfPath, current, 0o644)
			if restoreErr == nil {
				restoreErr = a.engine.Reload(recovery)
			}
			if restoreErr == nil {
				restoreErr = a.waitForConf(recovery, render.ConfID(current))
			}
		}
		if previousTable != nil {
			restoreErr = errors.Join(restoreErr, a.pushWithRetry(recovery, previousTable))
		}
		if restoreErr != nil {
			a.setDataPlaneHealthy(false)
			resultErr = errors.Join(resultErr, fmt.Errorf("restore previous data plane: %w", restoreErr))
		}
	}()
	if !bytes.Equal(conf, current) || !a.engine.Running() {
		next := a.cfg.ConfPath + ".next"
		if err := fsutil.WriteFileAtomic(next, conf, 0o644); err != nil {
			return err
		}
		if err := a.engine.Test(ctx, next); err != nil {
			_ = os.Remove(next)
			return &permanentError{err}
		}
		if err := fsutil.Rename(next, a.cfg.ConfPath); err != nil {
			return err
		}
		touched = true
		err := a.engine.Reload(ctx)
		if err == nil {
			err = a.waitForConf(ctx, render.ConfID(conf))
		}
		if err != nil {
			// nginx keeps running the previous file after a failed reload;
			// put it back so that a restart does not pick up the new one.
			if current != nil {
				if rerr := fsutil.WriteFileAtomic(a.cfg.ConfPath, current, 0o644); rerr != nil {
					a.log.Error("cannot restore the previous nginx.conf", "err", rerr)
				}
			}
			return &permanentError{err}
		}
		a.log.Info("nginx configuration installed and reloaded",
			"listeners", len(plan.Listeners), "cache_zones", len(plan.CacheZones), "conf", a.cfg.ConfPath)
	}

	// Purge markers go in before sites: a data plane that just (re)started
	// must never serve a purged object. A failure never blocks the sites
	// (see syncPurge for the site-level fallback).
	a.recoverLostPurge(plan)
	if err := a.syncPurgeWithRetry(ctx); err != nil {
		a.log.Warn("cannot install purge markers before the site table; retrying in the background", "err", err)
	}
	table := dataplane.FromPlan(plan)
	table.CDNID = a.cdnID()
	touched = true
	if err := a.pushWithRetry(ctx, table); err != nil {
		return err
	}
	a.mu.Lock()
	a.conf = conf
	a.desired = table
	a.plan = plan
	a.mu.Unlock()
	return nil
}

// waitForConf waits until the data plane's workers run the configuration
// with id want. A HUP (or `-s reload`) only asks nginx to reload: when the
// new file cannot be applied (e.g. a port is taken) nginx logs the error
// and keeps the old workers, so success is only known once a worker
// reports the new id.
func (a *Agent) waitForConf(ctx context.Context, want string) error {
	deadline := time.Now().Add(a.cfg.ReloadTimeout)
	var last string
	for {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		st, err := a.dp.Status(cctx)
		cancel()
		if err == nil {
			if st.ConfID == want {
				return nil
			}
			last = st.ConfID
		}
		if time.Now().After(deadline) {
			if err != nil {
				return fmt.Errorf("nginx did not come up with the new configuration within %s: %w", a.cfg.ReloadTimeout, err)
			}
			return fmt.Errorf("nginx did not load the new configuration within %s (still running %q); see the nginx log", a.cfg.ReloadTimeout, last)
		}
		if !sleepCtx(ctx, 100*time.Millisecond) {
			return ctx.Err()
		}
	}
}

// push installs table in the data plane (serialized).
func (a *Agent) push(ctx context.Context, table *dataplane.SiteTable) error {
	a.pushMu.Lock()
	defer a.pushMu.Unlock()
	return a.pushLocked(ctx, table)
}

// pushDesired installs the current desired table. Reading it under pushMu
// guarantees a concurrent apply cannot be overwritten by an older table.
func (a *Agent) pushDesired(ctx context.Context) error {
	a.activationMu.Lock()
	defer a.activationMu.Unlock()
	a.pushMu.Lock()
	defer a.pushMu.Unlock()
	a.mu.Lock()
	table := a.desired
	a.mu.Unlock()
	if table == nil {
		return nil
	}
	return a.pushLocked(ctx, table)
}

func (a *Agent) pushLocked(ctx context.Context, table *dataplane.SiteTable) error {
	st, err := a.dp.PutSites(ctx, table)
	if err != nil {
		return err
	}
	a.setDataPlaneHealthy(true)
	a.log.Info("site table pushed to data plane", "revision", table.Revision,
		"sites", st.SiteCount, "table_version", st.Version)
	return nil
}

// pushWithRetry retries transient failures (nginx still starting) within
// the push timeout.
func (a *Agent) pushWithRetry(ctx context.Context, table *dataplane.SiteTable) error {
	deadline := time.Now().Add(a.cfg.PushTimeout)
	delay := 100 * time.Millisecond
	for {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := a.push(cctx, table)
		cancel()
		if err == nil {
			return nil
		}
		var apiErr *dataplane.APIError
		if errors.As(err, &apiErr) && apiErr.Status == 400 {
			return &permanentError{fmt.Errorf("data plane rejected the site table: %w", err)}
		}
		if time.Now().After(deadline) {
			a.setDataPlaneHealthy(false)
			return fmt.Errorf("push site table: %w", err)
		}
		if !sleepCtx(ctx, delay) {
			return ctx.Err()
		}
		delay = min(delay*2, 2*time.Second)
	}
}

func (a *Agent) setDataPlaneHealthy(ok bool) {
	a.mu.Lock()
	changed := a.dpHealthy != ok
	a.dpHealthy = ok
	a.mu.Unlock()
	if changed && a.channel != nil {
		a.triggerReport()
	}
}

// dataPlaneLoop checks the data plane periodically and whenever the engine
// (re)starts. After an nginx restart the shared dicts are empty (status
// version 0), so the desired table is pushed again.
func (a *Agent) dataPlaneLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.DataPlaneInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.reconcileDataPlane(ctx)
			a.reconcileBans(ctx)
		case <-a.engine.Started():
			// The control socket needs a moment after the master starts.
			for range 20 {
				if a.reconcileDataPlane(ctx) || !sleepCtx(ctx, 250*time.Millisecond) {
					break
				}
			}
			a.reconcileBans(ctx)
		}
	}
}

// reconcileDataPlane returns true when the data plane is healthy and in
// sync after the call.
func (a *Agent) reconcileDataPlane(ctx context.Context) bool {
	a.mu.Lock()
	desired := a.desired
	a.mu.Unlock()
	if desired == nil {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := a.dp.Status(cctx)
	if err != nil {
		a.setDataPlaneHealthy(false)
		a.log.Debug("data plane status unavailable", "err", err)
		return false
	}
	a.setDataPlaneHealthy(true)
	a.maybePrunePurge(time.Now())
	purgeOK := true
	if st.Purge.ID != a.purgeID() {
		// The site table is pushed even when this fails: sites must never
		// disappear (404) because purge markers could not be installed.
		if err := a.syncPurge(cctx); err != nil {
			a.log.Warn("cannot install purge markers; pushing the site table anyway", "err", err)
			purgeOK = false
		}
	}
	if st.InSync(desired) {
		return purgeOK
	}
	a.log.Info("data plane out of sync (nginx restarted?), pushing site table",
		"data_plane_revision", st.Revision, "data_plane_table_version", st.Version, "revision", desired.Revision)
	if err := a.pushDesired(cctx); err != nil {
		a.log.Warn("cannot push site table", "err", err)
		return false
	}
	a.mu.Lock()
	failed := a.state == nodev1.ApplyState_APPLY_STATE_FAILED
	a.mu.Unlock()
	if failed && a.channel != nil {
		a.triggerSync() // retry the apply that failed while the data plane was down
	}
	return purgeOK
}

// syncLoop serializes all fetch-and-apply cycles.
func (a *Agent) syncLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.syncCh:
		}
		cctx, cancel := context.WithTimeout(ctx, 2*a.cfg.RPCTimeout)
		cfg, err := a.fetch(cctx)
		if err != nil {
			if ctx.Err() == nil {
				a.logRPCError("GetConfig failed", err)
			}
			cancel()
			continue
		}
		a.consider(cctx, cfg)
		cancel()
	}
}

// fetch retrieves the latest configuration, applying a diff to the local
// LKG when the console sends one. Any diff problem (unknown base, hash
// mismatch) falls back to a full snapshot.
func (a *Agent) fetch(ctx context.Context) (*nodev1.NodeConfig, error) {
	base := a.baseRevision()
	resp, err := a.getConfig(ctx, base)
	if err != nil {
		return nil, err
	}
	switch p := resp.GetPayload().(type) {
	case *nodev1.GetConfigResponse_Snapshot:
		return p.Snapshot, nil
	case *nodev1.GetConfigResponse_Diff:
		applied := a.appliedConfig()
		if base == 0 {
			applied = nil
		}
		cfg, err := configir.ApplyDiff(applied, p.Diff)
		if err == nil {
			return cfg, nil
		}
		a.log.Warn("cannot apply configuration diff; fetching a full snapshot",
			"base_revision", p.Diff.GetBaseRevision(), "revision", p.Diff.GetRevision(), "err", err)
		resp, err = a.getConfig(ctx, 0)
		if err != nil {
			return nil, err
		}
		if s := resp.GetSnapshot(); s != nil {
			return s, nil
		}
		return nil, errors.New("console answered a snapshot request (base_revision=0) without a snapshot")
	default:
		return nil, errors.New("console returned an empty GetConfig response")
	}
}

func (a *Agent) getConfig(ctx context.Context, base uint64) (*nodev1.GetConfigResponse, error) {
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	defer cancel()
	resp, err := a.channel.Client().GetConfig(cctx, connect.NewRequest(&nodev1.GetConfigRequest{
		Revision:     0,
		BaseRevision: base,
	}))
	if err != nil {
		return nil, err
	}
	if err := a.rememberReceipt(resp.Msg); err != nil {
		return nil, err
	}
	a.markConnected()
	return resp.Msg, nil
}

// consider decides whether cfg must be applied.
func (a *Agent) consider(ctx context.Context, cfg *nodev1.NodeConfig) {
	applied := a.appliedConfig()
	sameCluster := applied != nil && a.baseRevision() != 0
	if sameCluster && cfg.GetRevision() == applied.GetRevision() && cfg.GetContentHash() == applied.GetContentHash() {
		return // up to date
	}
	if sameCluster && cfg.GetRevision() < applied.GetRevision() {
		a.log.Warn("console returned an older revision than the applied one; ignoring",
			"revision", cfg.GetRevision(), "applied_revision", applied.GetRevision())
		return
	}
	key := fmt.Sprintf("%d/%s", cfg.GetRevision(), cfg.GetContentHash())
	a.mu.Lock()
	skip := key == a.rejectedKey && time.Since(a.rejectedAt) < rejectRetryAfter
	a.mu.Unlock()
	if skip {
		return
	}
	if err := configir.VerifyHash(cfg); err != nil {
		a.fail(cfg, key, &permanentError{err})
		return
	}
	a.apply(ctx, cfg, key)
}

func (a *Agent) apply(ctx context.Context, cfg *nodev1.NodeConfig, key string) {
	a.mu.Lock()
	previousPlan, previousConfig := a.plan, a.applied
	a.mu.Unlock()
	a.log.Info("applying configuration", "revision", cfg.GetRevision(), "content_hash", cfg.GetContentHash(), "sites", len(cfg.GetSites()))
	plan, err := configir.Build(cfg, a.buildOptions())
	if err != nil {
		a.fail(cfg, key, &permanentError{err})
		return
	}
	if err := a.ensureCredentials(ctx, plan); err != nil {
		a.fail(cfg, key, err) // transient: retried with the next sync
		return
	}
	a.attachCredentials(plan)
	if err := a.ensureCertificates(ctx, plan); err != nil {
		a.fail(cfg, key, err)
		return
	}
	ocspCtx, ocspCancel := context.WithTimeout(ctx, 30*time.Second)
	a.refreshOCSP(ocspCtx, plan)
	ocspCancel()
	if err := a.attachCertificates(plan); err != nil {
		a.fail(cfg, key, err)
		return
	}
	for _, w := range plan.Warnings {
		a.log.Warn("configuration warning", "revision", cfg.GetRevision(), "warning", w)
	}
	if err := a.applyPlan(ctx, plan); err != nil {
		a.fail(cfg, key, err)
		return
	}
	if err := a.lkg.Save(cfg); err != nil {
		if previousPlan == nil {
			previousPlan = configir.Bootstrap(a.cfg.DefaultPort)
		}
		recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.cfg.ReloadTimeout+a.cfg.PushTimeout+5*time.Second)
		restoreErr := a.applyPlan(recovery, previousPlan)
		cancel()
		if previousConfig != nil {
			restoreErr = errors.Join(restoreErr, a.lkg.Save(previousConfig))
		}
		// Repeated disk failures must not briefly reactivate the rejected table on
		// every watch/poll. Retry after the same cooldown as a rejected revision,
		// or immediately when a new revision arrives.
		a.fail(cfg, key, &permanentError{errors.Join(fmt.Errorf("cannot persist last-known-good configuration: %w", err), restoreErr)})
		return
	}
	a.mu.Lock()
	a.applied, a.appliedAt = cfg, time.Now()
	a.state = nodev1.ApplyState_APPLY_STATE_APPLIED
	a.message = summarizeWarnings(plan.Warnings)
	a.rejectedKey = ""
	a.mu.Unlock()
	a.pruneSecrets(cfg, previousConfig)
	a.log.Info("configuration applied", "revision", cfg.GetRevision(), "sites", len(plan.Sites), "warnings", len(plan.Warnings))
	a.triggerKernel() // platform allow lists may have changed
	a.triggerReport()
}

// fail records a failed apply; the previous configuration keeps serving.
func (a *Agent) fail(cfg *nodev1.NodeConfig, key string, err error) {
	var perm *permanentError
	isPerm := errors.As(err, &perm)
	a.mu.Lock()
	a.state = nodev1.ApplyState_APPLY_STATE_FAILED
	a.message = truncate(fmt.Sprintf("revision %d not applied: %v", cfg.GetRevision(), err))
	if isPerm {
		a.rejectedKey, a.rejectedAt = key, time.Now()
	}
	applied := a.applied.GetRevision()
	a.mu.Unlock()
	a.log.Error("configuration not applied; still serving the previous configuration",
		"revision", cfg.GetRevision(), "serving_revision", applied, "err", err)
	a.triggerReport()
}
