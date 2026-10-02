package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	"github.com/marvinli001/edgeweir-node/internal/retry"
)

// purgeFile persists the purge markers: they must outlive nginx and agent
// restarts for as long as objects cached before the purge may still exist.
const purgeFile = "purge.json"

// defaultPurgeRetention applies before any configuration is known.
const defaultPurgeRetention = 8 * 24 * time.Hour

// purgeTaskRetention keeps task epochs at least as long as the console may
// hand a task out again (7 days).
const purgeTaskRetention = 8 * 24 * time.Hour

// purgeFallbackRetry is how long a site-level fallback set stays installed
// before the full set is tried again.
const purgeFallbackRetry = time.Minute

func (a *Agent) purgePath() string { return filepath.Join(a.cfg.StateDir, purgeFile) }

// loadPurge reads the persisted markers. A missing file means none; an
// unreadable one means markers were lost: the first plan then gets a
// site-level marker for every site (over-purging instead of serving purged
// objects).
func (a *Agent) loadPurge() {
	st := newPurgeState()
	raw, err := os.ReadFile(a.purgePath())
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		a.log.Error("cannot read stored purge markers; every site will be purged once", "err", err)
		st.lost = true
	default:
		if loaded, perr := unmarshalPurge(raw); perr != nil {
			a.log.Error("stored purge markers are unreadable; every site will be purged once", "err", perr)
			st.lost = true
		} else {
			st = loaded
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.purge = st
	a.prunePurgeLocked(time.Now())
}

// purgeRetentionLocked is how long a marker must live: until every object
// cached before it has been evicted for inactivity (the longest `inactive`
// of the cache zones), plus a margin.
func (a *Agent) purgeRetentionLocked() time.Duration {
	if a.plan == nil {
		return defaultPurgeRetention
	}
	var longest time.Duration
	for _, z := range a.plan.CacheZones {
		longest = max(longest, time.Duration(z.InactiveSeconds)*time.Second)
	}
	return longest + time.Hour
}

// prunePurgeLocked drops expired markers and task epochs; a.mu must be held.
func (a *Agent) prunePurgeLocked(now time.Time) bool {
	a.lastPrune = now
	markerCutoff := now.Add(-a.purgeRetentionLocked()).UnixMilli()
	taskCutoff := now.Add(-max(a.purgeRetentionLocked(), purgeTaskRetention)).UnixMilli()
	return a.purge.prune(markerCutoff, taskCutoff)
}

// maybePrunePurge prunes at most once a minute (markers expire in hours).
func (a *Agent) maybePrunePurge(now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if now.Sub(a.lastPrune) < time.Minute {
		return
	}
	if a.prunePurgeLocked(now) {
		if err := a.savePurgeLocked(); err != nil {
			a.log.Warn("cannot persist purge markers", "err", err)
		}
	}
}

func (a *Agent) savePurgeLocked() error {
	raw, err := a.purge.marshal()
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(a.purgePath(), raw, 0o600)
}

func (a *Agent) purgeID() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.purge.id()
}

// taskEpoch assigns (and persists) the marker time of a purge task.
func (a *Agent) taskEpoch(taskID string) int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, known := a.purge.tasks[taskID]
	e := a.purge.taskEpoch(taskID, time.Now())
	if !known {
		if err := a.savePurgeLocked(); err != nil {
			a.log.Warn("cannot persist purge task time", "err", err)
		}
	}
	return e
}

// addMarkers merges markers into the persisted set (bounded per site) and
// returns what the data plane must merge, the collapsed sites and the id
// of the resulting set.
func (a *Agent) addMarkers(markers []dataplane.PurgeMarker) ([]dataplane.PurgeMarker, []string, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delta, collapsed, changed := a.purge.add(markers, a.cfg.PurgeMarkersPerSite, a.cfg.PurgeTagsPerSite)
	var err error
	if changed {
		err = a.savePurgeLocked()
	}
	return delta, collapsed, a.purge.id(), err
}

// collapsePurgeSites replaces the markers of sites by site-level markers
// (sites the data plane could not hold).
func (a *Agent) collapsePurgeSites(sites []string) {
	if len(sites) == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	changed := false
	for _, s := range sites {
		if a.purge.collapse(s) {
			changed = true
		}
	}
	if changed {
		a.purge.bump()
		if err := a.savePurgeLocked(); err != nil {
			a.log.Warn("cannot persist purge markers", "err", err)
		}
	}
	a.log.Warn("purge markers did not fit in the data plane; replaced by site-level markers", "sites", sites)
}

// recoverLostPurge adds a site-level marker for every site of plan when the
// stored markers were lost.
func (a *Agent) recoverLostPurge(plan *configir.Plan) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.purge.lost || len(plan.Sites) == 0 {
		return
	}
	epoch := a.purge.taskEpoch("", time.Now())
	var markers []dataplane.PurgeMarker
	for _, s := range plan.Sites {
		markers = append(markers, dataplane.PurgeMarker{SiteID: s.ID, Type: "site", Epoch: epoch})
	}
	a.purge.add(markers, 0, 0)
	a.purge.lost = false
	if err := a.savePurgeLocked(); err != nil {
		a.log.Warn("cannot persist purge markers", "err", err)
	}
	a.log.Warn("stored purge markers were lost: purged every site once", "sites", len(markers))
}

func (a *Agent) fullPurgeTable() (*dataplane.PurgeTable, *dataplane.PurgeTable) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.purge.table(), a.purge.compact()
}

// syncPurgeWithRetry is syncPurge with the retries of site pushes (nginx
// may still be starting; see retryWrite).
func (a *Agent) syncPurgeWithRetry(ctx context.Context) error {
	return a.retryWrite(ctx, 10*time.Second, a.syncPurge)
}

// syncPurge installs the full marker set unless the data plane already has
// it. It runs before site tables are pushed after an nginx restart, so a
// fresh data plane never serves a purged object. When the full set cannot
// be installed, a site-level marker for every site with markers is
// installed instead (it purges at least as much); the full set is retried
// later. An error means not even that worked.
func (a *Agent) syncPurge(ctx context.Context) error {
	a.purgeMu.Lock()
	defer a.purgeMu.Unlock()
	st, err := a.dp.Status(ctx)
	if err != nil {
		return err
	}
	a.mu.Lock()
	inSync := st.Purge.ID == a.purge.id()
	// The fallback of the current set stays until purgeRetryAt; a fallback
	// of an older set is replaced at once.
	holdFallback := st.Purge.ID == a.purge.compactID() && time.Now().Before(a.purgeRetryAt)
	a.mu.Unlock()
	if inSync || holdFallback {
		return nil
	}
	want, fallback := a.fullPurgeTable()
	res, err := a.dp.PutPurge(ctx, want)
	if err == nil {
		a.log.Info("purge markers installed in data plane", "markers", len(want.Markers), "id", want.ID)
		a.collapsePurgeSites(res.Collapsed)
		return nil
	}
	var apiErr *dataplane.APIError
	if errors.As(err, &apiErr) && apiErr.Status == 507 {
		// Not even one marker per site of the full set fits: keep only
		// site-level markers from now on.
		var sites []string
		for _, m := range fallback.Markers {
			sites = append(sites, m.SiteID)
		}
		a.collapsePurgeSites(sites)
	}
	if _, ferr := a.dp.PutPurge(ctx, fallback); ferr != nil {
		// The fallback's failure tells whether a retry can help.
		return fmt.Errorf("install purge markers: %v (site-level fallback: %w)", err, ferr)
	}
	a.mu.Lock()
	a.purgeRetryAt = time.Now().Add(purgeFallbackRetry)
	a.mu.Unlock()
	a.log.Warn("cannot install the purge markers; installed site-level markers for the affected sites instead",
		"err", err, "sites", len(fallback.Markers))
	return nil
}

// pushMarkers merges markers into the data plane, retrying transient
// failures (see retryWrite). When they do not fit, the full set is
// installed instead (with the per-site fallback).
func (a *Agent) pushMarkers(ctx context.Context, t *dataplane.PurgeTable) error {
	err := a.retryWrite(ctx, 10*time.Second, func(ctx context.Context) error {
		a.purgeMu.Lock()
		defer a.purgeMu.Unlock()
		_, err := a.dp.AddPurge(ctx, t)
		return err
	})
	if err == nil {
		a.log.Info("purge markers added to data plane", "markers", len(t.Markers), "id", t.ID)
		return nil
	}
	if retry.IsPermanent(err) {
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return a.syncPurge(cctx)
	}
	return err
}
