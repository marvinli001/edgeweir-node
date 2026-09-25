package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/edgeweir/edgeweir-node/internal/dataplane"
	"github.com/edgeweir/edgeweir-node/internal/fsutil"
)

// purgeFile persists the purge markers: they must outlive nginx and agent
// restarts for as long as objects cached before the purge may still exist.
const purgeFile = "purge.json"

// defaultPurgeRetention applies before any configuration is known.
const defaultPurgeRetention = 8 * 24 * time.Hour

func markerIdentity(m dataplane.PurgeMarker) string {
	return m.SiteID + "\x00" + m.Type + "\x00" + m.Host + "\x00" + m.Path + "\x00" + m.Query
}

// purgeSetID identifies a marker set (order independent).
func purgeSetID(markers []dataplane.PurgeMarker) string {
	if len(markers) == 0 {
		return "empty"
	}
	keys := make([]string, 0, len(markers))
	for _, m := range markers {
		keys = append(keys, fmt.Sprintf("%s\x00%d", markerIdentity(m), m.Epoch))
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (a *Agent) purgePath() string { return filepath.Join(a.cfg.StateDir, purgeFile) }

// loadPurge reads the persisted markers (missing file: none).
func (a *Agent) loadPurge() {
	raw, err := os.ReadFile(a.purgePath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			a.log.Warn("cannot read stored purge markers", "err", err)
		}
		return
	}
	var stored struct {
		Markers []dataplane.PurgeMarker `json:"markers"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		a.log.Warn("ignoring unreadable purge markers file", "err", err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.markers = stored.Markers
	a.pruneMarkersLocked(time.Now())
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

// pruneMarkersLocked drops expired markers; a.mu must be held.
func (a *Agent) pruneMarkersLocked(now time.Time) {
	cutoff := now.Add(-a.purgeRetentionLocked()).UnixMilli()
	kept := a.markers[:0]
	for _, m := range a.markers {
		if m.Epoch >= cutoff {
			kept = append(kept, m)
		}
	}
	a.markers = kept
}

func (a *Agent) savePurgeLocked() error {
	raw, err := json.Marshal(struct {
		Markers []dataplane.PurgeMarker `json:"markers"`
	}{a.markers})
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(a.purgePath(), raw, 0o600)
}

// addMarkers merges markers into the persisted set (keeping the highest
// epoch per identity) and returns the resulting set id.
func (a *Agent) addMarkers(markers []dataplane.PurgeMarker) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	index := make(map[string]int, len(a.markers))
	for i, m := range a.markers {
		index[markerIdentity(m)] = i
	}
	for _, m := range markers {
		if i, ok := index[markerIdentity(m)]; ok {
			if a.markers[i].Epoch < m.Epoch {
				a.markers[i].Epoch = m.Epoch
			}
			continue
		}
		index[markerIdentity(m)] = len(a.markers)
		a.markers = append(a.markers, m)
	}
	a.pruneMarkersLocked(time.Now())
	return purgeSetID(a.markers), a.savePurgeLocked()
}

func (a *Agent) purgeTable() *dataplane.PurgeTable {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneMarkersLocked(time.Now())
	markers := append([]dataplane.PurgeMarker{}, a.markers...)
	return &dataplane.PurgeTable{ID: purgeSetID(markers), Markers: markers}
}

// syncPurgeWithRetry is syncPurge with the retry budget of site pushes
// (nginx may still be starting).
func (a *Agent) syncPurgeWithRetry(ctx context.Context) error {
	deadline := time.Now().Add(a.cfg.PushTimeout)
	delay := 100 * time.Millisecond
	for {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := a.syncPurge(cctx)
		cancel()
		var apiErr *dataplane.APIError
		if err == nil || (errors.As(err, &apiErr) && apiErr.Status == 400) || time.Now().After(deadline) {
			return err
		}
		if !sleepCtx(ctx, delay) {
			return ctx.Err()
		}
		delay = min(delay*2, 2*time.Second)
	}
}

// syncPurge installs the full marker set unless the data plane already has
// it. It runs before site tables are pushed after an nginx restart, so a
// fresh data plane never serves a purged object.
func (a *Agent) syncPurge(ctx context.Context) error {
	want := a.purgeTable()
	st, err := a.dp.Status(ctx)
	if err != nil {
		return err
	}
	if st.Purge.ID == want.ID {
		return nil
	}
	if _, err := a.dp.PutPurge(ctx, want); err != nil {
		return err
	}
	a.log.Info("purge markers installed in data plane", "markers", len(want.Markers), "id", want.ID)
	return nil
}
