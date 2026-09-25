package agent

import (
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/edgeweir/edgeweir-node/internal/dataplane"
)

// DefaultPurgeMarkersPerSite bounds the URL and prefix markers of one site;
// beyond it the site's markers collapse into one site-level marker.
const DefaultPurgeMarkersPerSite = 1000

// maxPurgeTasks bounds the remembered task epochs.
const maxPurgeTasks = 100_000

// purgeState is the node's purge marker set (persisted in purge.json).
//
// The set is identified by "<generation>-<sequence>": the generation is
// random per state file, the sequence grows with every change, so
// comparing the identifier with the data plane's is O(1) instead of
// hashing every marker.
//
// Marker times (N-M3): a purge task's epoch is assigned by the node when it
// first applies the task, max(now, last+1) in milliseconds, and recorded
// per task id so that a task handed out again keeps its time. The
// console's created_at is not trusted: transactions committed out of order
// or skewed clocks would otherwise make a purge silently ineffective.
//
// Not safe for concurrent use; the agent guards it with its mutex.
type purgeState struct {
	gen     string
	seq     uint64
	markers map[string]dataplane.PurgeMarker // by markerIdentity
	perSite map[string]int                   // URL and prefix markers per site
	tasks   map[string]int64                 // task id -> assigned epoch
	last    int64                            // highest epoch assigned
	// lost is set when stored markers could not be read: the first plan
	// then gets a site-level marker for every site.
	lost bool
}

func newPurgeState() *purgeState {
	return &purgeState{
		gen:     randomGen(),
		markers: map[string]dataplane.PurgeMarker{},
		perSite: map[string]int{},
		tasks:   map[string]int64{},
	}
}

func randomGen() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	}
	return hex.EncodeToString(b[:])
}

func markerIdentity(m dataplane.PurgeMarker) string {
	if m.Type == "site" {
		return m.SiteID + "\x00site"
	}
	return m.SiteID + "\x00" + m.Type + "\x00" + m.Host + "\x00" + m.Path + "\x00" + m.Query
}

// id identifies the current set.
func (s *purgeState) id() string { return fmt.Sprintf("%s-%d", s.gen, s.seq) }

// compactID identifies the site-level fallback of the current set.
func (s *purgeState) compactID() string { return s.id() + "-sites" }

func (s *purgeState) bump() { s.seq++ }

// taskEpoch returns the marker time of a purge task (see purgeState).
func (s *purgeState) taskEpoch(taskID string, now time.Time) int64 {
	if e, ok := s.tasks[taskID]; ok && taskID != "" {
		return e
	}
	e := max(now.UnixMilli(), s.last+1)
	s.last = e
	if taskID != "" {
		if len(s.tasks) >= maxPurgeTasks {
			s.dropOldestTasks(len(s.tasks) - maxPurgeTasks + 1)
		}
		s.tasks[taskID] = e
	}
	return e
}

func (s *purgeState) dropOldestTasks(n int) {
	ids := slices.Collect(maps.Keys(s.tasks))
	slices.SortFunc(ids, func(a, b string) int { return cmp.Compare(s.tasks[a], s.tasks[b]) })
	for _, id := range ids[:min(n, len(ids))] {
		delete(s.tasks, id)
	}
}

// put stores m unless an equal or newer marker with the same identity
// exists; it reports whether the set changed.
func (s *purgeState) put(m dataplane.PurgeMarker) bool {
	k := markerIdentity(m)
	if old, ok := s.markers[k]; ok {
		if old.Epoch >= m.Epoch {
			return false
		}
		old.Epoch = m.Epoch
		s.markers[k] = old
		return true
	}
	s.markers[k] = m
	if m.Type != "site" {
		s.perSite[m.SiteID]++
	}
	return true
}

// add merges markers (highest epoch per identity wins) and collapses every
// site above perSiteCap. It returns the markers the data plane must merge
// (as stored), the collapsed sites and whether the set changed.
func (s *purgeState) add(markers []dataplane.PurgeMarker, perSiteCap int) (delta []dataplane.PurgeMarker, collapsed []string, changed bool) {
	touched := map[string]bool{}
	for _, m := range markers {
		if s.put(m) {
			changed = true
		}
		touched[m.SiteID] = true
	}
	for _, site := range slices.Sorted(maps.Keys(touched)) {
		if perSiteCap > 0 && s.perSite[site] > perSiteCap && s.collapse(site) {
			collapsed = append(collapsed, site)
			changed = true
		}
	}
	seen := map[string]bool{}
	for _, m := range markers {
		k := markerIdentity(m)
		if _, ok := s.markers[k]; !ok {
			k = markerIdentity(dataplane.PurgeMarker{SiteID: m.SiteID, Type: "site"}) // collapsed
		}
		if cur, ok := s.markers[k]; ok && !seen[k] {
			seen[k] = true
			delta = append(delta, cur)
		}
	}
	if changed {
		s.bump()
	}
	return delta, collapsed, changed
}

// collapse replaces every URL and prefix marker of site by one site-level
// marker at their highest epoch: over-purging is acceptable, an unbounded
// marker set is not. It does not bump the sequence.
func (s *purgeState) collapse(site string) bool {
	var top int64
	found := false
	for k, m := range s.markers {
		if m.SiteID != site {
			continue
		}
		top = max(top, m.Epoch)
		if m.Type != "site" {
			delete(s.markers, k)
			found = true
		}
	}
	delete(s.perSite, site)
	if !found {
		return false
	}
	s.markers[markerIdentity(dataplane.PurgeMarker{SiteID: site, Type: "site"})] = dataplane.PurgeMarker{SiteID: site, Type: "site", Epoch: top}
	return true
}

// prune drops markers older than markerCutoff and task epochs older than
// taskCutoff (Unix milliseconds); it reports whether markers changed.
func (s *purgeState) prune(markerCutoff, taskCutoff int64) bool {
	changed := false
	for k, m := range s.markers {
		if m.Epoch < markerCutoff {
			delete(s.markers, k)
			if m.Type != "site" {
				s.perSite[m.SiteID]--
				if s.perSite[m.SiteID] <= 0 {
					delete(s.perSite, m.SiteID)
				}
			}
			changed = true
		}
	}
	for id, e := range s.tasks {
		if e < taskCutoff {
			delete(s.tasks, id)
		}
	}
	if changed {
		s.bump()
	}
	return changed
}

// list returns the markers in a stable order.
func (s *purgeState) list() []dataplane.PurgeMarker {
	keys := slices.Sorted(maps.Keys(s.markers))
	out := make([]dataplane.PurgeMarker, 0, len(keys))
	for _, k := range keys {
		out = append(out, s.markers[k])
	}
	return out
}

// table returns the full set for PUT /v1/purge.
func (s *purgeState) table() *dataplane.PurgeTable {
	return &dataplane.PurgeTable{ID: s.id(), Markers: s.list()}
}

// compact returns the fallback set: one site-level marker per site with any
// marker, at the site's highest epoch. It purges at least what the full set
// does and always fits.
func (s *purgeState) compact() *dataplane.PurgeTable {
	top := map[string]int64{}
	for _, m := range s.markers {
		top[m.SiteID] = max(top[m.SiteID], m.Epoch)
	}
	t := &dataplane.PurgeTable{ID: s.compactID(), Markers: []dataplane.PurgeMarker{}}
	for _, site := range slices.Sorted(maps.Keys(top)) {
		t.Markers = append(t.Markers, dataplane.PurgeMarker{SiteID: site, Type: "site", Epoch: top[site]})
	}
	return t
}

// storedPurge is the format of purge.json. Version 1 (M2) only had
// "markers".
type storedPurge struct {
	Version   int                     `json:"version"`
	Gen       string                  `json:"gen,omitempty"`
	Seq       uint64                  `json:"seq,omitempty"`
	LastEpoch int64                   `json:"last_epoch,omitempty"`
	Markers   []dataplane.PurgeMarker `json:"markers"`
	Tasks     map[string]int64        `json:"tasks,omitempty"`
}

func (s *purgeState) marshal() ([]byte, error) {
	return json.Marshal(storedPurge{Version: 2, Gen: s.gen, Seq: s.seq, LastEpoch: s.last, Markers: s.list(), Tasks: s.tasks})
}

func unmarshalPurge(raw []byte) (*purgeState, error) {
	var st storedPurge
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	s := newPurgeState()
	if st.Gen != "" {
		s.gen = st.Gen
	}
	s.seq, s.last = st.Seq, st.LastEpoch
	for _, m := range st.Markers {
		if m.SiteID == "" || (m.Type != "url" && m.Type != "prefix" && m.Type != "site") {
			continue
		}
		s.put(m)
		s.last = max(s.last, m.Epoch)
	}
	maps.Copy(s.tasks, st.Tasks)
	return s, nil
}
