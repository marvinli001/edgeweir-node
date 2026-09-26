package agent

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
)

func urlMarker(site, path string, epoch int64) dataplane.PurgeMarker {
	return dataplane.PurgeMarker{SiteID: site, Type: "url", Host: site + ".test", Path: path, Epoch: epoch}
}

// TestPurgeTaskEpochAssignedByNode (N-M3): the node assigns a purge task's
// marker time when it first applies it, max(now, last+1), and keeps it for
// a task handed out again, also across restarts.
func TestPurgeTaskEpochAssignedByNode(t *testing.T) {
	s := newPurgeState()
	now := time.UnixMilli(1_800_000_000_000)
	e1 := s.taskEpoch("t1", now)
	if e1 != now.UnixMilli() {
		t.Fatalf("first epoch = %d, want now %d", e1, now.UnixMilli())
	}
	if again := s.taskEpoch("t1", now.Add(time.Hour)); again != e1 {
		t.Fatalf("re-applied task got %d, want its first epoch %d", again, e1)
	}
	// A clock that goes back (or a second task in the same millisecond)
	// still gets a later epoch: an older epoch would purge nothing.
	e2 := s.taskEpoch("t2", now.Add(-time.Hour))
	e3 := s.taskEpoch("t3", now.Add(-time.Hour))
	if e2 != e1+1 || e3 != e2+1 {
		t.Fatalf("epochs = %d, %d after %d, want strictly increasing", e2, e3, e1)
	}
	raw, err := s.marshal()
	if err != nil {
		t.Fatal(err)
	}
	r, err := unmarshalPurge(raw)
	if err != nil {
		t.Fatal(err)
	}
	if r.taskEpoch("t1", now.Add(2*time.Hour)) != e1 {
		t.Fatal("task epoch not persisted")
	}
	if e4 := r.taskEpoch("t4", now.Add(-time.Hour)); e4 != e3+1 {
		t.Fatalf("after reload the next epoch is %d, want %d", e4, e3+1)
	}
	// Task epochs expire with the retention.
	r.prune(0, e3+1)
	if _, ok := r.tasks["t1"]; ok {
		t.Fatal("expired task epoch kept")
	}
}

// TestPurgeStateCollapsesSitesOverTheCap (N-H3): beyond the per-site cap a
// site's URL and prefix markers become one site-level marker at their
// highest epoch.
func TestPurgeStateCollapsesSitesOverTheCap(t *testing.T) {
	s := newPurgeState()
	var batch []dataplane.PurgeMarker
	for i := range 5 {
		batch = append(batch, urlMarker("a", "/p"+string(rune('0'+i)), int64(100+i)))
	}
	batch = append(batch, urlMarker("b", "/keep", 50))
	delta, collapsed, changed := s.add(batch, 3)
	if !changed || !slices.Equal(collapsed, []string{"a"}) {
		t.Fatalf("collapsed = %v changed = %v", collapsed, changed)
	}
	list := s.list()
	want := []dataplane.PurgeMarker{{SiteID: "a", Type: "site", Epoch: 104}, urlMarker("b", "/keep", 50)}
	if !slices.Equal(list, want) {
		t.Fatalf("markers = %+v\nwant %+v", list, want)
	}
	if !slices.Contains(delta, dataplane.PurgeMarker{SiteID: "a", Type: "site", Epoch: 104}) || len(delta) != 2 {
		t.Fatalf("delta = %+v", delta)
	}
	// Further purges of the collapsed site stay below the cap again.
	_, collapsed, _ = s.add([]dataplane.PurgeMarker{urlMarker("a", "/new", 200)}, 3)
	if len(collapsed) != 0 || s.perSite["a"] != 1 {
		t.Fatalf("collapsed = %v per site = %v", collapsed, s.perSite)
	}
	// The site-level fallback set covers every site at its highest epoch.
	c := s.compact()
	if !slices.Equal(c.Markers, []dataplane.PurgeMarker{{SiteID: "a", Type: "site", Epoch: 200}, {SiteID: "b", Type: "site", Epoch: 50}}) ||
		!strings.HasSuffix(c.ID, "-sites") {
		t.Fatalf("compact = %+v", c)
	}
}

// TestPurgeStateIDIsIncremental: the set id changes with the content only,
// without hashing the markers.
func TestPurgeStateIDIsIncremental(t *testing.T) {
	s := newPurgeState()
	id0 := s.id()
	_, _, changed := s.add([]dataplane.PurgeMarker{urlMarker("a", "/x", 10)}, 0)
	id1 := s.id()
	if !changed || id1 == id0 {
		t.Fatal("id unchanged after adding a marker")
	}
	if _, _, changed := s.add([]dataplane.PurgeMarker{urlMarker("a", "/x", 10)}, 0); changed || s.id() != id1 {
		t.Fatal("re-adding the same marker changed the set")
	}
	s.add([]dataplane.PurgeMarker{urlMarker("a", "/x", 5)}, 0)
	if s.id() != id1 || s.markers[markerIdentity(urlMarker("a", "/x", 0))].Epoch != 10 {
		t.Fatal("an older marker lowered the epoch or changed the set")
	}
	if s.prune(0, 0) || s.id() != id1 {
		t.Fatal("prune without expired markers changed the set")
	}
	if !s.prune(11, 0) || s.id() == id1 || len(s.markers) != 0 || len(s.perSite) != 0 {
		t.Fatal("expired marker not pruned")
	}
	other := newPurgeState()
	if other.id() == id0 {
		t.Fatal("two state files share a generation")
	}
}

func TestPurgeStateReadsM2File(t *testing.T) {
	s, err := unmarshalPurge([]byte(`{"markers":[{"site_id":"a","type":"prefix","host":"a.test","path":"/s/","epoch":7},{"site_id":"b","type":"site","epoch":9},{"site_id":"","type":"url","epoch":1}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.markers) != 2 || s.perSite["a"] != 1 || s.last != 9 {
		t.Fatalf("state = %+v", s)
	}
	if e := s.taskEpoch("new", time.UnixMilli(1)); e != 10 {
		t.Fatalf("epoch after an M2 file = %d, want 10", e)
	}
}
