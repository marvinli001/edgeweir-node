package agent

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
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
	delta, collapsed, changed := s.add(batch, 3, 0)
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
	_, collapsed, _ = s.add([]dataplane.PurgeMarker{urlMarker("a", "/new", 200)}, 3, 0)
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
	_, _, changed := s.add([]dataplane.PurgeMarker{urlMarker("a", "/x", 10)}, 0, 0)
	id1 := s.id()
	if !changed || id1 == id0 {
		t.Fatal("id unchanged after adding a marker")
	}
	if _, _, changed := s.add([]dataplane.PurgeMarker{urlMarker("a", "/x", 10)}, 0, 0); changed || s.id() != id1 {
		t.Fatal("re-adding the same marker changed the set")
	}
	s.add([]dataplane.PurgeMarker{urlMarker("a", "/x", 5)}, 0, 0)
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

func tagMarker(site, tag string, epoch int64) dataplane.PurgeMarker {
	return dataplane.PurgeMarker{SiteID: site, Type: "tag", Tag: tag, Epoch: epoch}
}

// TestPurgeMarkersFromHostAndTagTargets: a HOST target purges every path
// of the host (a prefix marker on "/"), a TAG target becomes a tag marker
// in lowercase; tags are validated like the console does.
func TestPurgeMarkersFromHostAndTagTargets(t *testing.T) {
	long := strings.Repeat("t", 128)
	task := &nodev1.PurgeTask{Targets: []*nodev1.PurgeTarget{
		{SiteId: "a", Type: nodev1.PurgeType_PURGE_TYPE_HOST, Host: "WWW.a.test"},
		{SiteId: "a", Type: nodev1.PurgeType_PURGE_TYPE_TAG, Tag: "Product-42"},
		{SiteId: "a", Type: nodev1.PurgeType_PURGE_TYPE_TAG, Tag: "with inner space"},
		{SiteId: "a", Type: nodev1.PurgeType_PURGE_TYPE_TAG, Tag: long},
		{SiteId: "a", Type: nodev1.PurgeType_PURGE_TYPE_TAG, Tag: "~!@#$%^&*()_+{}|:<>?"},
	}}
	markers, invalid := purgeMarkers(task, 7)
	want := []dataplane.PurgeMarker{
		{SiteID: "a", Type: "prefix", Host: "www.a.test", Path: "/", Epoch: 7},
		tagMarker("a", "product-42", 7), tagMarker("a", "with inner space", 7), tagMarker("a", long, 7),
		tagMarker("a", "~!@#$%^&*()_+{}|:<>?", 7),
	}
	if len(invalid) != 0 || !slices.Equal(markers, want) {
		t.Fatalf("markers = %+v (invalid %v)\nwant %+v", markers, invalid, want)
	}

	bad := []*nodev1.PurgeTarget{
		{SiteId: "a", Type: nodev1.PurgeType_PURGE_TYPE_HOST},
		{SiteId: "a", Type: nodev1.PurgeType_PURGE_TYPE_TAG},
		{SiteId: "a", Type: nodev1.PurgeType_PURGE_TYPE_TAG, Tag: long + "t"},
		{SiteId: "a", Type: nodev1.PurgeType_PURGE_TYPE_TAG, Tag: "a,b"},
		{SiteId: "a", Type: nodev1.PurgeType_PURGE_TYPE_TAG, Tag: " leading"},
		{SiteId: "a", Type: nodev1.PurgeType_PURGE_TYPE_TAG, Tag: "trailing "},
		{SiteId: "a", Type: nodev1.PurgeType_PURGE_TYPE_TAG, Tag: "tab\there"},
		{SiteId: "a", Type: nodev1.PurgeType_PURGE_TYPE_TAG, Tag: "del\x7f"},
		{SiteId: "a", Type: nodev1.PurgeType_PURGE_TYPE_TAG, Tag: "café"},
		// The Kelvin sign lowercases to an ASCII "k": it must not slip
		// through as one.
		{SiteId: "a", Type: nodev1.PurgeType_PURGE_TYPE_TAG, Tag: "K"},
		{SiteId: "a|b", Type: nodev1.PurgeType_PURGE_TYPE_TAG, Tag: "ok"},
		{SiteId: "", Type: nodev1.PurgeType_PURGE_TYPE_SITE},
		{SiteId: "a", Type: nodev1.PurgeType(99)},
	}
	markers, invalid = purgeMarkers(&nodev1.PurgeTask{Targets: bad}, 7)
	if len(markers) != 0 || len(invalid) != len(bad) {
		t.Fatalf("invalid targets accepted: markers %+v, %d reasons %v", markers, len(invalid), invalid)
	}
}

// TestPurgeStateTagMarkers: tag markers are keyed by their tag, purging a
// tag again only raises its epoch, and beyond the tag cap the site's
// markers (tags, URLs and prefixes) collapse into one site-level marker at
// their highest epoch. The URL cap does not count tags.
func TestPurgeStateTagMarkers(t *testing.T) {
	s := newPurgeState()
	_, collapsed, changed := s.add([]dataplane.PurgeMarker{
		tagMarker("a", "x", 10), tagMarker("a", "y", 11), urlMarker("a", "/u", 12), tagMarker("b", "x", 13),
	}, 1, 2)
	if !changed || len(collapsed) != 0 || len(s.markers) != 4 || s.tags["a"] != 2 || s.perSite["a"] != 1 {
		t.Fatalf("collapsed %v, markers %+v, tags %v, per site %v", collapsed, s.markers, s.tags, s.perSite)
	}
	id := s.id()
	if _, _, changed := s.add([]dataplane.PurgeMarker{tagMarker("a", "x", 9)}, 1, 2); changed || s.id() != id {
		t.Fatal("an older epoch of a tag changed the set")
	}
	delta, _, changed := s.add([]dataplane.PurgeMarker{tagMarker("a", "x", 20)}, 1, 2)
	if !changed || len(s.markers) != 4 || s.tags["a"] != 2 || !slices.Equal(delta, []dataplane.PurgeMarker{tagMarker("a", "x", 20)}) {
		t.Fatalf("re-purged tag: delta %+v, markers %+v", delta, s.markers)
	}

	// A third tag of site a is over the cap of 2.
	delta, collapsed, _ = s.add([]dataplane.PurgeMarker{tagMarker("a", "z", 15)}, 1, 2)
	site := dataplane.PurgeMarker{SiteID: "a", Type: "site", Epoch: 20}
	if !slices.Equal(collapsed, []string{"a"}) || !slices.Equal(delta, []dataplane.PurgeMarker{site}) {
		t.Fatalf("collapsed %v, delta %+v", collapsed, delta)
	}
	if want := []dataplane.PurgeMarker{site, tagMarker("b", "x", 13)}; !slices.Equal(s.list(), want) {
		t.Fatalf("markers = %+v\nwant %+v", s.list(), want)
	}
	if s.tags["a"] != 0 || s.perSite["a"] != 0 || s.tags["b"] != 1 {
		t.Fatalf("counters after the collapse: tags %v, per site %v", s.tags, s.perSite)
	}

	// The site-level fallback covers tag epochs; expired tag markers go.
	if c := s.compact(); !slices.Equal(c.Markers, []dataplane.PurgeMarker{site, {SiteID: "b", Type: "site", Epoch: 13}}) {
		t.Fatalf("compact = %+v", c.Markers)
	}
	if !s.prune(14, 0) || len(s.tags) != 0 || !slices.Equal(s.list(), []dataplane.PurgeMarker{site}) {
		t.Fatalf("after pruning: %+v, tags %v", s.list(), s.tags)
	}
}

// TestPurgeStatePersistsTagMarkers: tag markers survive purge.json (format
// version 2), invalid stored tags are dropped and stored tags compare in
// lowercase.
func TestPurgeStatePersistsTagMarkers(t *testing.T) {
	s := newPurgeState()
	s.add([]dataplane.PurgeMarker{tagMarker("a", "x", 10), tagMarker("a", "y", 11), urlMarker("a", "/u", 12)}, 0, 0)
	raw, err := s.marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"version":2`) || !strings.Contains(string(raw), `{"site_id":"a","type":"tag","tag":"x","epoch":10}`) {
		t.Fatalf("purge.json = %s", raw)
	}
	r, err := unmarshalPurge(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.list(), s.list()) || r.tags["a"] != 2 || r.perSite["a"] != 1 || r.id() != s.id() || r.last != 12 {
		t.Fatalf("reloaded %+v (tags %v, per site %v, id %s, last %d), want %+v", r.list(), r.tags, r.perSite, r.id(), r.last, s.list())
	}

	r, err = unmarshalPurge([]byte(`{"version":2,"gen":"g","seq":3,"markers":[` +
		`{"site_id":"a","type":"tag","tag":"Mixed","epoch":5},` +
		`{"site_id":"a","type":"tag","tag":"mixed","epoch":4},` +
		`{"site_id":"a","type":"tag","tag":"a,b","epoch":6},` +
		`{"site_id":"a","type":"tag","epoch":7},` +
		`{"site_id":"a","type":"tag","tag":" x","epoch":8}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := []dataplane.PurgeMarker{tagMarker("a", "mixed", 5)}; !slices.Equal(r.list(), want) || r.tags["a"] != 1 || r.last != 8 {
		t.Fatalf("stored tags = %+v (tags %v, last %d), want %+v", r.list(), r.tags, r.last, want)
	}
}
