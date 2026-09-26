package configir

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func site(id string, domains ...string) *nodev1.Site {
	s := &nodev1.Site{
		Id:      id,
		Enabled: true,
		OriginPool: &nodev1.OriginPool{Id: "p-" + id, Origins: []*nodev1.Origin{
			{Id: "o1", Address: "origin.test", Port: 80, Weight: 1},
		}},
	}
	for _, d := range domains {
		s.Domains = append(s.Domains, &nodev1.Domain{Name: d})
	}
	return s
}

func withHash(t *testing.T, c *nodev1.NodeConfig) *nodev1.NodeConfig {
	t.Helper()
	Canonicalize(c)
	h, err := ContentHash(c)
	if err != nil {
		t.Fatal(err)
	}
	c.ContentHash = h
	return c
}

func TestApplyDiffUpsertAndRemove(t *testing.T) {
	base := withHash(t, &nodev1.NodeConfig{
		Revision:  1,
		ClusterId: "c1",
		Listeners: []*nodev1.Listener{{Port: 80}},
		Sites:     []*nodev1.Site{site("a", "a.test"), site("b", "b.test"), site("c", "c.test")},
	})
	changedB := site("b", "b.test", "www.b.test")
	target := withHash(t, &nodev1.NodeConfig{
		Revision:   2,
		ClusterId:  "c1",
		Listeners:  []*nodev1.Listener{{Port: 80}, {Port: 8080}},
		CacheZones: []*nodev1.CacheZone{{Name: "z"}},
		Sites:      []*nodev1.Site{site("a", "a.test"), changedB, site("d", "d.test")},
	})
	baseCopy := proto.CloneOf(base)

	d := Diff(base, target)
	if len(d.UpsertedSites) != 2 || d.UpsertedSites[0].Id != "b" || d.UpsertedSites[1].Id != "d" {
		t.Fatalf("diff upserts = %v", d.UpsertedSites)
	}
	if len(d.RemovedSiteIds) != 1 || d.RemovedSiteIds[0] != "c" {
		t.Fatalf("diff removals = %v", d.RemovedSiteIds)
	}

	got, err := ApplyDiff(base, d)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, target) {
		t.Fatalf("ApplyDiff result differs from target\n got %v\nwant %v", got, target)
	}
	if !proto.Equal(base, baseCopy) {
		t.Fatal("ApplyDiff modified its base")
	}
}

func TestApplyDiffHashMismatch(t *testing.T) {
	base := withHash(t, &nodev1.NodeConfig{Revision: 1, Sites: []*nodev1.Site{site("a", "a.test")}})
	target := withHash(t, &nodev1.NodeConfig{Revision: 2, Sites: []*nodev1.Site{site("a", "a.test"), site("b", "b.test")}})
	d := Diff(base, target)
	d.ContentHash = "0000000000000000000000000000000000000000000000000000000000000000"
	if _, err := ApplyDiff(base, d); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("err = %v, want ErrHashMismatch", err)
	}

	// A diff that silently drops an upsert must be caught by the hash.
	d = Diff(base, target)
	d.UpsertedSites = nil
	if _, err := ApplyDiff(base, d); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("incomplete diff: err = %v, want ErrHashMismatch", err)
	}
}

func TestApplyDiffBaseMismatch(t *testing.T) {
	base := withHash(t, &nodev1.NodeConfig{Revision: 3, ClusterId: "c1"})
	target := withHash(t, &nodev1.NodeConfig{Revision: 5, ClusterId: "c1"})
	d := Diff(&nodev1.NodeConfig{Revision: 4, ClusterId: "c1"}, target)
	if _, err := ApplyDiff(base, d); !errors.Is(err, ErrBaseMismatch) {
		t.Fatalf("err = %v, want ErrBaseMismatch", err)
	}
	if _, err := ApplyDiff(nil, d); !errors.Is(err, ErrBaseMismatch) {
		t.Fatalf("nil base: err = %v, want ErrBaseMismatch", err)
	}
	other := Diff(base, target)
	other.ClusterId = "c2"
	if _, err := ApplyDiff(base, other); !errors.Is(err, ErrBaseMismatch) {
		t.Fatalf("cluster mismatch: err = %v, want ErrBaseMismatch", err)
	}
}

func TestApplyDiffNoop(t *testing.T) {
	base := withHash(t, &nodev1.NodeConfig{Revision: 4, Sites: []*nodev1.Site{site("a", "a.test")}})
	d := Diff(base, base)
	got, err := ApplyDiff(base, d)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, base) {
		t.Fatal("no-op diff changed the config")
	}
}

// TestApplyDiffOriginAllowList: the allow list of the target revision
// replaces the base's (NodeConfigDiff field 10), including removal.
func TestApplyDiffOriginAllowList(t *testing.T) {
	base := withHash(t, &nodev1.NodeConfig{Revision: 1, Sites: []*nodev1.Site{site("a", "a.test")}})
	target := withHash(t, &nodev1.NodeConfig{
		Revision: 2, Sites: []*nodev1.Site{site("a", "a.test")},
		OriginAllowedCidrs: []string{"172.16.0.0/12", "10.0.0.0/8"},
	})
	d := Diff(base, target)
	if len(d.GetUpsertedSites()) != 0 || len(d.GetOriginAllowedCidrs()) != 2 {
		t.Fatalf("diff = %v", d)
	}
	got, err := ApplyDiff(base, d)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, target) || got.GetOriginAllowedCidrs()[0] != "10.0.0.0/8" {
		t.Fatalf("ApplyDiff = %v, want %v", got, target)
	}
	cleared := withHash(t, &nodev1.NodeConfig{Revision: 3, Sites: []*nodev1.Site{site("a", "a.test")}})
	got, err = ApplyDiff(target, Diff(target, cleared))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GetOriginAllowedCidrs()) != 0 {
		t.Fatalf("allow list not cleared: %v", got.GetOriginAllowedCidrs())
	}
}
