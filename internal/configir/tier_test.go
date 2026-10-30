package configir

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// tierConfig: lower tiers l1 and l2, regional tier r1, upper tier u1; site
// a uses plan p (l1 -> r1 -> u1, l2 -> u1, r1 -> u1).
func tierConfig(t *testing.T, change func(tc *nodev1.TieredCache)) *nodev1.NodeConfig {
	t.Helper()
	return g16Config(t, func(c *nodev1.NodeConfig, a *nodev1.Site) {
		tc := &nodev1.TieredCache{
			Port: 8444,
			Nodes: []*nodev1.TierNode{
				{Id: "l1"}, {Id: "l2"}, {Id: "r1", Address: "10.0.0.2"}, {Id: "u1", Address: "2001:db8::1"},
			},
			Plans: []*nodev1.TierPlan{{Id: "p", Hops: []*nodev1.TierHop{
				{NodeId: "l1", UpperNodeIds: []string{"r1", "u1"}},
				{NodeId: "l2", UpperNodeIds: []string{"u1"}},
				{NodeId: "r1", UpperNodeIds: []string{"u1"}},
			}}},
			LatencyTargets: []*nodev1.TierLatencyTarget{{Id: "o1", Host: "origin.example", Port: 443}},
		}
		if change != nil {
			change(tc)
		}
		c.TieredCache = tc
		a.TierPlanId = "p"
	})
}

func TestTieredCacheRoles(t *testing.T) {
	if !slices.Contains(SupportedFeatures, FeatureTieredCache) {
		t.Fatal("tiered-cache-v1 not supported")
	}
	cases := map[string]struct {
		listen, lower bool
		clients       []string
		uppers        []string
	}{
		"l1": {lower: true, uppers: []string{"r1", "u1"}},
		"r1": {listen: true, lower: true, clients: []string{"l1"}, uppers: []string{"u1"}},
		"u1": {listen: true, clients: []string{"l1", "l2", "r1"}},
		"x9": {},
	}
	for node, want := range cases {
		p, err := Build(tierConfig(t, nil), Options{NodeID: node})
		if err != nil {
			t.Fatalf("%s: %v", node, err)
		}
		tier := p.Tier
		if tier == nil {
			t.Fatalf("%s: no tier (latency targets are always measured)", node)
		}
		if tier.Listen != want.listen || tier.Lower != want.lower || !slices.Equal(tier.Clients, want.clients) {
			t.Errorf("%s: %+v", node, tier)
		}
		var ids []string
		for _, peer := range p.Sites[0].Tier {
			ids = append(ids, peer.ID)
			if peer.Port != 8444 || peer.CDNID != CDNID(peer.ID) || peer.Address == "" {
				t.Errorf("%s: peer %+v", node, peer)
			}
		}
		if !slices.Equal(ids, want.uppers) {
			t.Errorf("%s: uppers %v, want %v", node, ids, want.uppers)
		}
		if len(p.Sites) > 1 && p.Sites[1].Tier != nil {
			t.Errorf("%s: site b has upper tiers", node)
		}
		if len(tier.LatencyTargets) != 1 || tier.LatencyTargets[0].Host != "origin.example" {
			t.Errorf("%s: targets %+v", node, tier.LatencyTargets)
		}
	}
	p, _ := Build(tierConfig(t, nil), Options{NodeID: "l1"})
	raw, _ := json.Marshal(p.Sites[0])
	var site map[string]any
	_ = json.Unmarshal(raw, &site)
	peers, _ := site["tier"].([]any)
	if len(peers) != 2 || peers[1].(map[string]any)["address"] != "2001:db8::1" {
		t.Fatalf("site table tier %v", site["tier"])
	}
}

func TestTieredCacheUnusedPlanTakesNoRole(t *testing.T) {
	p, err := Build(g16Config(t, func(c *nodev1.NodeConfig, _ *nodev1.Site) {
		c.TieredCache = &nodev1.TieredCache{Port: 8444, Nodes: []*nodev1.TierNode{{Id: "l1"}, {Id: "u1", Address: "10.0.0.1"}},
			Plans: []*nodev1.TierPlan{{Id: "p", Hops: []*nodev1.TierHop{{NodeId: "l1", UpperNodeIds: []string{"u1"}}}}}}
	}), Options{NodeID: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if p.Tier != nil {
		t.Fatalf("no site uses the plan: %+v", p.Tier)
	}
}

func TestTieredCacheRejects(t *testing.T) {
	for name, change := range map[string]func(*nodev1.TieredCache){
		"no port":               func(tc *nodev1.TieredCache) { tc.Port = 0 },
		"listener port":         func(tc *nodev1.TieredCache) { tc.Port = 80 },
		"unsorted nodes":        func(tc *nodev1.TieredCache) { tc.Nodes[0], tc.Nodes[1] = tc.Nodes[1], tc.Nodes[0] },
		"bad address":           func(tc *nodev1.TieredCache) { tc.Nodes[2].Address = "node.example" },
		"unspecified address":   func(tc *nodev1.TieredCache) { tc.Nodes[2].Address = "0.0.0.0" },
		"upper without address": func(tc *nodev1.TieredCache) { tc.Plans[0].Hops[1].UpperNodeIds = []string{"l1"} },
		"unknown upper":         func(tc *nodev1.TieredCache) { tc.Plans[0].Hops[1].UpperNodeIds = []string{"zz"} },
		"self":                  func(tc *nodev1.TieredCache) { tc.Plans[0].Hops[2].UpperNodeIds = []string{"r1"} },
		"duplicate upper":       func(tc *nodev1.TieredCache) { tc.Plans[0].Hops[0].UpperNodeIds = []string{"u1", "u1"} },
		"four uppers": func(tc *nodev1.TieredCache) {
			tc.Nodes = append(tc.Nodes, &nodev1.TierNode{Id: "u2", Address: "10.0.0.3"}, &nodev1.TierNode{Id: "u3", Address: "10.0.0.4"})
			tc.Plans[0].Hops[1].UpperNodeIds = []string{"r1", "u1", "u2", "u3"}
		},
		"no uppers": func(tc *nodev1.TieredCache) { tc.Plans[0].Hops[1].UpperNodeIds = nil },
		"cycle": func(tc *nodev1.TieredCache) {
			tc.Plans[0].Hops = append(tc.Plans[0].Hops, &nodev1.TierHop{NodeId: "u1", UpperNodeIds: []string{"r1"}})
		},
		"three hops": func(tc *nodev1.TieredCache) {
			tc.Nodes = append(tc.Nodes, &nodev1.TierNode{Id: "v1", Address: "10.0.0.9"})
			tc.Plans[0].Hops = append(tc.Plans[0].Hops, &nodev1.TierHop{NodeId: "u1", UpperNodeIds: []string{"v1"}})
		},
		"bad plan id":     func(tc *nodev1.TieredCache) { tc.Plans[0].Id = "p q" },
		"unknown plan":    func(tc *nodev1.TieredCache) { tc.Plans[0].Id = "other" },
		"bad target host": func(tc *nodev1.TieredCache) { tc.LatencyTargets[0].Host = "a b" },
		"bad target port": func(tc *nodev1.TieredCache) { tc.LatencyTargets[0].Port = 0 },
	} {
		if _, err := Build(tierConfig(t, change), Options{NodeID: "l1"}); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
	cfg := tierConfig(t, nil)
	cfg.TieredCache = nil
	if _, err := Build(cfg, Options{NodeID: "l1"}); !errors.Is(err, ErrRejected) {
		t.Errorf("a plan without a tiered cache: %v", err)
	}
}

func TestTierDepth(t *testing.T) {
	for _, c := range []struct {
		hops map[string][]string
		want int
	}{
		{map[string][]string{}, 0},
		{map[string][]string{"a": {"b"}}, 1},
		{map[string][]string{"a": {"b", "c"}, "b": {"c"}}, 2},
		{map[string][]string{"a": {"b"}, "b": {"c"}, "c": {"d"}}, 3},
		{map[string][]string{"a": {"b"}, "b": {"a"}}, -1},
		{map[string][]string{"a": {"b"}, "b": {"c"}, "c": {"b"}}, -1},
	} {
		if got := tierDepth(c.hops); got != c.want {
			t.Errorf("%v: %d, want %d", c.hops, got, c.want)
		}
	}
}
