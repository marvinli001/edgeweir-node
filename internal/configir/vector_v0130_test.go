package configir

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// v0130Vector reads testdata/content_hash_vector_v0130.json, a copy of the
// console's fixture (packages/config-compiler/test/fixtures): the M2
// vector plus, on site s2, an origin group, rules with functions, value
// expression targets, query edits, every new config field, an origin
// action, compression rules, cache rules with a browser TTL and a typed
// condition, unsorted bulk redirects (two sources whose UTF-8 byte order
// differs from UTF-16 order) and a platform rule with unsorted set_query;
// required_features unsorted with a duplicate. Its canonical_hex and
// content_hash come from protobuf-es.
func v0130Vector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_v0130.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v hashVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	cfg := &nodev1.NodeConfig{}
	if err := protojson.Unmarshal(v.Config, cfg); err != nil {
		t.Fatal(err)
	}
	return cfg, v
}

func vectorSite(c *nodev1.NodeConfig, id string) *nodev1.Site {
	for _, s := range c.GetSites() {
		if s.GetId() == id {
			return s
		}
	}
	return nil
}

func ruleByID(rules []*nodev1.EdgeRule, id string) *nodev1.EdgeRule {
	for _, r := range rules {
		if r.GetId() == id {
			return r
		}
	}
	return nil
}

// TestContentHashVectorV0130 checks the proto v0.13.0 vector shared with
// the console: Go's canonical form of the unsorted configuration encodes to
// the console's canonical bytes and hash, bulk redirects sort by the bytes
// of their sources and query edits by name, every v0.13.0 field counts, and
// configir accepts the configuration.
func TestContentHashVectorV0130(t *testing.T) {
	cfg, v := v0130Vector(t)
	// The vector feeds unsorted lists into canonicalization.
	s2 := vectorSite(cfg, "s2")
	if s2 == nil || len(s2.BulkRedirects) != 5 || s2.BulkRedirects[0].GetSource() != "/！" || s2.BulkRedirects[1].GetSource() != "/\U0001F600" {
		t.Fatalf("vector s2 bulk redirects: %v", s2.GetBulkRedirects())
	}
	if e1 := ruleByID(s2.Rules, "e1").GetAction(); e1.GetSetQuery()[0].GetName() != "v" || e1.GetRemoveQuery()[0] != "utm_source" {
		t.Fatalf("vector rule e1 is already sorted: %v", e1)
	}
	b, err := CanonicalBytes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ContentHash(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v.CanonicalHex != hex.EncodeToString(b) {
		t.Fatalf("canonical bytes differ from the console\n got %x\nwant %s", b, v.CanonicalHex)
	}
	if v.ContentHash != h {
		t.Fatalf("vector hash %s, Go computes %s", v.ContentHash, h)
	}

	Canonicalize(cfg)
	s2 = vectorSite(cfg, "s2")
	var sources []string
	for _, r := range s2.BulkRedirects {
		sources = append(sources, r.GetSource())
	}
	// Bytes: "/" < "/a" < "/old" < "/！" (EF BC 81) < "/\U0001F600"
	// (F0 9F 98 80) < "bucket.test/a"; UTF-16 order would put the emoji
	// (a surrogate pair, D83D) before U+FF01.
	if want := []string{"/a", "/old", "/！", "/\U0001F600", "bucket.test/a"}; !slices.Equal(sources, want) {
		t.Errorf("canonical bulk redirect sources %q, want %q", sources, want)
	}
	names := func(params []*nodev1.QueryParam) []string {
		var out []string
		for _, p := range params {
			out = append(out, p.GetName())
		}
		return out
	}
	for _, check := range []struct {
		rule         *nodev1.EdgeRule
		set, removed []string
	}{
		{ruleByID(s2.Rules, "e1"), []string{"lang", "v"}, []string{"utm_medium", "utm_source"}},
		{ruleByID(s2.Rules, "e2"), nil, []string{"a", "b"}},
		{ruleByID(s2.Rules, "e3"), []string{"a", "z"}, nil},
		{ruleByID(cfg.PlatformRules, "p1"), []string{"from", "to"}, nil},
	} {
		a := check.rule.GetAction()
		if !slices.Equal(names(a.GetSetQuery()), check.set) || !slices.Equal(a.GetRemoveQuery(), check.removed) {
			t.Errorf("rule %s: set_query %v, remove_query %v", check.rule.GetId(), names(a.GetSetQuery()), a.GetRemoveQuery())
		}
	}
	if !slices.Equal(cfg.RequiredFeatures, []string{"rules-v1", "rules-v2"}) {
		t.Errorf("canonical required features %v", cfg.RequiredFeatures)
	}
	if hc, _ := ContentHash(cfg); hc != h {
		t.Fatalf("canonical config hashes to %s, want %s", hc, h)
	}

	// Every v0.13.0 field is part of the canonical bytes.
	for name, change := range map[string]func(*nodev1.NodeConfig){
		"bulk_redirects":      func(c *nodev1.NodeConfig) { vectorSite(c, "s2").BulkRedirects = nil },
		"bulk preserve_query": func(c *nodev1.NodeConfig) { vectorSite(c, "s2").BulkRedirects[1].PreserveQuery = false },
		"origin group": func(c *nodev1.NodeConfig) {
			for _, o := range vectorSite(c, "s2").OriginPool.Origins {
				o.Group = ""
			}
		},
		"rule target":         func(c *nodev1.NodeConfig) { ruleByID(vectorSite(c, "s2").Rules, "e1").Action.Target = nil },
		"preserve_query":      func(c *nodev1.NodeConfig) { ruleByID(vectorSite(c, "s2").Rules, "e1").Action.PreserveQuery = nil },
		"set_query":           func(c *nodev1.NodeConfig) { ruleByID(vectorSite(c, "s2").Rules, "e3").Action.SetQuery = nil },
		"remove_query":        func(c *nodev1.NodeConfig) { ruleByID(vectorSite(c, "s2").Rules, "e2").Action.RemoveQuery = nil },
		"config brotli=false": func(c *nodev1.NodeConfig) { ruleByID(vectorSite(c, "s2").Rules, "e4").Action.Brotli = nil },
		"log_sample_rate 0":   func(c *nodev1.NodeConfig) { ruleByID(vectorSite(c, "s2").Rules, "e4").Action.LogSampleRate = nil },
		"cc_max_level":        func(c *nodev1.NodeConfig) { ruleByID(vectorSite(c, "s2").Rules, "e4").Action.CcMaxLevel = "" },
		"origin port":         func(c *nodev1.NodeConfig) { ruleByID(vectorSite(c, "s2").Rules, "e5").Action.Port = 0 },
		"compression":         func(c *nodev1.NodeConfig) { ruleByID(vectorSite(c, "s2").Rules, "e6").Action.Compression = nil },
		"browser_ttl_seconds": func(c *nodev1.NodeConfig) {
			for _, r := range vectorSite(c, "s2").CacheRules {
				r.BrowserTtlSeconds = 0
			}
		},
		"cache condition": func(c *nodev1.NodeConfig) {
			for _, r := range vectorSite(c, "s2").CacheRules {
				if r.GetMatch().GetCondition() != nil {
					r.Match.Condition = &nodev1.RuleExpression{Op: "literal", ValueType: "boolean", Value: "true"}
				}
			}
		},
	} {
		c, _ := v0130Vector(t)
		change(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}

	// configir accepts what the console compiled and the plan carries it.
	p, err := Build(cfg, Options{ClusterID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	var site *Site
	for i := range p.Sites {
		if p.Sites[i].ID == "s2" {
			site = &p.Sites[i]
		}
	}
	if site == nil || len(site.BulkRedirects) != 5 || site.BulkRedirects[2].Source != "/！" || len(site.Rules) != 7 {
		t.Fatalf("plan site s2 = %+v", site)
	}
	groups := map[string]string{}
	for _, o := range site.Origins {
		groups[o.ID] = o.Group
	}
	ttls, conditions := 0, 0
	for _, r := range site.CacheRules {
		if r.BrowserTTL > 0 {
			ttls++
		}
		if r.Condition != nil {
			conditions++
		}
	}
	if groups["o2"] != "backup-pool" || groups["o3"] != "" || ttls == 0 || conditions != 1 {
		t.Fatalf("plan origins %v, cache rules %+v", groups, site.CacheRules)
	}
}

// The canonical order of v0.13.0 leaves rules in their order and sorts
// only inside actions; an unsorted copy hashes like the sorted one.
func TestCanonicalizeV0130KeepsRuleOrder(t *testing.T) {
	cfg, _ := v0130Vector(t)
	before := proto.CloneOf(cfg)
	h1, _ := ContentHash(cfg)
	Canonicalize(cfg)
	h2, _ := ContentHash(cfg)
	if h1 != h2 {
		t.Fatal("canonical order changed the hash of the unsorted config")
	}
	var a, b []string
	for _, r := range vectorSite(before, "s2").Rules {
		a = append(a, r.GetId())
	}
	for _, r := range vectorSite(cfg, "s2").Rules {
		b = append(b, r.GetId())
	}
	if !slices.Equal(a, b) {
		t.Fatalf("rules reordered: %v -> %v", a, b)
	}
}
