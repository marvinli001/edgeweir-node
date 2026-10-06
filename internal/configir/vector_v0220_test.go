package configir

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// v0220Vector reads testdata/content_hash_vector_v0220.json, a copy of the
// console's fixture (packages/config-compiler/test/fixtures): the M2
// vector plus, on site s2, rules with the rules-v3 fields, functions and
// wildcard comparisons, request and response headers with value
// expressions, a response header line (append), a 303 redirect whose
// set_query mixes a computed and a static parameter (unsorted) and an
// error page with {{time}} and {{path}}; required_features unsorted with a
// duplicate. Its canonical_hex and content_hash come from protobuf-es.
func v0220Vector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_v0220.json"))
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

// TestContentHashVectorV0220 checks the proto v0.22.0 vector shared with
// the console: Go's canonical form encodes to the console's bytes and
// hash, set_query sorts by name with its expressions, every v0.22.0 field
// counts, and configir accepts the configuration on a node with the ASN
// database.
func TestContentHashVectorV0220(t *testing.T) {
	cfg, v := v0220Vector(t)
	s2 := vectorSite(cfg, "s2")
	if q := ruleByID(s2.GetRules(), "g2").GetAction().GetSetQuery(); len(q) != 2 || q[0].GetName() != "z" || q[0].GetExpression() == nil {
		t.Fatalf("vector rule g2 set_query is already sorted: %v", q)
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
	if q := ruleByID(s2.Rules, "g2").GetAction().GetSetQuery(); q[0].GetName() != "a" || q[1].GetExpression().GetField() != "url_encode" {
		t.Errorf("canonical set_query %v", q)
	}
	if want := []string{"error-pages-v1", "geoip-asn-v1", "rules-v1", "rules-v2", "rules-v3"}; !slices.Equal(cfg.RequiredFeatures, want) {
		t.Errorf("canonical required features %v, want %v", cfg.RequiredFeatures, want)
	}

	// Every v0.22.0 field is part of the canonical bytes.
	for name, change := range map[string]func(*nodev1.NodeConfig){
		"header target": func(c *nodev1.NodeConfig) { ruleByID(vectorSite(c, "s2").Rules, "g1").Action.Target = nil },
		"append":        func(c *nodev1.NodeConfig) { ruleByID(vectorSite(c, "s2").Rules, "g5").Action.Append = false },
		"query expression": func(c *nodev1.NodeConfig) {
			ruleByID(vectorSite(c, "s2").Rules, "g2").Action.SetQuery[0].Expression = nil
		},
		"303": func(c *nodev1.NodeConfig) { ruleByID(vectorSite(c, "s2").Rules, "g2").Action.StatusCode = 302 },
		"integer argument": func(c *nodev1.NodeConfig) {
			ruleByID(vectorSite(c, "s2").Rules, "g6").Action.Target.Children[1].Value = "-2"
		},
		"error page placeholder": func(c *nodev1.NodeConfig) {
			vectorSite(c, "s2").ErrorPages.Pages[0].Template = "<p>{{status}}</p>"
		},
	} {
		c, _ := v0220Vector(t)
		change(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}

	// configir accepts what the console compiled, with the ASN database
	// (ip.geoip.as_name), and the plan carries the rules.
	if _, err := Build(cfg, Options{ClusterID: "c1"}); err == nil {
		t.Fatal("accepted ip.geoip.as_name without the ASN database")
	}
	p, err := Build(cfg, Options{ClusterID: "c1", ExtraFeatures: []string{"geoip-asn-v1"}})
	if err != nil {
		t.Fatal(err)
	}
	for i := range p.Sites {
		if p.Sites[i].ID == "s2" && len(p.Sites[i].Rules) != 6 {
			t.Fatalf("plan site s2 rules = %d", len(p.Sites[i].Rules))
		}
	}
}
