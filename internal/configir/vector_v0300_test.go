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

// v0300Vector reads testdata/content_hash_vector_v0300.json, a copy of the
// console's fixture: site a samples 10% of requests and has every access
// log option (log_blocked, log_query, log_headers accept-language and
// x-trace-id, log_peer), site b none. Sites, recorded headers and required
// features are reversed.
func v0300Vector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_v0300.json"))
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

// TestContentHashVectorV0300 checks the proto v0.30.0 vector shared with
// the console: log_headers sorted as a byte-ordered set, every option in the
// hash, and the plan.
func TestContentHashVectorV0300(t *testing.T) {
	cfg, v := v0300Vector(t)
	if cfg.GetSites()[0].GetId() != "b" || vectorSite(cfg, "a").GetLogHeaders()[0] != "x-trace-id" ||
		cfg.GetRequiredFeatures()[0] != "tls-v1" {
		t.Fatalf("vector is already canonical")
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
	if err := VerifyHash(cfg); err != nil {
		t.Fatal(err)
	}
	site := func(c *nodev1.NodeConfig) *nodev1.Site { return vectorSite(c, "a") }
	for name, change := range map[string]func(*nodev1.NodeConfig){
		"log blocked": func(c *nodev1.NodeConfig) { site(c).LogBlocked = false },
		"log query":   func(c *nodev1.NodeConfig) { site(c).LogQuery = false },
		"log headers": func(c *nodev1.NodeConfig) { site(c).LogHeaders = []string{"x-trace-id"} },
		"log peer":    func(c *nodev1.NodeConfig) { site(c).LogPeer = false },
		"site b":      func(c *nodev1.NodeConfig) { vectorSite(c, "b").LogQuery = true },
	} {
		c, _ := v0300Vector(t)
		change(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}
	// The recorded headers are a set: order and duplicates change nothing.
	c, _ := v0300Vector(t)
	site(c).LogHeaders = []string{"x-trace-id", "accept-language", "x-trace-id"}
	if hc, _ := ContentHash(c); hc != h {
		t.Errorf("reordered or repeated recorded headers change the hash")
	}

	Canonicalize(cfg)
	p, err := Build(cfg, Options{ClusterID: cfg.GetClusterId()})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sites) != 2 || p.Sites[0].ID != "a" || p.Sites[1].ID != "b" {
		t.Fatalf("plan sites %+v", p.Sites)
	}
	a, bs := p.Sites[0], p.Sites[1]
	if !a.LogBlocked || !a.LogQuery || !a.LogPeer || !slices.Equal(a.LogHeaders, []string{"accept-language", "x-trace-id"}) || a.LogSampleRate != 1000 {
		t.Fatalf("site a %+v", a)
	}
	if bs.LogBlocked || bs.LogQuery || bs.LogPeer || bs.LogHeaders != nil {
		t.Fatalf("site b %+v", bs)
	}
	for _, f := range cfg.GetRequiredFeatures() {
		if !slices.Contains(SupportedFeatures, f) {
			t.Errorf("required feature %s is not supported", f)
		}
	}
	// The site table the data plane gets: options only where they are on.
	raw, err := json.Marshal(p.Sites)
	if err != nil {
		t.Fatal(err)
	}
	var table []map[string]any
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	if table[0]["log_blocked"] != true || table[0]["log_query"] != true || table[0]["log_peer"] != true {
		t.Errorf("site a table %v", table[0])
	}
	if h, ok := table[0]["log_headers"].([]any); !ok || len(h) != 2 || h[0] != "accept-language" {
		t.Errorf("site a log_headers %v", table[0]["log_headers"])
	}
	for _, k := range []string{"log_blocked", "log_query", "log_headers", "log_peer"} {
		if _, ok := table[1][k]; ok {
			t.Errorf("site b table carries %s", k)
		}
	}
}
