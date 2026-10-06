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

// v0240Vector reads testdata/content_hash_vector_v0240.json, a copy of the
// console's fixture (packages/config-compiler/test/fixtures): one site with
// every site-content-v1 setting (maintenance lists unsorted with
// duplicates, error pages unsorted), a platform config rule with a body
// limit and a cache zone with unsorted node_sizes (cache-zone-v1);
// required_features reversed with a duplicate. Its canonical_hex and
// content_hash come from protobuf-es.
func v0240Vector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_v0240.json"))
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

// TestContentHashVectorV0240 checks the proto v0.24.0 vector shared with
// the console: Go's canonical form encodes to the console's bytes and hash,
// every v0.24.0 field counts, and configir plans it with the node's own
// cache size.
func TestContentHashVectorV0240(t *testing.T) {
	cfg, v := v0240Vector(t)
	if m := vectorSite(cfg, "s1").GetMaintenance(); len(m.GetAllowedCidrs()) != 3 {
		t.Fatalf("vector maintenance lists are already canonical: %v", m)
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
	s1 := vectorSite(cfg, "s1")
	if m := s1.GetMaintenance(); !slices.Equal(m.GetAllowedCidrs(), []string{"192.0.2.0/24", "2001:db8::/32"}) ||
		!slices.Equal(m.GetAllowedPathPrefixes(), []string{"/health", "/status"}) {
		t.Errorf("canonical maintenance lists %v", m)
	}
	if n := cfg.GetCacheZones()[0].GetNodeSizes(); n[0].GetNodeId() != "node-a" || n[1].GetNodeId() != "node-b" {
		t.Errorf("canonical node sizes %v", n)
	}
	if want := []string{"cache-zone-v1", "error-pages-v1", "rules-v1", "rules-v2", "site-content-v1", "tls-v1"}; !slices.Equal(cfg.RequiredFeatures, want) {
		t.Errorf("canonical required features %v, want %v", cfg.RequiredFeatures, want)
	}

	// Every v0.24.0 field is part of the canonical bytes.
	for name, change := range map[string]func(*nodev1.NodeConfig){
		"purge":        func(c *nodev1.NodeConfig) { vectorSite(c, "s1").Purge.CredentialVersion = 3 },
		"x-cache":      func(c *nodev1.NodeConfig) { vectorSite(c, "s1").HideXCache = false },
		"maintenance":  func(c *nodev1.NodeConfig) { vectorSite(c, "s1").Maintenance.RetryAfterSeconds = 1 },
		"charset":      func(c *nodev1.NodeConfig) { vectorSite(c, "s1").Charset.Uppercase = false },
		"body limit":   func(c *nodev1.NodeConfig) { vectorSite(c, "s1").RequestBodyLimit = nil },
		"gzip level":   func(c *nodev1.NodeConfig) { vectorSite(c, "s1").Tls.GzipLevel = 1 },
		"max length":   func(c *nodev1.NodeConfig) { vectorSite(c, "s1").Tls.CompressMaxLength = 1 },
		"tries":        func(c *nodev1.NodeConfig) { vectorSite(c, "s1").OriginPool.Tries = 4 },
		"status retry": func(c *nodev1.NodeConfig) { vectorSite(c, "s1").OriginPool.StatusRetryDisabled = false },
		"set-cookie": func(c *nodev1.NodeConfig) {
			vectorSite(c, "s1").CacheRules[0].CacheSetCookie = !vectorSite(c, "s1").CacheRules[0].CacheSetCookie
		},
		"exclude": func(c *nodev1.NodeConfig) {
			vectorSite(c, "s1").CacheKey.Query = nodev1.CacheKeyQuery_CACHE_KEY_QUERY_INCLUDE
		},
		"redirect page": func(c *nodev1.NodeConfig) { pageByStatus(vectorSite(c, "s1"), 5).RedirectUrl = "/x" },
		"page status":   func(c *nodev1.NodeConfig) { pageByStatus(vectorSite(c, "s1"), 404).ResponseStatus = 0 },
		"rule limit":    func(c *nodev1.NodeConfig) { *c.PlatformRules[0].Action.RequestBodyLimit = 1 },
		"node size":     func(c *nodev1.NodeConfig) { c.CacheZones[0].NodeSizes[0].MaxSizeMb++ },
	} {
		c, _ := v0240Vector(t)
		change(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}

	// configir accepts what the console compiled; node-a uses its own size.
	p, err := Build(cfg, Options{ClusterID: "c1", NodeID: "node-a"})
	if err != nil {
		t.Fatal(err)
	}
	if z := p.CacheZones[0]; z.MaxSizeMB != 1048576 || z.KeysZoneMB != 512 || z.InactiveSeconds != 14*86400 {
		t.Fatalf("plan zone %+v", z)
	}
	site := p.Sites[0]
	if !site.Purge || !site.HideXCache || site.Maintenance == nil || site.Charset == nil || site.BodyLimit != 0 ||
		site.Tries != 5 || !site.NoStatusRetry || site.CacheKey.Query != QueryExclude {
		t.Fatalf("plan site %+v", site)
	}
	if p.MaxRequestBody() != 0 {
		t.Fatalf("client_max_body_size %d, want 0 (no limit)", p.MaxRequestBody())
	}
}

func pageByStatus(s *nodev1.Site, status uint32) *nodev1.ErrorPage {
	for _, p := range s.GetErrorPages().GetPages() {
		if p.GetStatus() == status {
			return p
		}
	}
	return &nodev1.ErrorPage{}
}
