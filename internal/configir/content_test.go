package configir

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func buildOne(t *testing.T, s *nodev1.Site) (*Site, error) {
	t.Helper()
	p, err := Build(&nodev1.NodeConfig{Sites: []*nodev1.Site{s}}, Options{})
	if err != nil {
		return nil, err
	}
	if len(p.Sites) != 1 {
		t.Fatalf("sites = %+v", p.Sites)
	}
	return &p.Sites[0], nil
}

func mustReject(t *testing.T, name string, s *nodev1.Site) {
	t.Helper()
	if _, err := Build(&nodev1.NodeConfig{Sites: []*nodev1.Site{s}}, Options{}); !errors.Is(err, ErrRejected) {
		t.Errorf("%s: err = %v, want rejection", name, err)
	}
	// Disabled sites are checked too.
	s.Enabled = false
	if _, err := Build(&nodev1.NodeConfig{Sites: []*nodev1.Site{s}}, Options{}); !errors.Is(err, ErrRejected) {
		t.Errorf("%s on a disabled site: err = %v, want rejection", name, err)
	}
}

func TestSiteContentDefaults(t *testing.T) {
	got, err := buildOne(t, site("s", "a.test"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Tries != DefaultOriginTries || got.NoStatusRetry || got.HideXCache || got.Purge || got.PurgeKey != nil ||
		got.Maintenance != nil || got.Charset != nil || got.BodyLimit != DefaultRequestBodyLimit {
		t.Fatalf("defaults = %+v", got)
	}
	if !slices.Contains(SupportedFeatures, FeatureSiteContent) || !slices.Contains(SupportedFeatures, FeatureCacheZone) {
		t.Fatal("site-content-v1 and cache-zone-v1 must be announced")
	}
}

func TestSiteContentSettings(t *testing.T) {
	s := site("s", "a.test")
	s.OriginPool.Tries = 5
	s.OriginPool.StatusRetryDisabled = true
	s.HideXCache = true
	s.Purge = &nodev1.PurgeMethod{CredentialId: "key-1", CredentialVersion: 3}
	s.Maintenance = &nodev1.Maintenance{Template: "<p>{{status}}</p>", RetryAfterSeconds: 120,
		AllowedCidrs: []string{"192.0.2.0/24", "2001:db8::/32", "::ffff:102:304/128"}, AllowedPathPrefixes: []string{"/health", "/status/"}}
	s.Charset = &nodev1.Charset{Name: "gbk", Force: true, Uppercase: true}
	s.RequestBodyLimit = proto.Uint64(0)
	s.Tls = &nodev1.TlsOptions{MinimumVersion: "1.2", CipherProfile: "modern", Gzip: true, GzipLevel: 9, CompressMaxLength: 1 << 20}
	got, err := buildOne(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if got.Tries != 5 || !got.NoStatusRetry || !got.HideXCache || !got.Purge || *got.PurgeKey != (PurgeRef{"key-1", 3}) ||
		got.BodyLimit != 0 || got.TLS.GzipLevel != 9 || got.TLS.CompressMaxLength != 1<<20 {
		t.Fatalf("site = %+v", got)
	}
	if *got.Charset != (Charset{Name: "gbk", Force: true, Uppercase: true}) {
		t.Fatalf("charset = %+v", got.Charset)
	}
	m := got.Maintenance
	// The IPv4-mapped prefix (as the console writes it) becomes IPv4: the data
	// plane looks IPv4 clients up as IPv4.
	if m.Template != "<p>{{status}}</p>" || m.RetryAfter != 120 || !slices.Equal(m.AllowCIDRs, []string{"192.0.2.0/24", "2001:db8::/32", "1.2.3.4/32"}) ||
		!slices.Equal(m.AllowPrefixes, []string{"/health", "/status/"}) {
		t.Fatalf("maintenance = %+v", m)
	}
	p, _ := Build(&nodev1.NodeConfig{Sites: []*nodev1.Site{s}}, Options{})
	if refs := p.CredentialRefs(); refs["key-1"] != 3 {
		t.Fatalf("credential refs = %v, want the PURGE key", refs)
	}
	// The key never reaches the data plane's site table.
	if raw := siteJSON(t, got); strings.Contains(raw, "key-1") || !strings.Contains(raw, `"purge":true`) {
		t.Fatalf("site table = %s", raw)
	}
}

func TestSiteContentRejections(t *testing.T) {
	for name, edit := range map[string]func(*nodev1.Site){
		"six tries":          func(s *nodev1.Site) { s.OriginPool.Tries = 6 },
		"PURGE key id":       func(s *nodev1.Site) { s.Purge = &nodev1.PurgeMethod{CredentialId: "a b"} },
		"maintenance CIDR":   func(s *nodev1.Site) { s.Maintenance = &nodev1.Maintenance{AllowedCidrs: []string{"192.0.2.1/24"}} },
		"maintenance prefix": func(s *nodev1.Site) { s.Maintenance = &nodev1.Maintenance{AllowedPathPrefixes: []string{"health"}} },
		"maintenance query":  func(s *nodev1.Site) { s.Maintenance = &nodev1.Maintenance{AllowedPathPrefixes: []string{"/a?b"}} },
		"maintenance Retry":  func(s *nodev1.Site) { s.Maintenance = &nodev1.Maintenance{RetryAfterSeconds: 86401} },
		"maintenance page": func(s *nodev1.Site) {
			s.Maintenance = &nodev1.Maintenance{Template: strings.Repeat("m", MaxErrorPageBytes+1)}
		},
		"maintenance CIDR count": func(s *nodev1.Site) { s.Maintenance = &nodev1.Maintenance{AllowedCidrs: manyCIDRs(65)} },
		"charset":                func(s *nodev1.Site) { s.Charset = &nodev1.Charset{Name: "latin1"} },
		"charset case":           func(s *nodev1.Site) { s.Charset = &nodev1.Charset{Name: "GBK"} },
		"body limit":             func(s *nodev1.Site) { s.RequestBodyLimit = proto.Uint64(MaxRequestBodyLimit + 1) },
		"gzip level": func(s *nodev1.Site) {
			s.Tls = &nodev1.TlsOptions{MinimumVersion: "1.2", CipherProfile: "modern", Gzip: true, GzipLevel: 10}
		},
	} {
		s := site("s", "a.test")
		edit(s)
		mustReject(t, name, s)
	}
}

func manyCIDRs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "10.0." + itoa(i) + ".0/24"
	}
	return out
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}

func TestCacheKeyExclude(t *testing.T) {
	key, warnings := buildCacheKey(&nodev1.CacheKeyPolicy{
		Query:       nodev1.CacheKeyQuery_CACHE_KEY_QUERY_EXCLUDE,
		QueryParams: []string{"fbclid", "utm_*", "*", "a*b", "x=y"},
	})
	if key.Query != QueryExclude || !slices.Equal(key.QueryParams, []string{"fbclid", "utm_*"}) || len(warnings) != 3 {
		t.Fatalf("key = %+v, warnings %q", key, warnings)
	}
	// Patterns belong to EXCLUDE only: an included name keeps "*" as an
	// ordinary character, as before proto v0.24.0.
	key, warnings = buildCacheKey(&nodev1.CacheKeyPolicy{
		Query: nodev1.CacheKeyQuery_CACHE_KEY_QUERY_INCLUDE, QueryParams: []string{"id", "v*", "a*b", "x=y"},
	})
	if key.Query != QueryInclude || !slices.Equal(key.QueryParams, []string{"id", "v*", "a*b"}) || len(warnings) != 1 {
		t.Fatalf("include key = %+v, warnings %q", key, warnings)
	}
}

func TestCacheRuleSetCookie(t *testing.T) {
	s := site("s", "a.test")
	s.CacheRules = []*nodev1.CacheRule{{Id: "r1", Action: nodev1.CacheAction_CACHE_ACTION_CACHE,
		OriginCacheControl: nodev1.OriginCacheControl_ORIGIN_CACHE_CONTROL_OVERRIDE, EdgeTtlSeconds: 60, CacheSetCookie: true}}
	got, err := buildOne(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.CacheRules) != 1 || !got.CacheRules[0].CacheSetCookie || !strings.Contains(siteJSON(t, got), `"set_cookie":true`) {
		t.Fatalf("rules = %+v", got.CacheRules)
	}
}

func TestErrorPagesV24(t *testing.T) {
	s := site("s", "a.test")
	s.ErrorPages = &nodev1.SiteErrorPages{InterceptOriginErrors: true, Pages: []*nodev1.ErrorPage{
		{Status: 4, Template: "<p>4xx</p>"},
		{Status: 5, RedirectUrl: "https://status.example.com/?code={{status}}&id={{request_id}}"},
		{Status: 404, Template: "<p>404</p>", ResponseStatus: 200},
		{Status: 410, RedirectUrl: "/gone"},
	}}
	got, err := buildOne(t, s)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint32]ErrorPage{
		4:   {Template: "<p>4xx</p>"},
		5:   {Redirect: "https://status.example.com/?code={{status}}&id={{request_id}}"},
		404: {Template: "<p>404</p>", Status: 200},
		410: {Redirect: "/gone"},
	}
	for status, page := range want {
		if got.ErrorPages.Pages[status] != page {
			t.Errorf("page %d = %+v, want %+v", status, got.ErrorPages.Pages[status], page)
		}
	}
	for name, p := range map[string]*nodev1.ErrorPage{
		"class 6":              {Status: 6, Template: "x"},
		"template and URL":     {Status: 404, Template: "x", RedirectUrl: "/x"},
		"URL with a status":    {Status: 404, RedirectUrl: "/x", ResponseStatus: 200},
		"protocol-relative":    {Status: 404, RedirectUrl: "//evil.test/"},
		"other scheme":         {Status: 404, RedirectUrl: "javascript:alert(1)"},
		"space":                {Status: 404, RedirectUrl: "/a b"},
		"unknown placeholder":  {Status: 404, RedirectUrl: "/x?h={{host}}"},
		"long URL":             {Status: 404, RedirectUrl: "/" + strings.Repeat("a", 2048)},
		"response status 199":  {Status: 404, Template: "x", ResponseStatus: 199},
		"response status 600":  {Status: 404, Template: "x", ResponseStatus: 600},
		"neither":              {Status: 404},
		"user info in the URL": {Status: 404, RedirectUrl: "https://u:p@example.com/"},
	} {
		s := site("s", "a.test")
		s.ErrorPages = &nodev1.SiteErrorPages{Pages: []*nodev1.ErrorPage{p}}
		mustReject(t, name, s)
	}
}

func TestCacheZoneNodeSizes(t *testing.T) {
	zone := &nodev1.CacheZone{Name: "default", MaxSizeMb: 10240, KeysZoneMb: 64, InactiveSeconds: 604800,
		NodeSizes: []*nodev1.CacheZoneNodeSize{
			{NodeId: "node-a", MaxSizeMb: 2048, KeysZoneMb: 16},
			{NodeId: "node-b", MaxSizeMb: 1 << 20, KeysZoneMb: 512},
		}}
	cfg := &nodev1.NodeConfig{CacheZones: []*nodev1.CacheZone{zone}}
	for node, want := range map[string]CacheZone{
		"node-b": {Name: "default", MaxSizeMB: 1 << 20, KeysZoneMB: 512, InactiveSeconds: 604800},
		"node-c": {Name: "default", MaxSizeMB: 10240, KeysZoneMB: 64, InactiveSeconds: 604800},
		"":       {Name: "default", MaxSizeMB: 10240, KeysZoneMB: 64, InactiveSeconds: 604800},
	} {
		p, err := Build(cfg, Options{NodeID: node})
		if err != nil || len(p.CacheZones) != 1 || p.CacheZones[0] != want {
			t.Errorf("node %q: zones = %+v, %v; want %+v", node, p.CacheZones, err, want)
		}
	}
	for name, sizes := range map[string][]*nodev1.CacheZoneNodeSize{
		"unsorted":    {{NodeId: "b", MaxSizeMb: 2048, KeysZoneMb: 16}, {NodeId: "a", MaxSizeMb: 2048, KeysZoneMb: 16}},
		"duplicate":   {{NodeId: "a", MaxSizeMb: 2048, KeysZoneMb: 16}, {NodeId: "a", MaxSizeMb: 4096, KeysZoneMb: 32}},
		"too small":   {{NodeId: "a", MaxSizeMb: 1023, KeysZoneMb: 16}},
		"too large":   {{NodeId: "a", MaxSizeMb: MaxCacheZoneMB + 1, KeysZoneMb: 16}},
		"keys zone":   {{NodeId: "a", MaxSizeMb: 2048, KeysZoneMb: 513}},
		"invalid id":  {{NodeId: "a:b", MaxSizeMb: 2048, KeysZoneMb: 16}},
		"no keys mem": {{NodeId: "a", MaxSizeMb: 2048}},
	} {
		z := proto.Clone(zone).(*nodev1.CacheZone)
		z.NodeSizes = sizes
		if _, err := Build(&nodev1.NodeConfig{CacheZones: []*nodev1.CacheZone{z}}, Options{NodeID: "a"}); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: err = %v, want rejection", name, err)
		}
	}
	// The console's derivation (ADR-0035): 64 MiB for the default 10 GiB.
	for size, want := range map[uint64]uint32{1024: 16, 10240: 64, 100 * 1024: 512, MaxCacheZoneMB: 512, 5000: 32} {
		if got := keysZoneMB(size); got != want {
			t.Errorf("keysZoneMB(%d) = %d, want %d", size, got, want)
		}
	}
}

func TestMaxRequestBody(t *testing.T) {
	limitRule := func(limit uint64) *nodev1.EdgeRule {
		return &nodev1.EdgeRule{Id: "r", Phase: "config", Expression: &nodev1.RuleExpression{Op: "eq", Field: "http.host", ValueType: "string", Value: "a.test"},
			Action: &nodev1.RuleAction{Kind: "config", RequestBodyLimit: proto.Uint64(limit)}}
	}
	build := func(c *nodev1.NodeConfig) uint64 {
		t.Helper()
		p, err := Build(c, Options{})
		if err != nil {
			t.Fatal(err)
		}
		return p.MaxRequestBody()
	}
	if got := build(&nodev1.NodeConfig{}); got != DefaultRequestBodyLimit {
		t.Fatalf("no sites: %d", got)
	}
	small, large := site("a", "a.test"), site("b", "b.test")
	small.RequestBodyLimit = proto.Uint64(1 << 20)
	large.RequestBodyLimit = proto.Uint64(1 << 30)
	if got := build(&nodev1.NodeConfig{Sites: []*nodev1.Site{small, large}}); got != 1<<30 {
		t.Fatalf("largest site limit: %d", got)
	}
	if got := build(&nodev1.NodeConfig{Sites: []*nodev1.Site{small}}); got != 1<<20 {
		t.Fatalf("one small site: %d", got)
	}
	small.Rules = []*nodev1.EdgeRule{limitRule(2 << 30)}
	if got := build(&nodev1.NodeConfig{Sites: []*nodev1.Site{small, large}}); got != 2<<30 {
		t.Fatalf("site rule: %d", got)
	}
	if got := build(&nodev1.NodeConfig{Sites: []*nodev1.Site{small, large}, PlatformRules: []*nodev1.EdgeRule{limitRule(0)}}); got != 0 {
		t.Fatalf("platform rule without limit: %d", got)
	}
	large.RequestBodyLimit = proto.Uint64(0)
	small.Rules = nil
	if got := build(&nodev1.NodeConfig{Sites: []*nodev1.Site{small, large}}); got != 0 {
		t.Fatalf("site without limit: %d", got)
	}
}

func TestConfigRuleBodyLimit(t *testing.T) {
	expr := &nodev1.RuleExpression{Op: "eq", Field: "http.host", ValueType: "string", Value: "a.test"}
	for _, tc := range []struct {
		name  string
		phase string
		limit uint64
		ok    bool
	}{
		{"config", "config", 1 << 30, true},
		{"no limit", "config", 0, true},
		{"over 10 GiB", "config", MaxRequestBodyLimit + 1, false},
		{"cache phase", "cache", 1 << 20, false},
	} {
		s := site("s", "a.test")
		s.Rules = []*nodev1.EdgeRule{{Id: "r", Phase: tc.phase, Expression: expr,
			Action: &nodev1.RuleAction{Kind: "config", RequestBodyLimit: proto.Uint64(tc.limit)}}}
		_, err := Build(&nodev1.NodeConfig{Sites: []*nodev1.Site{s}}, Options{})
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok %v", tc.name, err, tc.ok)
		}
	}
}

// siteJSON is the site as the data plane's site table holds it.
func siteJSON(t *testing.T, s *Site) string {
	t.Helper()
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestErrorRedirectVectors checks the error page redirect URLs shared with
// the console (testdata/error_redirect_vectors.json): the node accepts
// exactly what the console saves, so no saved page rejects a configuration.
func TestErrorRedirectVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "error_redirect_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []struct {
			Value string `json:"value"`
			Valid bool   `json:"valid"`
			Note  string `json:"note"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) < 30 {
		t.Fatalf("only %d cases", len(v.Cases))
	}
	for _, c := range v.Cases {
		if got := validErrorRedirect(c.Value); got != c.Valid {
			t.Errorf("%s (%q): valid = %v, want %v", c.Note, c.Value, got, c.Valid)
		}
	}
}

// TestMaintenanceMappedCIDRs: IPv4-mapped allow prefixes of /96 and longer
// become the IPv4 prefixes they cover, which the data plane looks IPv4
// clients up in.
func TestMaintenanceMappedCIDRs(t *testing.T) {
	for in, want := range map[string]string{
		"::ffff:0:0/96":       "0.0.0.0/0",
		"::ffff:c000:200/120": "192.0.2.0/24",
		"::ffff:102:304/128":  "1.2.3.4/32",
		"2001:db8::/32":       "2001:db8::/32",
	} {
		m, err := buildMaintenance(&nodev1.Maintenance{AllowedCidrs: []string{in}})
		if err != nil || len(m.AllowCIDRs) != 1 || m.AllowCIDRs[0] != want {
			t.Errorf("%s: %v %v, want %s", in, m, err, want)
		}
	}
}
