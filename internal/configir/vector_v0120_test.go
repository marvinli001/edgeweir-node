package configir

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// v0120Fields adds every proto v0.12.0 IR field to a copy of the M2 vector,
// as the console's vector (packages/config-compiler/test/fixtures) does: on
// the first site of the file (s2) keep_cache_tag, error pages (statuses
// unsorted, UTF-8 templates with placeholders) that intercept origin
// errors, and an origin pool with an active health check and session
// affinity; challenge keys unsorted, the platform's error pages without
// site_disabled, offline hosts out of order (one name exact and wildcard,
// one name that extends another) and required_features unsorted with a
// duplicate. The canonical form sorts the pages by status, the offline
// hosts by (name, wildcard), the keys by id and the features as a set.
func v0120Fields(m2 *nodev1.NodeConfig) *nodev1.NodeConfig {
	c := proto.CloneOf(m2)
	s := c.Sites[0]
	s.KeepCacheTag = true
	s.ErrorPages = &nodev1.SiteErrorPages{
		Pages: []*nodev1.ErrorPage{
			{Status: 503, Template: "<h1>{{status}}</h1><p>{{request_id}} {{client_ip}} {{host}}</p>"},
			{Status: 403, Template: "<p>denied {{unknown}} 错误</p>"},
		},
		InterceptOriginErrors: true,
	}
	s.OriginPool.ActiveHealthCheck = &nodev1.ActiveHealthCheck{
		Path: "/healthz?full=1", Method: "HEAD", ExpectedStatusMin: 200, ExpectedStatusMax: 299, Host: "health.example.com",
		IntervalSeconds: 10, TimeoutSeconds: 3, HealthyThreshold: 2, UnhealthyThreshold: 3,
	}
	s.OriginPool.SessionAffinity = &nodev1.SessionAffinity{TtlSeconds: 3600}
	c.ChallengeKeys = []*nodev1.ChallengeKeyRef{{Id: "k2", Role: "current"}, {Id: "k3", Role: "next"}, {Id: "k1", Role: "previous"}}
	c.PlatformErrorPages = &nodev1.PlatformErrorPages{
		UnknownHost:   "<h1>{{host}} is not served here</h1>",
		SiteSuspended: "<h1>suspended</h1><p>{{request_id}}</p>",
	}
	c.OfflineHosts = []*nodev1.OfflineHost{
		{Name: "old.test", Reason: "disabled"},
		{Name: "away.test", Wildcard: true, Reason: "suspended"},
		{Name: "away.test", Reason: "suspended"},
		{Name: "away.test.example", Reason: "disabled"},
	}
	c.RequiredFeatures = []string{"session-affinity-v1", "error-pages-v1", "challenge-v1", "active-health-v1", "error-pages-v1"}
	return c
}

// TestContentHashVectorV0120 checks the proto v0.12.0 vector shared with
// the console (testdata/content_hash_vector_v0120.json, a copy of the
// console's fixture; its canonical_hex and content_hash come from
// protobuf-es): the M2 vector plus the fields of v0120Fields must encode to
// the same canonical bytes in Go.
func TestContentHashVectorV0120(t *testing.T) {
	path := filepath.Join("testdata", "content_hash_vector_v0120.json")
	want := v0120Fields(m2VectorConfig(t))
	b, err := CanonicalBytes(want)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ContentHash(want)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
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
	if !proto.Equal(cfg, want) {
		t.Fatalf("vector config is not the M2 vector plus the v0.12.0 fields:\n%v", cfg)
	}
	if v.CanonicalHex != hex.EncodeToString(b) {
		t.Fatalf("canonical bytes differ from the console\n got %x\nwant %s", b, v.CanonicalHex)
	}
	if v.ContentHash != h {
		t.Fatalf("vector hash %s, Go computes %s", v.ContentHash, h)
	}
	// The unsorted lists hash like their canonical form.
	Canonicalize(cfg)
	var statuses []uint32
	for _, s := range cfg.Sites {
		for _, p := range s.GetErrorPages().GetPages() {
			statuses = append(statuses, p.GetStatus())
		}
	}
	if !slices.Equal(statuses, []uint32{403, 503}) {
		t.Errorf("canonical error page statuses %v", statuses)
	}
	var hosts []string
	for _, o := range cfg.OfflineHosts {
		hosts = append(hosts, displayDomain(o.GetName(), o.GetWildcard()))
	}
	if !slices.Equal(hosts, []string{"away.test", "*.away.test", "away.test.example", "old.test"}) {
		t.Errorf("canonical offline hosts %v", hosts)
	}
	if !slices.Equal(cfg.RequiredFeatures, []string{"active-health-v1", "challenge-v1", "error-pages-v1", "session-affinity-v1"}) {
		t.Errorf("canonical required features %v", cfg.RequiredFeatures)
	}
	if hc, _ := ContentHash(cfg); hc != h {
		t.Fatalf("canonical config hashes to %s, want %s", hc, h)
	}
	// Every v0.12.0 field is part of the canonical bytes.
	for name, clear := range map[string]func(*nodev1.NodeConfig){
		"keep_cache_tag":          func(c *nodev1.NodeConfig) { c.Sites[0].KeepCacheTag = false },
		"error_pages":             func(c *nodev1.NodeConfig) { c.Sites[0].ErrorPages = nil },
		"intercept_origin_errors": func(c *nodev1.NodeConfig) { c.Sites[0].ErrorPages.InterceptOriginErrors = false },
		"active_health_check":     func(c *nodev1.NodeConfig) { c.Sites[0].OriginPool.ActiveHealthCheck = nil },
		"session_affinity":        func(c *nodev1.NodeConfig) { c.Sites[0].OriginPool.SessionAffinity = nil },
		"platform_error_pages":    func(c *nodev1.NodeConfig) { c.PlatformErrorPages = nil },
		"offline_hosts":           func(c *nodev1.NodeConfig) { c.OfflineHosts = nil },
	} {
		c := v0120Fields(m2VectorConfig(t))
		clear(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}
	// The plan carries what the vector sets.
	p, err := Build(cfg, Options{ClusterID: "c1", ExtraFeatures: []string{FeatureActiveHealth}})
	if err != nil {
		t.Fatal(err)
	}
	var s2 *Site
	for i := range p.Sites {
		if p.Sites[i].ID == "s2" {
			s2 = &p.Sites[i]
		}
	}
	if s2 == nil || !s2.KeepCacheTag || s2.ErrorPages == nil || len(s2.ErrorPages.Pages) != 2 || !s2.ErrorPages.Intercept ||
		!s2.ActiveHealth || s2.Affinity == nil || s2.Affinity.TTL != 3600 {
		t.Fatalf("plan site s2 = %+v", s2)
	}
	if len(p.OfflineHosts) != 4 || p.PlatformErrorPages == nil || p.PlatformErrorPages.SiteDisabled != "" {
		t.Fatalf("plan: offline %v, pages %+v", p.OfflineHosts, p.PlatformErrorPages)
	}
}

func TestCanonicalizeV0120(t *testing.T) {
	s := site("site-a", "a.test")
	s.ErrorPages = &nodev1.SiteErrorPages{Pages: []*nodev1.ErrorPage{page(504, "c"), page(403, "a"), page(429, "b")}}
	c := &nodev1.NodeConfig{
		Sites: []*nodev1.Site{s},
		OfflineHosts: []*nodev1.OfflineHost{
			{Name: "b.test", Reason: "disabled"},
			{Name: "a.test", Wildcard: true, Reason: "suspended"},
			{Name: "a.test", Reason: "disabled"},
			{Name: "a.b.test", Reason: "disabled"},
		},
	}
	h1, err := ContentHash(c)
	if err != nil {
		t.Fatal(err)
	}
	Canonicalize(c)
	var names []string
	for _, h := range c.OfflineHosts {
		names = append(names, displayDomain(h.GetName(), h.GetWildcard()))
	}
	// Name first, exact before wildcard (the console sorts by
	// "<name>\0<0|1>").
	if got := strings.Join(names, ","); got != "a.b.test,a.test,*.a.test,b.test" {
		t.Fatalf("offline hosts %s", got)
	}
	var statuses []uint32
	for _, p := range c.Sites[0].ErrorPages.Pages {
		statuses = append(statuses, p.GetStatus())
	}
	if !slices.Equal(statuses, []uint32{403, 429, 504}) {
		t.Fatalf("pages %v", statuses)
	}
	h2, _ := ContentHash(c)
	if h1 != h2 {
		t.Fatal("canonical order changed the hash of the unsorted config")
	}
}

func TestApplyDiffCarriesPlatformPagesAndOfflineHosts(t *testing.T) {
	base := withHash(t, &nodev1.NodeConfig{Revision: 1, ClusterId: "c1", Sites: []*nodev1.Site{site("site-a", "a.test")}})
	target := &nodev1.NodeConfig{Revision: 2, ClusterId: "c1", Sites: []*nodev1.Site{site("site-a", "a.test")},
		PlatformErrorPages: &nodev1.PlatformErrorPages{UnknownHost: "<p>gone</p>"},
		OfflineHosts:       []*nodev1.OfflineHost{{Name: "z.test", Reason: "suspended"}, {Name: "b.test", Reason: "disabled"}},
	}
	target = withHash(t, target)
	d := Diff(base, target)
	if d.GetPlatformErrorPages().GetUnknownHost() != "<p>gone</p>" || len(d.GetOfflineHosts()) != 2 {
		t.Fatalf("diff = %v", d)
	}
	got, err := ApplyDiff(base, d)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, target) {
		t.Fatalf("diff result differs from the target:\n%v\n%v", got, target)
	}
	// Both are sent in full: a diff without them clears them.
	clear := withHash(t, &nodev1.NodeConfig{Revision: 3, ClusterId: "c1", Sites: []*nodev1.Site{site("site-a", "a.test")}})
	got, err = ApplyDiff(target, Diff(target, clear))
	if err != nil || got.PlatformErrorPages != nil || len(got.OfflineHosts) != 0 {
		t.Fatalf("after clearing: %v, %v", got, err)
	}
}
