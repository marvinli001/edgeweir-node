package configir

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	nodev1 "github.com/edgeweir/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func TestBuildHappyPath(t *testing.T) {
	cfg := vectorConfig()
	p, err := Build(cfg, Options{ClusterID: "c1", DefaultPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", p.Warnings)
	}
	if len(p.Listeners) != 1 || p.Listeners[0].Port != 80 {
		t.Fatalf("listeners = %+v", p.Listeners)
	}
	if len(p.CacheZones) != 1 || p.CacheZones[0] != (CacheZone{Name: "default", MaxSizeMB: 1024, KeysZoneMB: 10, InactiveSeconds: 600}) {
		t.Fatalf("zones = %+v", p.CacheZones)
	}
	if len(p.Sites) != 1 {
		t.Fatalf("sites = %+v", p.Sites)
	}
	s := p.Sites[0]
	if s.CacheZone != "default" || s.CacheGeneration != 1 || s.LoadBalance != LBWeighted {
		t.Fatalf("site = %+v", s)
	}
	if s.Origins[0] != (Origin{ID: "o1", Scheme: "http", Address: "whoami", Port: 80, Weight: 1}) {
		t.Fatalf("origin = %+v", s.Origins[0])
	}
	r := s.CacheRules[0]
	if r.Action != ActionCache || r.Mode != ModeOverride || r.TTL != 60 || r.PathPrefixes[0] != "/" {
		t.Fatalf("rule = %+v", r)
	}
}

func TestBuildRejectsExpression(t *testing.T) {
	cfg := vectorConfig()
	cfg.Sites[0].CacheRules[0].Match.Expression = `http.host eq "a.com"`
	_, err := Build(cfg, Options{})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
}

func TestBuildRejectsForeignCluster(t *testing.T) {
	_, err := Build(vectorConfig(), Options{ClusterID: "other"})
	if !errors.Is(err, ErrRejected) {
		t.Fatalf("err = %v, want ErrRejected", err)
	}
}

func TestBuildSkipsInvalidParts(t *testing.T) {
	cfg := &nodev1.NodeConfig{
		Listeners: []*nodev1.Listener{
			{Port: 0},
			{Port: 70000},
			{Port: 443, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTPS},
			{Port: 8080, Http2: true},
			{Port: 8080},
		},
		CacheZones: []*nodev1.CacheZone{
			{Name: "bad name"},
			{Name: "edgeweir_sites"},
			{Name: "main"},
		},
		Sites: []*nodev1.Site{
			{ // valid, but references an unknown zone and has bad parts
				Id: "a", Enabled: true, CacheZone: "missing",
				Domains: []*nodev1.Domain{
					{Name: "A.Test"}, {Name: "bad_domain.test"}, {Name: "*.x.test"},
					{Name: "wild.test", Wildcard: true}, {Name: "com", Wildcard: true},
				},
				OriginPool: &nodev1.OriginPool{Origins: []*nodev1.Origin{
					{Id: "ok", Address: "10.0.0.1", Port: 8080},
					{Id: "https-default", Address: "origin.test", Scheme: nodev1.OriginScheme_ORIGIN_SCHEME_HTTPS},
					{Id: "bad-port", Address: "origin.test", Port: 70000},
					{Id: "bad-addr", Address: "edgeweir_origin_layer"},
					{Id: "bad-host", Address: "origin.test", HostHeader: "a b"},
				}},
				CacheRules: []*nodev1.CacheRule{
					{Id: "r0", Action: nodev1.CacheAction_CACHE_ACTION_UNSPECIFIED},
					{Id: "r1", Action: nodev1.CacheAction_CACHE_ACTION_CACHE, Match: &nodev1.CacheRuleMatch{Extensions: []string{"..", "*"}}},
					{Id: "r2", Action: nodev1.CacheAction_CACHE_ACTION_CACHE, EdgeTtlSeconds: 30,
						OriginCacheControl: nodev1.OriginCacheControl_ORIGIN_CACHE_CONTROL_RESPECT,
						Match:              &nodev1.CacheRuleMatch{PathPrefixes: []string{"static/"}, Extensions: []string{".PNG", "css"}}},
				},
			},
			{ // loses its only domain to site a
				Id: "b", Enabled: true,
				Domains:    []*nodev1.Domain{{Name: "a.test"}},
				OriginPool: &nodev1.OriginPool{Origins: []*nodev1.Origin{{Id: "o", Address: "1.1.1.1"}}},
			},
			{ // no origins
				Id: "c", Enabled: true,
				Domains: []*nodev1.Domain{{Name: "c.test"}},
			},
			{ // disabled
				Id: "d", Enabled: false,
				Domains:    []*nodev1.Domain{{Name: "d.test"}},
				OriginPool: &nodev1.OriginPool{Origins: []*nodev1.Origin{{Id: "o", Address: "1.1.1.1"}}},
			},
		},
	}
	p, err := Build(cfg, Options{DefaultPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Listeners) != 1 || p.Listeners[0] != (Listener{Port: 8080, HTTP2: true}) {
		t.Fatalf("listeners = %+v", p.Listeners)
	}
	if len(p.CacheZones) != 1 || p.CacheZones[0].Name != "main" || p.CacheZones[0].MaxSizeMB != defaultZoneMaxSizeMB {
		t.Fatalf("zones = %+v", p.CacheZones)
	}
	if len(p.Sites) != 1 || p.Sites[0].ID != "a" {
		t.Fatalf("sites = %+v", p.Sites)
	}
	s := p.Sites[0]
	if s.CacheZone != "main" {
		t.Fatalf("cache zone fallback = %q", s.CacheZone)
	}
	if got := domainNames(s.Domains); got != "a.test,wild.test*" {
		t.Fatalf("domains = %s", got)
	}
	if len(s.Origins) != 2 || s.Origins[1].Port != 443 || s.Origins[1].Scheme != "https" {
		t.Fatalf("origins = %+v", s.Origins)
	}
	if len(s.CacheRules) != 1 {
		t.Fatalf("cache rules = %+v", s.CacheRules)
	}
	r := s.CacheRules[0]
	if r.ID != "r2" || r.PathPrefixes[0] != "/static/" || strings.Join(r.Extensions, ",") != "png,css" || r.Mode != ModeRespect {
		t.Fatalf("rule = %+v", r)
	}
	joined := strings.Join(p.Warnings, "\n")
	for _, want := range []string{
		"invalid port 0", "invalid port 70000", "HTTPS listener on port 443", "duplicate listener on port 8080",
		`cache zone "bad name"`, `cache zone "edgeweir_sites"`, `unknown cache zone "missing"`,
		`invalid domain "bad_domain.test"`, `invalid domain "*.x.test"`, `wildcard over a top-level label "com"`,
		`origin "bad-port"`, `origin "bad-addr"`, `origin "bad-host"`,
		`cache rule "r0"`, `cache rule "r1"`,
		`domain "a.test" already served by site a`, "site b skipped", "site c skipped: no valid origin",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings missing %q\n%s", want, joined)
		}
	}
}

func TestBuildDefaults(t *testing.T) {
	p, err := Build(&nodev1.NodeConfig{}, Options{DefaultPort: 8081})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Listeners) != 1 || p.Listeners[0].Port != 8081 {
		t.Fatalf("listeners = %+v", p.Listeners)
	}
	if len(p.CacheZones) != 1 || p.CacheZones[0].Name != DefaultCacheZone {
		t.Fatalf("zones = %+v", p.CacheZones)
	}
	if len(p.Warnings) != 0 {
		t.Fatalf("warnings = %v", p.Warnings)
	}
	b := Bootstrap(80)
	if b.Revision != 0 || len(b.Sites) != 0 || b.Listeners[0].Port != 80 {
		t.Fatalf("bootstrap = %+v", b)
	}
}

// TestBuildSkipsCacheZonesNamedLikeSharedDicts: nginx has one namespace
// for shared memory zones, so a cache zone named like any lua_shared_dict
// of the data plane would make `nginx -t` fail for the whole cluster.
func TestBuildSkipsCacheZonesNamedLikeSharedDicts(t *testing.T) {
	for _, name := range []string{"edgeweir_sites", "edgeweir_meta", "edgeweir_stats", "edgeweir_purge", "edgeweir_health"} {
		cfg := &nodev1.NodeConfig{CacheZones: []*nodev1.CacheZone{{Name: name}, {Name: "main"}}}
		p, err := Build(cfg, Options{DefaultPort: 80})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.CacheZones) != 1 || p.CacheZones[0].Name != "main" {
			t.Errorf("cache zone %q: zones = %+v, want only main", name, p.CacheZones)
		}
		if want := fmt.Sprintf("cache zone %q skipped", name); !strings.Contains(strings.Join(p.Warnings, "\n"), want) {
			t.Errorf("warnings %v miss %q", p.Warnings, want)
		}
	}
	// Other names with the same prefix stay usable.
	p, err := Build(&nodev1.NodeConfig{CacheZones: []*nodev1.CacheZone{{Name: "edgeweir_images"}}}, Options{DefaultPort: 80})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.CacheZones) != 1 || p.CacheZones[0].Name != "edgeweir_images" || len(p.Warnings) != 0 {
		t.Fatalf("zones = %+v, warnings = %v", p.CacheZones, p.Warnings)
	}
}

func TestValidHostname(t *testing.T) {
	good := []string{"a.test", "demo.test", "xn--fiqs8s.cn", "a-b.c-d.e", "localhost", "1.2.3.4", strings.Repeat("a", 63) + ".test"}
	bad := []string{"", "-a.test", "a-.test", "a..test", "a.test.", ".a.test", "A.test", "a_b.test", "*.a.test", "a test", strings.Repeat("a", 64) + ".test", strings.Repeat("a.", 127) + "aa"}
	for _, h := range good {
		if !ValidHostname(h) {
			t.Errorf("ValidHostname(%q) = false", h)
		}
	}
	for _, h := range bad {
		if ValidHostname(h) {
			t.Errorf("ValidHostname(%q) = true", h)
		}
	}
}

func domainNames(ds []Domain) string {
	var out []string
	for _, d := range ds {
		n := d.Name
		if d.Wildcard {
			n += "*"
		}
		out = append(out, n)
	}
	return strings.Join(out, ",")
}

// TestBuildRejectsUnsafeIDs: ids are separators in the data plane (cache,
// purge and health keys, X-Edgeweir-Rules), so a config with any other
// character is rejected as a whole.
func TestBuildRejectsUnsafeIDs(t *testing.T) {
	for _, mutate := range []func(*nodev1.NodeConfig){
		func(c *nodev1.NodeConfig) { c.Sites[0].Id = "s|1" },
		func(c *nodev1.NodeConfig) { c.Sites[0].Id = "s 1" },
		func(c *nodev1.NodeConfig) { c.Sites[0].Id = "s:1" },
		func(c *nodev1.NodeConfig) { c.Sites[0].Id = strings.Repeat("s", 129) },
		func(c *nodev1.NodeConfig) { c.Sites[0].OriginPool.Origins[0].Id = "o/1" },
		func(c *nodev1.NodeConfig) { c.Sites[0].OriginPool.Origins[0].Id = "o\x00" },
		func(c *nodev1.NodeConfig) { c.Sites[0].CacheRules[0].Id = "r,1" },
		func(c *nodev1.NodeConfig) { c.Sites[0].CacheRules[0].Id = "règle" },
	} {
		cfg := vectorConfig()
		mutate(cfg)
		if _, err := Build(cfg, Options{}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "may only contain") {
			t.Errorf("config accepted or wrong error: %v", err)
		}
	}
	cfg := vectorConfig()
	cfg.Sites[0].Id = "Site_A-1"
	cfg.Sites[0].OriginPool.Origins[0].Id = "0b2c6f1e-4c1d-4a8e-9f0a-2d7c3e5b6a91"
	cfg.Sites[0].CacheRules[0].Id = "rule_1"
	if _, err := Build(cfg, Options{}); err != nil {
		t.Fatalf("valid ids rejected: %v", err)
	}
	// Empty origin and rule ids drop the item only.
	cfg = vectorConfig()
	cfg.Sites[0].OriginPool.Origins = append(cfg.Sites[0].OriginPool.Origins, &nodev1.Origin{Address: "b.test", Port: 80})
	cfg.Sites[0].CacheRules = append(cfg.Sites[0].CacheRules, &nodev1.CacheRule{Priority: 99, Action: nodev1.CacheAction_CACHE_ACTION_CACHE})
	p, err := Build(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sites[0].Origins) != 1 || len(p.Sites[0].CacheRules) != 1 ||
		!strings.Contains(strings.Join(p.Warnings, "\n"), "origin without id") || !strings.Contains(strings.Join(p.Warnings, "\n"), "rule without id") {
		t.Fatalf("origins %+v rules %+v warnings %v", p.Sites[0].Origins, p.Sites[0].CacheRules, p.Warnings)
	}
}
