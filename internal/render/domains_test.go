package render

import (
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

// domainsPlan: HTTP 80 and HTTPS 443 (HTTP/3); site a with an exact name,
// a wildcard, two suffixes and a pattern (HTTP/3, brotli), site b with a
// deeper suffix and an earlier pattern, site c with exact names only
// (the default site for unknown hosts and node IP access).
func domainsPlan() *configir.Plan {
	tls := func(http3, brotli bool) *configir.TLSOptions {
		return &configir.TLSOptions{MinimumVersion: "1.2", CipherProfile: "modern", HTTP2: true, HTTP3: http3, Brotli: brotli, BrotliLevel: 4}
	}
	return &configir.Plan{
		Listeners: []configir.Listener{
			{Port: 80},
			{Port: 443, TLS: true, HTTP2: true, HTTP3: true},
		},
		CacheZones: []configir.CacheZone{{Name: "default", MaxSizeMB: 1024, KeysZoneMB: 16, InactiveSeconds: 3600}},
		Sites: []configir.Site{
			{ID: "a", CertificateID: "c", TLS: tls(true, true), Domains: []configir.Domain{
				{Name: "a.test"},
				{Name: "a.test", Wildcard: true},
				{Name: "a.test", Match: configir.MatchSuffix},
				{Name: "deep.test", Match: configir.MatchSuffix},
				{Name: `api\d+\.test`, Match: configir.MatchRegex, Order: 32},
			}},
			{ID: "b", CertificateID: "c", TLS: tls(false, false), Domains: []configir.Domain{
				{Name: "x.a.test", Match: configir.MatchSuffix},
				{Name: `(www|m)\.e\.test`, Match: configir.MatchRegex, Order: 16},
			}},
			{ID: "c", CertificateID: "c", TLS: tls(false, false), Domains: []configir.Domain{{Name: "c.test"}}},
		},
		UnknownHosts: &configir.UnknownHosts{UnknownHost: "close", IPAccess: "site", DefaultSiteID: "c"},
	}
}

func TestRenderDomainsGolden(t *testing.T) {
	got, err := Render(params(), domainsPlan())
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "domains.conf.golden", got)
}

// TestRenderDomainServers: with suffix or pattern domains, wildcards match
// one label, suffixes and patterns get servers of their own after every
// site's server (longest suffix first, patterns by order), and the
// default site's server is the default_server.
func TestRenderDomainServers(t *testing.T) {
	got, err := Render(params(), domainsPlan())
	if err != nil {
		t.Fatal(err)
	}
	conf := string(got)
	var names []string
	defaults := map[string]bool{}
	for _, block := range strings.Split(conf, "    server {")[1:] {
		name, listen := "", ""
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			if v, ok := strings.CutPrefix(line, "server_name "); ok {
				name = strings.TrimSuffix(v, ";")
			}
			if v, ok := strings.CutPrefix(line, "listen "); ok && strings.HasPrefix(v, "443 ") {
				listen = v
			}
		}
		if listen == "" {
			continue
		}
		names = append(names, name)
		if strings.Contains(listen, "default_server") {
			defaults[name] = true
		}
	}
	want := []string{
		"_",
		`a.test ~^[^.]+\.a\.test$`,
		"c.test",
		// Longest first: a nested suffix always comes before the one it is under.
		`~^.+\.deep\.test$`,
		`~^.+\.x\.a\.test$`,
		`~^.+\.a\.test$`,
		`"~^(?:(www|m)\.e\.test)$"`,
		`"~^(?:api\d+\.test)$"`,
	}
	if strings.Join(names, "\n") != strings.Join(want, "\n") {
		t.Fatalf("443 server names\n%s\nwant\n%s", strings.Join(names, "\n"), strings.Join(want, "\n"))
	}
	if len(defaults) != 1 || !defaults["c.test"] {
		t.Fatalf("default servers on 443: %v", defaults)
	}
	for _, want := range []string{"listen 443 quic reuseport default_server;", "lua_regex_cache_max_entries 1028;"} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Count(conf, "reuseport default_server;") != 1 {
		t.Errorf("reuseport on more than one QUIC listen")
	}
	// Without suffixes and patterns wildcards stay nginx wildcards.
	plain := domainsPlan()
	plain.Sites = plain.Sites[2:]
	plain.Sites[0].Domains = append(plain.Sites[0].Domains, configir.Domain{Name: "c.test", Wildcard: true})
	plain.UnknownHosts = nil
	got, err = Render(params(), plain)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "server_name c.test *.c.test;") || strings.Contains(string(got), "lua_regex_cache_max_entries") {
		t.Fatal("plain wildcard or regex cache changed")
	}
}
