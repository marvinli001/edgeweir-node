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
// site's server (longest suffix first, never a Host that starts with a
// dot; patterns by order, case-sensitive), a guard takes Hosts longer than
// 253 characters before any regex name, the default site's server is the
// default_server and the generic server keeps requests without a Host
// (named `_ ""`).
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
		`_ ""`,
		`"~^.{254}"`,
		`a.test ~^[^.]+\.a\.test$`,
		"c.test",
		// Longest first: a nested suffix always comes before the one it is under.
		`~^[^.].*\.deep\.test$`,
		`~^[^.].*\.x\.a\.test$`,
		`~^[^.].*\.a\.test$`,
		`"~(?-i)^(?:(www|m)\.e\.test)$"`,
		`"~(?-i)^(?:api\d+\.test)$"`,
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

// TestRenderDefaultSiteServer: handing requests to a default site moves
// default_server to its server without losing the plain listener's h2c
// (gRPC sites) and turns "*.x" into one label even without suffix or
// pattern domains (a deeper host is unknown to the store and goes to the
// default site, so it must not get the wildcard site's server).
func TestRenderDefaultSiteServer(t *testing.T) {
	plan := domainsPlan()
	plan.Sites = []configir.Site{
		{ID: "g", GRPC: true, TLS: &configir.TLSOptions{MinimumVersion: "1.2", CipherProfile: "modern"}, Domains: []configir.Domain{{Name: "grpc.test"}}},
		{ID: "w", TLS: &configir.TLSOptions{MinimumVersion: "1.2", CipherProfile: "modern"}, Domains: []configir.Domain{{Name: "w.test", Wildcard: true}}},
		{ID: "d", TLS: &configir.TLSOptions{MinimumVersion: "1.2", CipherProfile: "modern"}, Domains: []configir.Domain{{Name: "d.test"}}},
	}
	plan.UnknownHosts = &configir.UnknownHosts{UnknownHost: "site", IPAccess: "close", DefaultSiteID: "d"}
	got, err := Render(params(), plan)
	if err != nil {
		t.Fatal(err)
	}
	conf := string(got)
	var server string
	for _, block := range strings.Split(conf, "    server {")[1:] {
		if strings.Contains(block, "server_name d.test;") && strings.Contains(block, "listen 80 default_server") {
			server = block
		}
	}
	if server == "" {
		t.Fatalf("no default server for d on 80:\n%s", conf)
	}
	if !strings.Contains(server, "http2 on;") {
		t.Errorf("the default site's server on 80 lost h2c:\n%s", server)
	}
	if !strings.Contains(conf, `server_name ~^[^.]+\.w\.test$;`) || strings.Contains(conf, "*.w.test") {
		t.Errorf("wildcard not one label with a default site")
	}
}

// TestRenderUnboundSiteNames: a site not bound to a listener's port has no
// server there; its names go to the server its hosts are served by
// (edgeweir.router: unknown), the default site's while unknown hosts are
// handed to it, else the generic server.
func TestRenderUnboundSiteNames(t *testing.T) {
	plan := domainsPlan()
	tls := plan.Sites[0].TLS
	plan.Sites = []configir.Site{
		{ID: "u", TLS: tls, Ports: []uint32{8080}, Domains: []configir.Domain{
			{Name: "u.test"}, {Name: "u.test", Match: configir.MatchSuffix},
		}},
		{ID: "d", TLS: tls, Domains: []configir.Domain{{Name: "d.test"}}},
	}
	plan.Listeners = []configir.Listener{{Port: 80}, {Port: 8080}}
	plan.UnknownHosts = &configir.UnknownHosts{UnknownHost: "site", IPAccess: "page", DefaultSiteID: "d"}
	got, err := Render(params(), plan)
	if err != nil {
		t.Fatal(err)
	}
	conf := string(got)
	for _, want := range []string{
		"server_name d.test u.test;",
		`server_name ~^[^.].*\.u\.test$;`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q", want)
		}
	}
	// Unknown hosts get the page: the generic server takes the names.
	plan.UnknownHosts.UnknownHost = "page"
	plan.UnknownHosts.IPAccess = "site"
	got, err = Render(params(), plan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `server_name _ "" u.test;`) {
		t.Errorf("unbound names not on the generic server")
	}
}
