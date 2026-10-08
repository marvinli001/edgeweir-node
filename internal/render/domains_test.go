package render

import (
	"fmt"
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
// dot; patterns by order, case-sensitive, never a Host longer than 253
// characters), the default site's server is the default_server and, node
// IP access being handed to it, a server with its settings takes requests
// without a Host and IP hosts before any other regex name while the
// generic server gets a name of its own.
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
		`_ "" "~^(?:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[.*)$"`,
		"generic.edgeweir.invalid",
		`a.test ~^[^.]+\.a\.test$`,
		"c.test",
		// Longest first: a nested suffix always comes before the one it is under.
		`~^[^.].*\.deep\.test$`,
		`~^[^.].*\.x\.a\.test$`,
		`~^[^.].*\.a\.test$`,
		`"~(?-i)^(?!.{254})(?:(www|m)\.e\.test)$"`,
		`"~(?-i)^(?!.{254})(?:api\d+\.test)$"`,
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
	if !strings.Contains(string(got), `server_name generic.edgeweir.invalid u.test;`) {
		t.Errorf("unbound names not on the generic server")
	}
}

// TestRenderNodeIPAccess: IP hosts and requests without a Host are node IP
// access, looked up by exact name only (edgeweir.store): a regex name for
// them comes before every other one, on a server with the default site's
// settings while node IP access is handed to it, else on the generic
// server; an unbound site's IP name follows node IP access, its other
// names unknown hosts.
func TestRenderNodeIPAccess(t *testing.T) {
	tls := func(http2, brotli bool) *configir.TLSOptions {
		return &configir.TLSOptions{MinimumVersion: "1.2", CipherProfile: "modern", HTTP2: http2, Brotli: brotli, BrotliLevel: 4}
	}
	plan := &configir.Plan{
		Listeners:  []configir.Listener{{Port: 80}, {Port: 8080}},
		CacheZones: []configir.CacheZone{{Name: "default", MaxSizeMB: 1024, KeysZoneMB: 16, InactiveSeconds: 3600}},
		Sites: []configir.Site{
			{ID: "p", TLS: tls(false, false), Domains: []configir.Domain{{Name: `[0-9._]+`, Match: configir.MatchRegex, Order: 16}}},
			{ID: "u", TLS: tls(false, false), Ports: []uint32{8080}, Domains: []configir.Domain{{Name: "198.51.100.7"}, {Name: "u.test"}}},
			{ID: "d", TLS: tls(true, true), Domains: []configir.Domain{{Name: "d.test"}}},
		},
		UnknownHosts: &configir.UnknownHosts{UnknownHost: "page", IPAccess: "site", DefaultSiteID: "d"},
	}
	servers := func() []string {
		t.Helper()
		got, err := Render(params(), plan)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, block := range strings.Split(string(got), "    server {")[1:] {
			if !strings.Contains(block, "listen 80;") && !strings.Contains(block, "listen 80 ") {
				continue
			}
			var name string
			for _, line := range strings.Split(block, "\n") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(line), "server_name "); ok {
					name = strings.TrimSuffix(v, ";")
				}
			}
			out = append(out, name+" brotli="+fmt.Sprint(strings.Contains(block, "brotli on;")))
		}
		return out
	}
	ip := `"~^(?:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[.*)$"`
	want := []string{
		`_ "" ` + ip + " 198.51.100.7 brotli=true",
		"generic.edgeweir.invalid u.test brotli=false",
		"d.test brotli=true",
		`"~(?-i)^(?!.{254})(?:[0-9._]+)$" brotli=false`,
	}
	if got := servers(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("servers on 80\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// Node IP access closed, unknown hosts to the default site.
	plan.UnknownHosts.UnknownHost, plan.UnknownHosts.IPAccess = "site", "close"
	want = []string{
		`_ "" ` + ip + " 198.51.100.7 brotli=false",
		"d.test u.test brotli=true",
		`"~(?-i)^(?!.{254})(?:[0-9._]+)$" brotli=false`,
	}
	if got := servers(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("servers on 80\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// No default site: the generic server is the default one.
	plan.UnknownHosts = nil
	want = []string{
		"_ " + ip + " u.test 198.51.100.7 brotli=false",
		"d.test brotli=true",
		`"~(?-i)^(?!.{254})(?:[0-9._]+)$" brotli=false`,
	}
	if got := servers(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("servers on 80\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestRenderHandedServers: names of a site not bound to a TLS port without
// a certificate (or still pending) are unknown hosts there too, not
// skipped (another site's suffix would take them); the generic server
// takes HTTP/2 when the default site's server, where a connection without
// SNI negotiates it, does; an unbound site's patterns keep their place
// among the others (order, then their own site's id).
func TestRenderHandedServers(t *testing.T) {
	tls := &configir.TLSOptions{MinimumVersion: "1.2", CipherProfile: "modern"}
	plan := &configir.Plan{
		Listeners:  []configir.Listener{{Port: 80}, {Port: 443, TLS: true}},
		CacheZones: []configir.CacheZone{{Name: "default", MaxSizeMB: 1024, KeysZoneMB: 16, InactiveSeconds: 3600}},
		Sites: []configir.Site{
			{ID: "a", TLS: tls, Ports: []uint32{80}, Domains: []configir.Domain{{Name: "shop.example.test"}, {Name: "new.example.test", TLSPending: true}}},
			{ID: "b", CertificateID: "c", TLS: tls, Domains: []configir.Domain{{Name: "example.test", Match: configir.MatchSuffix}, {Name: `[a-z]+\.p\.test`, Match: configir.MatchRegex, Order: 5}}},
			{ID: "c", CertificateID: "c", TLS: tls, Ports: []uint32{8080}, Domains: []configir.Domain{{Name: `www\.p\.test`, Match: configir.MatchRegex, Order: 5}}},
			{ID: "d", CertificateID: "c", GRPC: true, TLS: tls, Domains: []configir.Domain{{Name: "d.test"}}},
		},
		UnknownHosts: &configir.UnknownHosts{UnknownHost: "site", IPAccess: "close", DefaultSiteID: "d", DefaultCertificate: true},
	}
	got, err := Render(params(), plan)
	if err != nil {
		t.Fatal(err)
	}
	var tls443 []string
	var generic string
	for _, block := range strings.Split(string(got), "    server {")[1:] {
		if !strings.Contains(block, "listen 443 ") {
			continue
		}
		for _, line := range strings.Split(block, "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "server_name "); ok {
				tls443 = append(tls443, strings.TrimSuffix(v, ";"))
				if strings.HasPrefix(v, "_ ") {
					generic = block
				}
			}
		}
	}
	want := []string{
		`_ "" "~^(?:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|\[.*)$"`,
		"d.test shop.example.test new.example.test",
		`~^[^.].*\.example\.test$`,
		`"~(?-i)^(?!.{254})(?:[a-z]+\.p\.test)$"`,
		`"~(?-i)^(?!.{254})(?:www\.p\.test)$"`,
	}
	if strings.Join(tls443, "\n") != strings.Join(want, "\n") {
		t.Fatalf("443 server names\n%s\nwant\n%s", strings.Join(tls443, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(generic, "http2 on;") {
		t.Errorf("the generic server on 443 lacks the default server's HTTP/2:\n%s", generic)
	}
	// A default site without a certificate takes node IP access over HTTPS
	// (no SNI: the health certificate) on a server with its settings and the
	// listener's HTTP/2, while the generic server stays the default one.
	plan.Sites[3].CertificateID, plan.Sites[3].GRPC = "", false
	plan.Sites[3].TLS = &configir.TLSOptions{MinimumVersion: "1.2", CipherProfile: "modern", Brotli: true, BrotliLevel: 4}
	plan.Listeners[1].HTTP2 = true
	plan.UnknownHosts = &configir.UnknownHosts{UnknownHost: "page", IPAccess: "site", DefaultSiteID: "d"}
	got, err = Render(params(), plan)
	if err != nil {
		t.Fatal(err)
	}
	var ip string
	for _, block := range strings.Split(string(got), "    server {")[1:] {
		if strings.Contains(block, "listen 443 ") && strings.Contains(block, `server_name _ ""`) {
			ip = block
		}
	}
	if !strings.Contains(ip, "brotli on;") || !strings.Contains(ip, "http2 on;") || strings.Contains(ip, "default_server") {
		t.Errorf("node IP access on 443 without the default site's settings:\n%s", ip)
	}
	if !strings.Contains(string(got), "listen 443 default_server ssl;") {
		t.Errorf("the generic server lost default_server on 443")
	}
}
