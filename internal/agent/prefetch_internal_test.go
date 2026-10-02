package agent

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/pki/pkitest"
	"github.com/marvinli001/edgeweir-node/internal/render"
)

// TestPrefetchUserAgentsMatchTheCacheKey keeps the variants' User-Agents in
// sync with edgeweir.cachekey: the data plane caches a mobile object for a
// request whose User-Agent matches MOBILE_RE, a desktop one otherwise.
func TestPrefetchUserAgentsMatchTheCacheKey(t *testing.T) {
	lua, err := os.ReadFile("../../lua/edgeweir/cachekey.lua")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^local MOBILE_RE = \[\[(.*)\]\]$`).FindSubmatch(lua)
	if m == nil {
		t.Fatal("MOBILE_RE not found in lua/edgeweir/cachekey.lua")
	}
	// The Lua pattern is matched with ngx.re.find(..., "jo"): PCRE,
	// case-sensitive; this alternation means the same in RE2.
	mobileRE := regexp.MustCompile(string(m[1]))
	for v, wantMobile := range map[nodev1.DeviceVariant]bool{
		nodev1.DeviceVariant_DEVICE_VARIANT_UNSPECIFIED: false,
		nodev1.DeviceVariant_DEVICE_VARIANT_DESKTOP:     false,
		nodev1.DeviceVariant_DEVICE_VARIANT_MOBILE:      true,
	} {
		ua, ok := prefetchUserAgent(v)
		if !ok || !strings.Contains(ua, "edgeweir-node-prefetch/") {
			t.Fatalf("%v: User-Agent %q does not name the agent", v, ua)
		}
		if got := mobileRE.MatchString(ua); got != wantMobile {
			t.Errorf("%v: User-Agent %q mobile = %v, want %v (MOBILE_RE %s)", v, ua, got, wantMobile, m[1])
		}
	}
	if _, ok := prefetchUserAgent(nodev1.DeviceVariant(3)); ok {
		t.Error("an unknown variant has a User-Agent")
	}
}

// serveUnix serves h on a new unix socket (with TLS when tlsConfig is set)
// and returns its path.
func serveUnix(t *testing.T, h http.Handler, tlsConfig *tls.Config) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "edge")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "edge.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = ln
	if tlsConfig != nil {
		srv.TLS = tlsConfig
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	return path
}

// TestPrefetchSchemes: an http URL of a site with a certificate is
// prefetched over https as well (the cache key holds the scheme); the
// edge's own redirect to the https form (HTTPS only) is followed instead,
// any other redirect of the edge fails, an origin's redirect is cached as
// it is.
func TestPrefetchSchemes(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	record := func(r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		seen = append(seen, scheme+"://"+r.Host+r.URL.RequestURI())
	}
	plain := serveUnix(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		switch r.URL.Path {
		case "/force":
			w.Header().Set(edgeResponseHeader, "1")
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
		case "/elsewhere":
			w.Header().Set(edgeResponseHeader, "1")
			http.Redirect(w, r, "https://"+r.Host+"/other", http.StatusFound)
		case "/origin-redirect":
			http.Redirect(w, r, "/new", http.StatusMovedPermanently)
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}), nil)
	ca, err := pkitest.NewCA("prefetch test CA")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueServer([]string{"a.test", "b.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	secure := serveUnix(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		_, _ = w.Write([]byte("ok"))
	}), &tls.Config{Certificates: []tls.Certificate{cert}})
	sites := []configir.Site{{ID: "site-a", TLS: &configir.TLSOptions{}, CertificateID: "cert-a"}, {ID: "site-b"}}
	run := func(withTLS bool, site, u string) (prefetchOutcome, []string) {
		listeners := []configir.Listener{{Port: 80}}
		if withTLS {
			listeners = append(listeners, configir.Listener{Port: 443, TLS: true})
		}
		a := &Agent{cfg: Config{Render: render.Params{EdgeSocket: plain, EdgeTLSSocket: secure}, PrefetchConcurrency: 1, PrefetchTimeout: time.Minute},
			plan: &configir.Plan{Listeners: listeners, Sites: sites}}
		c := a.newPrefetchClient()
		defer c.CloseIdleConnections()
		mu.Lock()
		seen = nil
		mu.Unlock()
		o := prefetchOne(context.Background(), c, prefetchItem{site: site, url: u})
		mu.Lock()
		defer mu.Unlock()
		return o, slices.Clone(seen)
	}
	for _, c := range []struct {
		tls       bool
		site, url string
		err       string
		status    int
		seen      []string
	}{
		{true, "site-a", "http://a.test/p?x=1", "", 0, []string{"http://a.test/p?x=1", "https://a.test/p?x=1"}},
		{true, "site-b", "http://b.test/p", "", 0, []string{"http://b.test/p"}},
		{false, "site-a", "http://a.test/p", "", 0, []string{"http://a.test/p"}},
		{true, "site-a", "https://a.test/p", "", 0, []string{"https://a.test/p"}},
		{true, "site-a", "http://a.test/force", "", 0, []string{"http://a.test/force", "https://a.test/force"}},
		{true, "site-b", "http://b.test/force", "", 0, []string{"http://b.test/force", "https://b.test/force"}},
		{false, "site-a", "http://a.test/force", "HTTPS prefetch needs an HTTPS listener on the node", 0, []string{"http://a.test/force"}},
		{true, "site-a", "http://a.test/elsewhere", "HTTP 302: the edge redirects to https://a.test/other", 302, []string{"http://a.test/elsewhere"}},
		{true, "site-a", "http://a.test/origin-redirect", "", 0, []string{"http://a.test/origin-redirect", "https://a.test/origin-redirect"}},
	} {
		o, got := run(c.tls, c.site, c.url)
		if !o.done || o.err != c.err || o.status != c.status || !slices.Equal(got, c.seen) {
			t.Errorf("%s (TLS listener %v): %+v, requests %q; want err %q, requests %q", c.url, c.tls, o, got, c.err, c.seen)
		}
	}
}
