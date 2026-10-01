package agent_test

import (
	"bytes"
	"compress/gzip"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marvinli001/edgeweir-node/internal/agent"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// sitemapEdge imitates the node's edge listener: it serves the sitemap
// documents by path, answers everything else with 200 and records every
// request as "<host> <uri> <user agent>".
type sitemapEdge struct {
	docs map[string][]byte
	mu   sync.Mutex
	seen []string
}

func (e *sitemapEdge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	e.seen = append(e.seen, r.Host+" "+r.URL.RequestURI()+" "+r.UserAgent())
	e.mu.Unlock()
	switch {
	case r.URL.Path == "/moved.xml":
		http.Redirect(w, r, "/sitemap.xml", http.StatusMovedPermanently)
	case r.URL.Path == "/slow.xml":
		<-r.Context().Done()
	case strings.HasSuffix(r.URL.Path, ".xml") || strings.HasSuffix(r.URL.Path, ".gz") || strings.HasSuffix(r.URL.Path, ".html"):
		doc, ok := e.docs[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(doc)
	default:
		_, _ = w.Write([]byte("page"))
	}
}

// requests returns the recorded requests, sorted, and forgets them.
func (e *sitemapEdge) requests() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := e.seen
	e.seen = nil
	slices.Sort(out)
	return out
}

func urlset(locs ...string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`)
	for _, l := range locs {
		b.WriteString("\n  <url><loc>" + l + "</loc><lastmod>2026-09-30</lastmod></url>")
	}
	b.WriteString("\n</urlset>\n")
	return []byte(b.String())
}

func sitemapIndex(locs ...string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`)
	for _, l := range locs {
		b.WriteString("\n  <sitemap><loc>" + l + "</loc></sitemap>")
	}
	b.WriteString("\n</sitemapindex>\n")
	return []byte(b.String())
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sitemapTask(id, site, url string, maxURLs uint32, variants ...nodev1.DeviceVariant) *nodev1.NodeTask {
	return &nodev1.NodeTask{Id: id, CreatedAt: timestamppb.Now(), Kind: &nodev1.NodeTask_Sitemap{Sitemap: &nodev1.SitemapPrefetchTask{
		SiteId: site, Url: url, MaxUrls: maxURLs, Variants: variants,
	}}}
}

// sitemapConfig serves site-a on site-a.test and *.site-a.test, site-b on
// b.site-a.test, with the edge listener on port.
func sitemapConfig(port uint32) *nodev1.NodeConfig {
	a := demoSite("site-a", "site-a.test")
	a.Domains = append(a.Domains, &nodev1.Domain{Name: "site-a.test", Wildcard: true})
	c := baseConfig(a, demoSite("site-b", "b.site-a.test"))
	c.Listeners[0].Port = port
	return c
}

// TestAgentSitemapPrefetch: the sitemap is fetched through the edge with
// the desktop User-Agent; the URLs on hosts the edge routes to the site
// are kept once each, in document order, and prefetched in every variant.
func TestAgentSitemapPrefetch(t *testing.T) {
	edge := &sitemapEdge{docs: map[string][]byte{"/sitemap.xml": urlset(
		"http://site-a.test/1",
		"http://site-a.test/1#again",
		"http://SITE-A.test/2",
		"http://www.site-a.test/3",
		"http://b.site-a.test/4",        // routed to site-b
		"http://deep.www.site-a.test/5", // two labels below the wildcard
		"http://other.test/6",
		"/relative",
		"ftp://site-a.test/7",
		"  http://site-a.test/8?q=1&amp;r=2\n  ",
	)}}
	e := startEnrolledConfig(t, "sitemap", nil, sitemapConfig(listenEdge(t, edge, nil)))
	if !hasFeature(e.console.LastStatus(), "prefetch-v2") {
		t.Fatalf("prefetch-v2 not announced: %v", e.console.LastStatus().GetInfo().GetSupportedFeatures())
	}
	mobile := nodev1.DeviceVariant_DEVICE_VARIANT_MOBILE
	e.console.AddTask(sitemapTask("s1", "site-a", "http://site-a.test/sitemap.xml", 0,
		mobile, nodev1.DeviceVariant_DEVICE_VARIANT_DESKTOP, nodev1.DeviceVariant_DEVICE_VARIANT_UNSPECIFIED), false)
	res := waitResults(t, e.console, 1)[0]
	if res.GetState() != nodev1.TaskState_TASK_STATE_SUCCEEDED || res.GetSucceeded() != 8 || res.GetFailed() != 0 || res.GetErrorCode() != "" {
		t.Fatalf("result = %v", res)
	}
	var want []string
	for _, u := range []string{"site-a.test /1", "site-a.test /2", "www.site-a.test /3", "site-a.test /8?q=1&r=2"} {
		want = append(want, u+" "+desktopUA, u+" "+mobileUA)
	}
	want = append(want, "site-a.test /sitemap.xml "+desktopUA)
	slices.Sort(want)
	if got := edge.requests(); !slices.Equal(got, want) {
		t.Fatalf("edge saw\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestAgentSitemapIndex: a gzipped sitemapindex is followed one level:
// children on other hosts are not fetched, a child that is an index is not
// followed, a missing child fails the task (sitemap_failed) while the
// URLs of the others are prefetched; max_urls stops the fetching. Sitemap
// tasks run after the purges of their batch.
func TestAgentSitemapIndex(t *testing.T) {
	edge := &sitemapEdge{docs: map[string][]byte{
		"/index.xml.gz": gz(t, sitemapIndex(
			"http://site-a.test/child-1.xml",
			"http://www.site-a.test/child-2.xml.gz",
			"http://other.test/foreign.xml",
			"http://site-a.test/nested.xml",
			"http://site-a.test/missing.xml",
			"http://site-a.test/child-1.xml",
		)),
		"/child-1.xml":    urlset("http://site-a.test/c1a", "http://site-a.test/c1b"),
		"/child-2.xml.gz": gz(t, urlset("http://site-a.test/c2a", "http://site-a.test/c1a")),
		"/nested.xml":     sitemapIndex("http://site-a.test/child-1.xml"),
	}}
	e := startEnrolledConfig(t, "sitemapindex", func(c *agent.Config) { c.TaskPollInterval = time.Hour },
		sitemapConfig(listenEdge(t, edge, nil)))
	e.console.AddTasks(true,
		sitemapTask("s-index", "site-a", "http://site-a.test/index.xml.gz", 0),
		purgeTask("p1", time.Now(), urlTarget("site-a", "/x")))
	res := waitResults(t, e.console, 2)
	if res[0].GetTaskId() != "p1" {
		t.Fatalf("%s ran first, want the purge", res[0].GetTaskId())
	}
	want := map[string]string{"url": "http://site-a.test/missing.xml", "reason": "status", "status": "404"}
	if r := res[1]; r.GetState() != nodev1.TaskState_TASK_STATE_FAILED || r.GetSucceeded() != 3 || r.GetFailed() != 0 ||
		r.GetErrorCode() != "sitemap_failed" || !maps.Equal(r.GetErrorParams(), want) ||
		!strings.HasPrefix(r.GetMessage(), "sitemap http://site-a.test/missing.xml: HTTP 404") {
		t.Fatalf("result = %v", r)
	}
	fetched := []string{
		"site-a.test /index.xml.gz", "site-a.test /child-1.xml", "www.site-a.test /child-2.xml.gz",
		"site-a.test /nested.xml", "site-a.test /missing.xml",
		"site-a.test /c1a", "site-a.test /c1b", "site-a.test /c2a",
	}
	for i := range fetched {
		fetched[i] += " " + desktopUA
	}
	slices.Sort(fetched)
	if got := edge.requests(); !slices.Equal(got, fetched) {
		t.Fatalf("edge saw\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(fetched, "\n"))
	}

	// max_urls 2: the first child is enough.
	e.console.AddTask(sitemapTask("s-capped", "site-a", "http://site-a.test/index.xml.gz", 2), false)
	if r := waitResults(t, e.console, 3)[2]; r.GetState() != nodev1.TaskState_TASK_STATE_SUCCEEDED || r.GetSucceeded() != 2 {
		t.Fatalf("capped result = %v", r)
	}
	fetched = []string{"site-a.test /c1a", "site-a.test /c1b", "site-a.test /child-1.xml", "site-a.test /index.xml.gz"}
	for i := range fetched {
		fetched[i] += " " + desktopUA
	}
	if got := edge.requests(); !slices.Equal(got, fetched) {
		t.Fatalf("capped: edge saw\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(fetched, "\n"))
	}
}

// TestAgentSitemapFailures: sitemap_failed with its reason and
// sitemap_empty; nothing is prefetched.
func TestAgentSitemapFailures(t *testing.T) {
	edge := &sitemapEdge{docs: map[string][]byte{
		"/sitemap.xml": urlset("http://site-a.test/1"),
		"/page.html":   []byte("<!DOCTYPE html><html><body>not a sitemap</body></html>"),
		"/cut.xml":     []byte(`<urlset><url><loc>http://site-a.test/1</loc></url>`),
		"/empty.xml":   urlset("http://other.test/1", "http://b.site-a.test/2"),
	}}
	e := startEnrolledConfig(t, "sitemapfail", nil, sitemapConfig(listenEdge(t, edge, nil)))
	for i, c := range []struct {
		site, url, code string
		params          map[string]string
	}{
		{"site-a", "http://site-a.test/moved.xml", "sitemap_failed", map[string]string{"reason": "status", "status": "301"}},
		{"site-a", "http://site-a.test/missing.xml", "sitemap_failed", map[string]string{"reason": "status", "status": "404"}},
		{"site-a", "http://site-a.test/page.html", "sitemap_failed", map[string]string{"reason": "invalid"}},
		{"site-a", "http://site-a.test/cut.xml", "sitemap_failed", map[string]string{"reason": "invalid"}},
		{"site-a", "https://site-a.test/sitemap.xml", "sitemap_failed", map[string]string{"reason": "https_unsupported"}},
		{"site-a", "http://other.test/sitemap.xml", "sitemap_failed", map[string]string{"reason": "other"}},
		{"site-a", "http://b.site-a.test/sitemap.xml", "sitemap_failed", map[string]string{"reason": "other"}},
		{"site-x", "http://site-a.test/sitemap.xml", "sitemap_failed", map[string]string{"reason": "other"}},
		{"site-a", "http://site-a.test/empty.xml", "sitemap_empty", map[string]string{}},
	} {
		e.console.AddTask(sitemapTask("f"+string(rune('a'+i)), c.site, c.url, 0), false)
		r := waitResults(t, e.console, i+1)[i]
		c.params["url"] = c.url
		if r.GetState() != nodev1.TaskState_TASK_STATE_FAILED || r.GetErrorCode() != c.code || !maps.Equal(r.GetErrorParams(), c.params) ||
			r.GetSucceeded() != 0 || r.GetFailed() != 0 {
			t.Errorf("%s (site %s): %v, want %s %v", c.url, c.site, r, c.code, c.params)
		}
	}
	for _, req := range edge.requests() {
		if !strings.Contains(req, ".xml") && !strings.Contains(req, ".html") {
			t.Errorf("prefetched %q after a failed sitemap", req)
		}
		if strings.Contains(req, "other.test") || strings.HasPrefix(req, "b.site-a.test") {
			t.Errorf("fetched a sitemap of another site: %q", req)
		}
	}
}

// TestAgentSitemapConnectFailedAndTimeout: nothing listens on the edge
// port (connect_failed); a sitemap that does not arrive within the batch's
// time budget (timeout).
func TestAgentSitemapConnectFailedAndTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := uint32(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	e := startEnrolledConfig(t, "sitemaprefused", nil, sitemapConfig(closed))
	e.console.AddTask(sitemapTask("s-refused", "site-a", "http://site-a.test/sitemap.xml", 0), false)
	if r := waitResults(t, e.console, 1)[0]; r.GetErrorCode() != "sitemap_failed" || r.GetErrorParams()["reason"] != "connect_failed" {
		t.Fatalf("refused: %v", r)
	}

	edge := &sitemapEdge{}
	e = startEnrolledConfig(t, "sitemapslow", func(c *agent.Config) { c.PrefetchBudget = 400 * time.Millisecond },
		sitemapConfig(listenEdge(t, edge, nil)))
	start := time.Now()
	e.console.AddTask(sitemapTask("s-slow", "site-a", "http://site-a.test/slow.xml", 0), false)
	r := waitResults(t, e.console, 1)[0]
	if r.GetErrorCode() != "sitemap_failed" || r.GetErrorParams()["reason"] != "timeout" || time.Since(start) > 5*time.Second {
		t.Fatalf("slow: %v after %v", r, time.Since(start))
	}
}
