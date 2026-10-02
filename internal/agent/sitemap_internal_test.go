package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/render"
)

type sitemapEntry struct {
	index bool
	loc   string
}

func parseAll(doc string, stopAfter int) ([]sitemapEntry, error) {
	var got []sitemapEntry
	err := parseSitemap(strings.NewReader(doc), func(index bool, loc string) bool {
		got = append(got, sitemapEntry{index, loc})
		return stopAfter == 0 || len(got) < stopAfter
	})
	return got, err
}

// TestParseSitemap: url/loc of a urlset and sitemap/loc of a
// sitemapindex in document order, whatever the namespace prefix, with
// entities, CDATA and surrounding white space; other elements are not
// entries.
func TestParseSitemap(t *testing.T) {
	urlset := `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
  <url>
    <loc>
      http://a.test/1?x=1&amp;y=2
    </loc>
    <image:image><image:loc>http://a.test/image.png</image:loc></image:image>
  </url>
  <url><lastmod>2026-09-30</lastmod><loc><![CDATA[http://a.test/2]]></loc></url>
  <other><loc>http://a.test/not-an-entry</loc></other>
  <url><loc></loc></url>
  <url><loc>http://a.test/` + strings.Repeat("x", maxSitemapLoc) + `</loc></url>
  <url><loc>http://a.test/3</loc></url>
</urlset>
trailing text after the root element is ignored <x>`
	got, err := parseAll(urlset, 0)
	want := []sitemapEntry{{false, "http://a.test/1?x=1&y=2"}, {false, "http://a.test/2"}, {false, "http://a.test/3"}}
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("urlset = %v, %v\nwant %v", got, err, want)
	}
	if got, err = parseAll(urlset, 1); err != nil || !slices.Equal(got, want[:1]) {
		t.Fatalf("stopped after one entry: %v, %v", got, err)
	}

	index := `<sm:sitemapindex xmlns:sm="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sm:sitemap><sm:loc>http://a.test/s1.xml</sm:loc></sm:sitemap>
  <sm:sitemap><sm:loc>http://a.test/s2.xml.gz</sm:loc><sm:lastmod>2026-09-30</sm:lastmod></sm:sitemap>
  <sm:url><sm:loc>http://a.test/not-in-an-index</sm:loc></sm:url>
</sm:sitemapindex>`
	got, err = parseAll(index, 0)
	if want := []sitemapEntry{{true, "http://a.test/s1.xml"}, {true, "http://a.test/s2.xml.gz"}}; err != nil || !slices.Equal(got, want) {
		t.Fatalf("index = %v, %v\nwant %v", got, err, want)
	}
	if got, err = parseAll(`<urlset/>`, 0); err != nil || len(got) != 0 {
		t.Fatalf("empty urlset = %v, %v", got, err)
	}

	for name, doc := range map[string]string{
		"empty":           "",
		"white space":     "  \n",
		"html":            "<!DOCTYPE html><html><body>not found</body></html>",
		"truncated":       "<urlset><url><loc>http://a.test/1</loc>",
		"syntax":          "<urlset><url><loc>http://a.test/1</loc></uri></urlset>",
		"latin-1":         `<?xml version="1.0" encoding="ISO-8859-1"?><urlset/>`,
		"undefined":       `<urlset><url><loc>http://a.test/&nbsp;</loc></url></urlset>`,
		"text":            "http://a.test/1\nhttp://a.test/2\n",
		"binary garbage":  "\x1f\x8b\x08\x00",
		"unclosed at EOF": "<urlset>",
	} {
		if _, err := parseAll(doc, 0); err == nil {
			t.Errorf("%s: parsed without an error", name)
		}
	}
}

// TestSiteHostsRouteLikeTheEdge: a sitemap URL is kept when the edge routes
// its host to the site: an exact domain of any site first, then a wildcard
// domain one label up (never the apex, never two labels).
func TestSiteHostsRouteLikeTheEdge(t *testing.T) {
	a := &Agent{plan: &configir.Plan{Sites: []configir.Site{
		{ID: "a", Domains: []configir.Domain{{Name: "a.test"}, {Name: "a.test", Wildcard: true}}},
		{ID: "b", Domains: []configir.Domain{{Name: "b.a.test"}}},
	}}}
	hosts, ok := a.siteHosts("a")
	if !ok {
		t.Fatal("site a not served")
	}
	for loc, want := range map[string]string{
		"http://a.test/x":                "http://a.test/x",
		"https://A.Test:8443/x?y=1#frag": "https://a.test:8443/x?y=1",
		"http://www.a.test/p%20q":        "http://www.a.test/p%20q",
		"http://b.a.test/x":              "", // site b's exact domain wins
		"http://deep.www.a.test/x":       "",
		"http://other.test/x":            "",
		"/relative":                      "",
		"ftp://a.test/x":                 "",
		"http://user:secret@a.test/x":    "",
	} {
		got, ok := hosts.url(loc)
		if ok != (want != "") || got != want {
			t.Errorf("%s: %q %v, want %q", loc, got, ok, want)
		}
	}
	if _, ok := hosts.url("http://a.test/" + strings.Repeat("x", maxSitemapLoc)); ok {
		t.Error("a URL over the sitemap protocol's limit was kept")
	}
	if _, ok := a.siteHosts("missing"); ok {
		t.Error("a site the plan lacks is served")
	}
	if _, ok := (&Agent{}).siteHosts("a"); ok {
		t.Error("served without a plan")
	}
}

func TestSitemapLimitAndVariants(t *testing.T) {
	for in, want := range map[uint32]int{0: 1000, 1: 1, 10000: 10000, 10001: 10000} {
		if got := sitemapLimit(in); got != want {
			t.Errorf("sitemapLimit(%d) = %d, want %d", in, got, want)
		}
	}
	d, m := nodev1.DeviceVariant_DEVICE_VARIANT_DESKTOP, nodev1.DeviceVariant_DEVICE_VARIANT_MOBILE
	for _, c := range []struct{ in, want []nodev1.DeviceVariant }{
		{nil, []nodev1.DeviceVariant{d}},
		{[]nodev1.DeviceVariant{nodev1.DeviceVariant_DEVICE_VARIANT_UNSPECIFIED, d}, []nodev1.DeviceVariant{d}},
		{[]nodev1.DeviceVariant{m, d, m}, []nodev1.DeviceVariant{m, d}},
	} {
		if got := sitemapVariants(c.in); !slices.Equal(got, c.want) {
			t.Errorf("sitemapVariants(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func gzipped(t testing.TB, b []byte) []byte {
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

// TestFetchSitemapLimits: a document gets the per-document timeout and at
// most the byte limit, packed and unpacked; gzip is recognized by its
// magic bytes; failures carry their reasons.
func TestFetchSitemapLimits(t *testing.T) {
	small := `<urlset><url><loc>http://a.test/1</loc></url></urlset>`
	exact := small[:len(small)-len("</urlset>")] + strings.Repeat(" ", 1024-len(small)) + "</urlset>"
	big := "<urlset>" + strings.Repeat(" ", 1100) + "</urlset>"
	var emptyMembers []byte
	for range 80 {
		emptyMembers = append(emptyMembers, gzipped(t, nil)...) // ~20 bytes each, unpacking to nothing
	}
	mux := http.NewServeMux()
	serve := func(path string, body []byte) {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	}
	serve("/small.xml", []byte(small))
	serve("/exact.xml", []byte(exact))
	serve("/small.xml.gz", gzipped(t, []byte(small)))
	serve("/big.xml", []byte(big))
	serve("/big.xml.gz", gzipped(t, []byte(big)))
	serve("/members.gz", emptyMembers)
	serve("/corrupt.gz", append([]byte{0x1f, 0x8b, 0x08, 0x00}, bytes.Repeat([]byte{0xff}, 64)...))
	mux.HandleFunc("/moved.xml", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/small.xml", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/slow-headers.xml", func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	mux.HandleFunc("/slow-body.xml", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<urlset>"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	})
	mux.HandleFunc("/cut.xml", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write([]byte("<urlset>"))
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.Close()
	})
	a := &Agent{cfg: Config{Render: render.Params{EdgeSocket: serveUnix(t, mux, nil)}, PrefetchConcurrency: 1, PrefetchTimeout: time.Minute},
		plan: &configir.Plan{Listeners: []configir.Listener{{Port: 80}}}}
	c := a.newPrefetchClient()
	defer c.CloseIdleConnections()
	lim := sitemapLimits{timeout: 300 * time.Millisecond, bytes: 1024}

	fetch := func(path string) ([]string, *sitemapError) {
		var locs []string
		err := fetchSitemap(context.Background(), c, "http://a.test"+path, lim, func(_ bool, loc string) bool {
			locs = append(locs, loc)
			return true
		})
		return locs, err
	}
	for _, path := range []string{"/small.xml", "/exact.xml", "/small.xml.gz"} {
		if locs, err := fetch(path); err != nil || !slices.Equal(locs, []string{"http://a.test/1"}) {
			t.Errorf("%s: %v %+v", path, locs, err)
		}
	}
	for path, reason := range map[string]string{
		"/big.xml":          "too_large",
		"/big.xml.gz":       "too_large",
		"/members.gz":       "too_large",
		"/corrupt.gz":       "invalid",
		"/moved.xml":        "status",
		"/missing.xml":      "status",
		"/slow-headers.xml": "timeout",
		"/slow-body.xml":    "timeout",
		"/cut.xml":          "other",
	} {
		_, err := fetch(path)
		if err == nil || err.reason != reason || err.url != "http://a.test"+path {
			t.Errorf("%s: %+v, want reason %s", path, err, reason)
			continue
		}
		wantStatus := map[string]string{"/moved.xml": "301", "/missing.xml": "404"}[path]
		if got := err.params()["status"]; got != wantStatus {
			t.Errorf("%s: status param %q, want %q", path, got, wantStatus)
		}
	}
	if e := documentError("u", lim, errTooLarge); e.reason != "too_large" || e.err != "larger than 1024 bytes unpacked" {
		t.Fatalf("too large: %+v", e)
	}
	if e := documentError("u", documentLimits, errTooLarge); e.err != "larger than 50 MiB unpacked" {
		t.Fatalf("too large message: %q", e.err)
	}
	if e := documentError("u", lim, &bodyError{context.DeadlineExceeded}); e.reason != "timeout" {
		t.Fatalf("body timeout: %+v", e)
	}
	if e := documentError("u", lim, errors.New("xml: syntax error")); e.reason != "invalid" {
		t.Fatalf("syntax error: %+v", e)
	}
}

// TestCappedReader: exactly the limit is fine, one byte more is too large.
func TestCappedReader(t *testing.T) {
	for n, wantErr := range map[int]error{4: nil, 5: nil, 6: errTooLarge} {
		got, err := io.ReadAll(&cappedReader{r: strings.NewReader(strings.Repeat("x", n)), left: 5})
		if !errors.Is(err, wantErr) || (wantErr == nil && len(got) != n) {
			t.Errorf("%d bytes: %d read, err %v, want %v", n, len(got), err, wantErr)
		}
	}
}
