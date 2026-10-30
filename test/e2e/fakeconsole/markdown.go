package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

// The Markdown for Agents sites (markdown-v1):
//
//	md.test       origin console:8082, everything cached 60 s; converts
//	                every path but /md/private/
//	mdlive.test   the same origin, nothing cached; converts /md/ only
//
// The test origin's paths: /md/page (an HTML page with chrome, a table,
// JSON-LD and Cache-Tag "mdpage"), /md/gz (the page gzip-encoded whatever
// the request asks), /md/private/page (the page), /md/data.json (JSON),
// /md/own (Markdown the origin negotiates itself for text/markdown);
// /md/count tells how often the origin served /md/page.
func markdownSites() []*nodev1.Site {
	md := site("site-md", "md.test", "console", 8082)
	md.Markdown = &nodev1.Markdown{ExcludePrefixes: []string{"/md/private/"}}
	live := site("site-mdlive", "mdlive.test", "console", 8082)
	live.CacheRules = nil
	live.Markdown = &nodev1.Markdown{IncludePrefixes: []string{"/md/"}}
	return []*nodev1.Site{md, live}
}

const markdownPage = `<!doctype html>
<html><head><meta charset="utf-8"><title>E2E page</title>
<meta name="description" content="Markdown for Agents end to end">
<script>var tracking = 1;</script>
<script type="application/ld+json">{"@type": "WebPage", "name": "E2E"}</script>
</head><body>
<header><nav><a href="/">Home</a></nav></header>
<main><h1>Converted page</h1>
<p>Read the <a href="/md/next">next page</a>.</p>
<table><tr><th>Key</th><th>Value</th></tr><tr><td>a</td><td>1</td></tr></table>
</main>
<footer>Footer text</footer>
</body></html>
`

// markdownServed counts the origin's answers for /md/page.
var markdownServed atomic.Int32

// serveMarkdown answers the test origin's /md/ paths; false for any other.
func serveMarkdown(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/md/") {
		return false
	}
	h := w.Header()
	html := func() {
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("ETag", `"md-page"`)
		h.Set("Cache-Tag", "mdpage")
		fmt.Fprint(w, markdownPage)
	}
	switch r.URL.Path {
	case "/md/page":
		markdownServed.Add(1)
		html()
	case "/md/private/page":
		html()
	case "/md/gz":
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		fmt.Fprint(zw, markdownPage)
		zw.Close()
		h.Set("Content-Type", "text/html")
		h.Set("Content-Encoding", "gzip")
		w.Write(b.Bytes())
	case "/md/data.json":
		h.Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"a":1}`)
	case "/md/own":
		if strings.Contains(r.Header.Get("Accept"), "text/markdown") {
			h.Set("Content-Type", "text/markdown")
			fmt.Fprint(w, "# Origin's own Markdown\n")
			return true
		}
		html()
	case "/md/count":
		h.Set("Cache-Control", "no-store")
		fmt.Fprintf(w, "%d\n", markdownServed.Load())
	default:
		http.NotFound(w, r)
	}
	return true
}

// markdownHelpers registers GET /md/responses: the converted responses
// site-md reported in its statistics.
func markdownHelpers(mux *http.ServeMux, c *fakeconsole.Console) {
	mux.HandleFunc("GET /md/responses", func(w http.ResponseWriter, _ *http.Request) {
		var n uint64
		for _, m := range c.Stats() {
			if m.GetSiteId() == "site-md" {
				n += m.GetMarkdownResponses()
			}
		}
		fmt.Fprintf(w, "%d\n", n)
	})
}
