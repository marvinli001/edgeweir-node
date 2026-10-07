package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

// The proto v0.24.0 sites (site-content-v1):
//
//	content.test   origin console:8082; /account/ cached with its Set-Cookie
//	                  lines, everything else cached 60 s; the cache key drops
//	                  utm_* parameters; charset gbk (force, upper case); body
//	                  limit 1024 bytes, 0 under /upload/ (config rule); gzip
//	                  level 9 above 100 bytes, nothing compressed above 2000;
//	                  PURGE method with the key purgeKey; error pages: 4xx
//	                  template, 404 redirect, 5xx template sent as 200,
//	                  origin errors intercepted
//	nox.test       like demo.test, without X-Cache
//	maint.test     maintenance: page with {{status}}, Retry-After 30, /open
//	                  served as usual
//	retry.test     origins console:8082 and console:8083 (round robin, 2
//	                  tries); /fail8082 answers 502 on 8082 only
//	noretry.test   like retry.test without retries after 502-504
const purgeKey = "e2e-purge-key-0123456789"

// purgeKeyID is the credential id of content.test's PURGE key.
const purgeKeyID = "purge-key-content"

func contentSite() *nodev1.Site {
	s := site("site-content", "content.test", "console", 8082)
	s.CacheRules = append([]*nodev1.CacheRule{{
		Id: "account", Priority: 10,
		Match:              &nodev1.CacheRuleMatch{PathPrefixes: []string{"/account/"}},
		Action:             nodev1.CacheAction_CACHE_ACTION_CACHE,
		EdgeTtlSeconds:     60,
		OriginCacheControl: nodev1.OriginCacheControl_ORIGIN_CACHE_CONTROL_OVERRIDE,
		CacheSetCookie:     true,
	}}, s.CacheRules...)
	s.CacheKey = &nodev1.CacheKeyPolicy{Query: nodev1.CacheKeyQuery_CACHE_KEY_QUERY_EXCLUDE, QueryParams: []string{"utm_*"}}
	s.Charset = &nodev1.Charset{Name: "gbk", Force: true, Uppercase: true}
	s.RequestBodyLimit = proto.Uint64(1024)
	s.Rules = []*nodev1.EdgeRule{{Id: "uploads", Phase: "config", Expression: pathStarts("/upload/"),
		Action: &nodev1.RuleAction{Kind: "config", RequestBodyLimit: proto.Uint64(0)}}}
	s.Tls = &nodev1.TlsOptions{MinimumVersion: "1.2", CipherProfile: "modern", Gzip: true, GzipMinLength: 100,
		GzipTypes: []string{"text/plain"}, GzipLevel: 9, CompressMaxLength: 2000}
	s.Purge = &nodev1.PurgeMethod{CredentialId: purgeKeyID, CredentialVersion: 1}
	s.ErrorPages = &nodev1.SiteErrorPages{InterceptOriginErrors: true, Pages: []*nodev1.ErrorPage{
		{Status: 4, Template: "<p>c4 {{status}}</p>"},
		{Status: 5, Template: "<p>c5 {{status}}</p>", ResponseStatus: 200},
		{Status: 404, RedirectUrl: "/nf?s={{status}}&id={{request_id}}"},
	}}
	return s
}

func noXCacheSite(origin string) *nodev1.Site {
	s := site("site-nox", "nox.test", origin, 80)
	s.HideXCache = true
	return s
}

func maintenanceSite(origin string) *nodev1.Site {
	s := site("site-maint", "maint.test", origin, 80)
	s.Maintenance = &nodev1.Maintenance{Template: "<p>maint {{status}}</p>", RetryAfterSeconds: 30,
		AllowedPathPrefixes: []string{"/open"}}
	return s
}

func retrySite(id, domain string, statusRetry bool) *nodev1.Site {
	s := site(id, domain, "console", 8082)
	s.OriginPool.Policy = nodev1.LoadBalancePolicy_LOAD_BALANCE_POLICY_ROUND_ROBIN
	s.OriginPool.Origins = append(s.OriginPool.Origins, &nodev1.Origin{
		Id: "o2", Address: "console", Port: 8083, Scheme: nodev1.OriginScheme_ORIGIN_SCHEME_HTTP, Weight: 1,
	})
	s.OriginPool.Tries = 2
	s.OriginPool.StatusRetryDisabled = !statusRetry
	s.CacheRules = nil
	return s
}

func contentSites(origin string) []*nodev1.Site {
	return []*nodev1.Site{
		contentSite(),
		noXCacheSite(origin),
		maintenanceSite(origin),
		retrySite("site-retry", "retry.test", true),
		retrySite("site-noretry", "noretry.test", false),
	}
}

// cookies counts the Set-Cookie responses of /account/ by port.
var cookies atomic.Int32

// serveContent answers the test origin's proto v0.24.0 paths; false for
// any other path.
func serveContent(w http.ResponseWriter, r *http.Request, port string) bool {
	h := w.Header()
	switch {
	case strings.HasPrefix(r.URL.Path, "/account/"):
		n := cookies.Add(1)
		h.Add("Set-Cookie", fmt.Sprintf("sid=visitor-%d; Path=/; HttpOnly", n))
		h.Add("Set-Cookie", "pref=a,b; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/")
		fmt.Fprintf(w, "account %d\n", n)
	case strings.HasPrefix(r.URL.Path, "/text/"):
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/text/"))
		body := strings.Repeat("a", min(max(n, 0), 1<<20))
		// A known length: the edge compresses responses of unknown length.
		h.Set("Content-Type", "text/plain")
		h.Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write([]byte(body))
	case r.URL.Path == "/fail8082":
		if port == "8082" {
			w.WriteHeader(http.StatusBadGateway)
		}
		fmt.Fprintf(w, "fail8082 from %s\n", port)
	case (r.Method == http.MethodPost || r.Method == http.MethodPut) &&
		(strings.HasPrefix(r.URL.Path, "/upload/") || r.URL.Path == "/form"):
		n := 0
		buf := make([]byte, 32<<10)
		for {
			k, err := r.Body.Read(buf)
			n += k
			if err != nil {
				break
			}
		}
		fmt.Fprintf(w, "received %d bytes\n", n)
	default:
		return false
	}
	return true
}

// contentHelpers serves the test script's proto v0.24.0 helpers:
//
//	GET  /purges       the PURGE requests the node submitted (JSON)
//	GET  /cache-usage  the cache usage of the latest heartbeat (JSON)
//	POST /cache-size   publishes the base sites with this node's cache
//	                   zone size (?mb=, 0: the zone's own)
func contentHelpers(mux *http.ServeMux, c *fakeconsole.Console, publish func(*nodev1.NodeConfig) uint64, base func() *nodev1.NodeConfig) {
	mux.HandleFunc("GET /purges", func(w http.ResponseWriter, _ *http.Request) {
		var out []map[string]string
		for _, p := range c.Purges() {
			out = append(out, map[string]string{"site_id": p.GetSiteId(), "url": p.GetUrl()})
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /cache-usage", func(w http.ResponseWriter, _ *http.Request) {
		var out []map[string]any
		for _, u := range c.LastStatus().GetCacheUsage() {
			out = append(out, map[string]any{"name": u.GetName(), "used": u.GetUsedBytes(), "max": u.GetMaxBytes()})
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /cache-size", func(w http.ResponseWriter, r *http.Request) {
		mb, _ := strconv.ParseUint(r.URL.Query().Get("mb"), 10, 64)
		cfg := base()
		if mb > 0 {
			cfg.CacheZones[0].NodeSizes = []*nodev1.CacheZoneNodeSize{{NodeId: "node-e2e", MaxSizeMb: mb, KeysZoneMb: 16}}
			cfg.RequiredFeatures = append(cfg.RequiredFeatures, "cache-zone-v1")
		}
		fmt.Fprint(w, publish(cfg))
	})
}
