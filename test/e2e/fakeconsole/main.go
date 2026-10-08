// Command fakeconsole serves the fake NodeService used by the container
// smoke test (test/e2e). It is not part of any release artifact.
//
// It publishes demo.test -> whoami:80 (cache everything for 60s) and sites
// that exercise the origin address policy:
//
//	loop.test       -> node:80 (the node itself: CDN-Loop answers 508)
//	forbidden.test  -> 127.0.0.1:80 (special-purpose literal: 502)
//	hidden.test     -> hidden:80 (DNS answer on a network outside the
//	                   allow list: 502)
//	tls-ok.test     -> https://console:8444, SNI origin.test (200)
//	tls-bad.test    -> https://console:8444, SNI wrong.test (502: the
//	                   certificate is only valid for origin.test)
//	ua.test, js.test, pow.test, captcha.test  Under Attack with cookie302,
//	                   js, pow and captcha (proofs of work of 8 bits),
//	                   passes of 5 minutes
//	cc.test         CC: 2 requests per second per address, 20 per second
//	                   for the site, 2 seconds to escalate, up to cookie302
//	compress.test   gzip, Brotli and Zstandard for text/plain (from 1 byte)
//	crs-detect.test OWASP CRS, detect only (every request logged)
//	crs-block.test  OWASP CRS, blocking, rule 942100 excluded (every
//	                   request logged)
//	tags.test       origin console:8082 (Cache-Tag from the query, see
//	                   serveTestOrigin)
//	keep.test       like tags.test, keeps Cache-Tag for clients
//	slice.test      like tags.test, Range slices
//	swr.test        like tags.test, cached 1 s, stale-while-revalidate 60 s
//	sie.test        like tags.test, cached 1 s, stale-if-error 60 s
//	pages.test      error pages for 403 and 503 that intercept origin errors
//	                   (every request logged)
//	dead.test       origin console:9 (nothing listens: 502)
//	aff.test        origins console:8082 and console:8083 with session
//	                   affinity (120 s), nothing cached
//	smap.test       origin console:8082, cache key separates devices (for
//	                   sitemap prefetches of both variants)
//	active.test     origins console:8082 and console:8083 with an active
//	                   health check of /health every 5 s (one result
//	                   changes the state), nothing cached
//	rules.test      rules-v2: origin console:8082, group "api" whoami:80;
//	                   a dynamic redirect with query edits (/old/), a
//	                   rewrite to the api group with its own Host
//	                   (/api/), a port override (/port/), config rules
//	                   (/slow read timeout 1 s, /sampled logged, /ws
//	                   without WebSocket, /guarded Under Attack), bulk
//	                   redirects and a cache rule condition with a browser
//	                   TTL (/img/); compress.test has compression rules
//	                   (/gz-only gzip, /no-compress none, /no-gzip config
//	                   gzip=false)
//	v3.test         rules-v3: origin whoami:80; computed request headers
//	                   (x-req = http.request.id, x-info = version, scheme,
//	                   port and User-Agent; x-bad from ?bad=, skipped when
//	                   invalid), two Link lines (append), x-cache-status,
//	                   x-ua-match for User-Agent *CURL*, a block for the
//	                   Cookie role=admin with a 403 page of {{time}} and
//	                   {{path}}, a 303 to /signin with a computed next=
//	                   and a redirect to ?to= (a value expression target)
//
// The sites of HTTP/2 to origins and gRPC, and their origins, are in h2.go.
//
// Every revision also carries the layer-4 applications of l4.go (their
// origins run in this container too).
//
// The configuration names the offline hosts of disabled sites (old.test,
// *.gone.test), answered with the built-in page unless POST /disabled-page
// publishes the platform's page for them. The listeners are :80, :8081
// (PROXY protocol) and :8443 (HTTPS, reached from this container for the
// health certificate checks).
//
// Every revision carries three challenge keys (e2e-key-1..3, current
// e2e-key-2) that GetChallengeKeys hands out.
//
// POST /g11 publishes the G11 sites (several certificates, client
// certificates, session ticket keys; g11.go), whose certificates and
// ticket keys GetCertificates and GetSessionTicketKeys hand out.
//
// The HTTPS origin's certificate comes from a separate CA that is written
// to --origin-ca-out; the node trusts it through --trusted-ca.
//
// The origin allow list is the network(s) of this container, which the
// node and whoami share, so the Docker-internal origins stay reachable
// without widening the default policy. A plain-HTTP helper API serves the
// test script:
//
//	GET /pin      internal CA pin (--ca-sha256)
//	GET /token    single-use enrollment token
//	GET /applied  "<applied_revision> <state>" from the last ReportStatus
//	GET /stats    number of uploaded MinuteStats buckets
//	GET /node-id  node id the console assigned
//	POST /purge-prefix?site=&host=&path=  queue a prefix purge task
//	GET /task-results  "<task id> <state> <error code>" per result
//	GET /origin-health  one line per origin with failures from the last
//	              ReportStatus: "<site> <origin> <code> <error>"
//	POST /publish publish a new revision adding site demo2.test
//	POST /update  update the existing demo2 site with an alias, without adding a site ID
//	POST /ban?cidr=&site=&ttl=  add a manual ban (platform scope without site);
//	              answers "<id> <sequence>"
//	POST /unban?id=  lift a ban; answers the sequence
//	GET /ban-status  "<applied_sequence> <entries> <unapplied> <kernel_entries>
//	              <kernel-ban-v1: yes|no>" from the last ReportStatus
//	GET /security-events  "<kind> <site> <level> <address> <metric>" per
//	              reported CC event
//	GET /security-state   "<site> <level> <escalated paths>" per site above
//	              normal in the last ReportStatus
//	POST /crs?enabled=false  publish the base sites without the OWASP CRS
//	              (enabled=true: with it again); answers the revision
//	POST /disabled-page?enabled=true  publish the base sites with the
//	              platform's page for disabled sites (enabled=false: the
//	              built-in page again); answers the revision
//	GET /features supported features of the last ReportStatus, one per line
//	GET /logs     "<site> <status> <path> <waf_blocked> <rule ids>" per
//	              uploaded access log ("-" when no rule matched)
//	GET /waf-rules "<site> <rule id> <requests>" per uploaded minute
//	GET /request-ids "<site> <status> <path> <request id>" per uploaded
//	              access log
//	POST /purge-tag?site=&tag=  queue a tag purge task; answers its id
//	POST /purge-host?site=&host=  queue a host purge task; answers its id
//	POST /sitemap?site=&url=&max=&variants=desktop,mobile  queue a sitemap
//	              prefetch task; answers its id
//	POST /prefetch?site=&url=  queue a prefetch task of one URL; answers its id
//	GET /task-result?id=  "<state> <error code> <succeeded> <failed>" of a
//	              reported task ("-" for no code)
//	POST /health?port=&status=  the status of the test origin's /health
//	GET /flaky?port=  how many requests the test origin saw at /flaky
//	GET /active-health  "<site> <origin> <healthy> <code>" per ACTIVE entry
//	              of the last ReportStatus ("-" for no code)
//	GET /tls-health?sni=&host=&path=  a TLS request to node:8443 with that
//	              SNI (none when empty): "<certificate CN> <status> <body>",
//	              or "handshake-failed <error>"
//	GET /probe-token  a new one-time probe token
//	POST /probe-node?enabled=  let the node probe (targets: node-peer at the
//	              node's address on :9 (closed), :80 HTTP and TCP, :8081
//	              HTTP with PROXY protocol, :8443 HTTPS, and node-e2e itself
//	              on :80; 5 s interval, 2 s timeout, 3 attempts) or stop it
//	GET /probe-results  the latest round of each prober: "<prober> <node>
//	              <method> <port> <sent> <lost> <rtt_ms> <error>" per result
//	GET /metrics  "<cpu %> <load1> <memory total> <memory used> <egress bps>
//	              <connections>" of the last ReportStatus
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/pki/pkitest"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

func tlsSite(id, domain, sni string) *nodev1.Site {
	s := site(id, domain, "console", 8444)
	s.OriginPool.Origins[0].Scheme = nodev1.OriginScheme_ORIGIN_SCHEME_HTTPS
	s.OriginPool.Origins[0].Sni = sni
	return s
}

// originCA issues the certificates of the HTTPS origins (for origin.test
// only) and is written to caOut, which the node trusts.
func originCA(caOut string) *pkitest.CA {
	ca, err := pkitest.NewCA("Edgeweir e2e origin CA")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(caOut+".tmp", ca.PEM, 0o644); err != nil {
		log.Fatal(err)
	}
	if err := os.Rename(caOut+".tmp", caOut); err != nil {
		log.Fatal(err)
	}
	return ca
}

// serveTLSOrigin serves an HTTPS origin with a certificate of ca for
// origin.test only.
func serveTLSOrigin(addr string, ca *pkitest.CA) {
	cert, err := ca.IssueServer([]string{"origin.test"}, nil)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "tls origin ok sni=%s\n", r.TLS.ServerName)
		}),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("HTTPS origin on %s", addr)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// serveTestOrigin serves the plain HTTP origin of the G4 sites on addr:
//
//	/tagged?tags=a,b  Cache-Tag: a,b (none without tags)
//	/gen              Cache-Tag: gen-<n>, n counting the requests of the
//	                  path, no validators (every refresh is new content)
//	/big.bin          3 MiB with Range support, Cache-Tag: file,
//	                  range-<the request's Range or none>
//	/status/<code>    answers <code> with an ETag
//	/echo             "port <port> rid <X-Request-Id>"
//	/health           the status set with the helper's POST /health (200)
//	/flaky            "flaky <n>", n counting the requests (the helper's
//	                  GET /flaky); 200 for the first, 500 for every later
//	                  one
//	/sitemap-index.xml.gz, /sitemap-a.xml, /sitemap-b.xml.gz  a gzipped
//	                  sitemap index with a plain and a gzipped sitemap of
//	                  smap.test (page-1, page-2, page-3?v=1) and URLs and a
//	                  sitemap on other.test
//
// Every response carries X-Origin: <port> and the origin's own
// X-Request-Id (the edge never forwards it).
func serveTestOrigin(addr string) {
	_, port, _ := net.SplitHostPort(addr)
	big := bytes.Repeat([]byte("0123456789abcdef"), 3<<20/16)
	var mu sync.Mutex
	gens := map[string]int{}
	health := healthOf(port)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Origin", port)
		h.Set("X-Request-Id", "origin-"+port)
		if serveContent(w, r, port) {
			return
		}
		if doc, ok := sitemaps[r.URL.Path]; ok {
			_, _ = w.Write(doc)
			return
		}
		switch {
		case r.URL.Path == "/health":
			w.WriteHeader(int(health.Load()))
		case r.URL.Path == "/flaky":
			n := flakyOf(port).Add(1)
			if n > 1 {
				w.WriteHeader(http.StatusInternalServerError)
			}
			fmt.Fprintf(w, "flaky %d\n", n)
		case r.URL.Path == "/gen":
			mu.Lock()
			gens[r.URL.Path]++
			n := gens[r.URL.Path]
			mu.Unlock()
			h.Set("Cache-Tag", fmt.Sprintf("gen-%d", n))
			fmt.Fprintf(w, "generation %d\n", n)
		case r.URL.Path == "/big.bin":
			h.Set("Cache-Tag", "file, range-"+cmpOr(r.Header.Get("Range"), "none"))
			http.ServeContent(w, r, "big.bin", time.Time{}, bytes.NewReader(big))
		case strings.HasPrefix(r.URL.Path, "/status/"):
			code, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/status/"))
			if err != nil || code < 200 || code > 599 {
				code = 400
			}
			h.Set("ETag", `"e2e"`)
			w.WriteHeader(code)
			fmt.Fprintf(w, "origin status %d\n", code)
		case r.URL.Path == "/echo":
			fmt.Fprintf(w, "port %s rid %s\n", port, r.Header.Get("X-Request-Id"))
		case r.URL.Path == "/slow":
			time.Sleep(2500 * time.Millisecond)
			fmt.Fprintf(w, "slow from %s\n", port)
		default:
			if tags := r.URL.Query().Get("tags"); tags != "" {
				h.Set("Cache-Tag", tags)
			}
			fmt.Fprintf(w, "%s from %s\n", r.URL.Path, port)
		}
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("test origin on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

// healths holds the status of each test origin's /health by port.
var healths sync.Map

func healthOf(port string) *atomic.Int32 {
	v, _ := healths.LoadOrStore(port, new(atomic.Int32))
	h := v.(*atomic.Int32)
	h.CompareAndSwap(0, http.StatusOK)
	return h
}

// flakies counts the requests of each test origin's /flaky by port.
var flakies sync.Map

func flakyOf(port string) *atomic.Int32 {
	v, _ := flakies.LoadOrStore(port, new(atomic.Int32))
	return v.(*atomic.Int32)
}

// sitemaps are the sitemap documents of the test origins.
var sitemaps = map[string][]byte{
	"/sitemap-index.xml.gz": gzipped(sitemapDoc("sitemapindex", "sitemap",
		"http://smap.test/sitemap-a.xml", "http://smap.test/sitemap-b.xml.gz", "http://other.test/sitemap-c.xml")),
	"/sitemap-a.xml": sitemapDoc("urlset", "url",
		"http://smap.test/page-1", "http://smap.test/page-2", "http://other.test/page-x"),
	"/sitemap-b.xml.gz": gzipped(sitemapDoc("urlset", "url", "http://smap.test/page-2", "http://smap.test/page-3?v=1")),
}

func sitemapDoc(root, entry string, locs ...string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n<" + root + ` xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`)
	for _, l := range locs {
		b.WriteString("\n  <" + entry + "><loc>" + strings.ReplaceAll(l, "&", "&amp;") + "</loc></" + entry + ">")
	}
	b.WriteString("\n</" + root + ">\n")
	return []byte(b.String())
}

func gzipped(b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return buf.Bytes()
}

func cmpOr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func site(id, domain, origin string, port uint32) *nodev1.Site {
	return &nodev1.Site{
		Id: id, Name: id, Enabled: true,
		Domains: []*nodev1.Domain{{Name: domain}},
		OriginPool: &nodev1.OriginPool{Id: "pool-" + id, Origins: []*nodev1.Origin{{
			Id: "o1", Address: origin, Port: port, Scheme: nodev1.OriginScheme_ORIGIN_SCHEME_HTTP, Weight: 1,
		}}},
		CacheRules: []*nodev1.CacheRule{{
			Id: "all", Priority: 100,
			Match:              &nodev1.CacheRuleMatch{PathPrefixes: []string{"/"}},
			Action:             nodev1.CacheAction_CACHE_ACTION_CACHE,
			EdgeTtlSeconds:     60,
			OriginCacheControl: nodev1.OriginCacheControl_ORIGIN_CACHE_CONTROL_OVERRIDE,
		}},
		CacheZone:       "default",
		CacheGeneration: 1,
	}
}

// ownNetworks returns the IPv4 networks of this container's interfaces.
func ownNetworks() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatal(err)
	}
	var out []string
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil {
			continue
		}
		pfx, err := netip.ParsePrefix(ipn.String())
		if err == nil {
			out = append(out, pfx.Masked().String())
		}
	}
	return out
}

var allowList []string

// challengeKeys are the cluster's pass keys.
var challengeKeys = []*nodev1.ChallengeKeyRef{
	{Id: "e2e-key-1", Role: "previous"}, {Id: "e2e-key-2", Role: "current"}, {Id: "e2e-key-3", Role: "next"},
}

func config(sites ...*nodev1.Site) *nodev1.NodeConfig {
	return &nodev1.NodeConfig{
		ChallengeKeys:    challengeKeys,
		RequiredFeatures: []string{"challenge-v1", "brotli-v1", "zstd-v1", "modsecurity-v1", "error-pages-v1", "session-affinity-v1", "active-health-v1", configir.FeatureRulesV2, configir.FeatureL4, configir.FeatureOriginHTTP2, configir.FeatureRulesV3, configir.FeatureEdgePorts, configir.FeatureClientIP, configir.FeatureL4V2, configir.FeatureSiteContent},
		OfflineHosts: []*nodev1.OfflineHost{
			{Name: "gone.test", Wildcard: true, Reason: "disabled"},
			{Name: "old.test", Reason: "disabled"},
		},
		Listeners: []*nodev1.Listener{
			{Port: 80, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTP},
			// Behind a load balancer that speaks the PROXY protocol.
			{Port: 8081, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTP, ProxyProtocol: true},
			// HTTPS: the probes' health certificate (no site has a certificate).
			{Port: 8443, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTPS},
			// edge-ports-v1: an extra HTTP port that only some sites are bound to.
			{Port: 8082, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTP},
		},
		CacheZones:         []*nodev1.CacheZone{{Name: "default", MaxSizeMb: 256, KeysZoneMb: 8, InactiveSeconds: 600}},
		Sites:              sites,
		OriginAllowedCidrs: allowList,
		IpLists:            l4Lists,
		L4Apps:             currentL4(),
	}
}

// edgePortSites (edge-ports-v1, client-ip-v1): ports.test is served on
// 8082 only, p80.test on 80 only (every other site has no ports: every
// listener); peer.test sends the connection's peer (ip.peer) to the origin
// as X-Peer.
func edgePortSites(origin string) []*nodev1.Site {
	ports := site("site-ports", "ports.test", origin, 80)
	ports.Ports = []uint32{8082}
	p80 := site("site-p80", "p80.test", origin, 80)
	p80.Ports = []uint32{80}
	peer := site("site-peer", "peer.test", origin, 80)
	peer.Rules = []*nodev1.EdgeRule{{
		Id: "peer", Phase: "request-transform",
		Expression: &nodev1.RuleExpression{Op: "literal", ValueType: "boolean", Value: "true"},
		Action:     &nodev1.RuleAction{Kind: "request_header", Header: "x-peer", Target: irCall("to_string", "string", irField("ip.peer", "ip"))},
	}}
	return []*nodev1.Site{ports, p80, peer}
}

// baseSites are published in every revision.
func baseSites(origin string) []*nodev1.Site {
	return append([]*nodev1.Site{
		site("site-demo", "demo.test", origin, 80),
		site("site-loop", "loop.test", "node", 80),
		site("site-forbidden", "forbidden.test", "127.0.0.1", 80),
		site("site-hidden", "hidden.test", "hidden", 80),
		tlsSite("site-tls-ok", "tls-ok.test", "origin.test"),
		tlsSite("site-tls-bad", "tls-bad.test", "wrong.test"),
		keyedSite(origin),
		authSite(origin),
		underAttackSite("site-ua", "ua.test", origin, "cookie302"),
		underAttackSite("site-js", "js.test", origin, "js"),
		underAttackSite("site-pow", "pow.test", origin, "pow"),
		underAttackSite("site-captcha", "captcha.test", origin, "captcha"),
		ccSite(origin),
		compressSite(origin),
		crsSite("site-crs-detect", "crs-detect.test", origin, "detect"),
		crsSite("site-crs-block", "crs-block.test", origin, "block", 942100),
		site("site-tags", "tags.test", "console", 8082),
		keepSite(),
		sliceSite(),
		swrSite(),
		sieSite(),
		pagesSite(),
		site("site-dead", "dead.test", "console", 9),
		affinitySite(),
		sitemapSite(),
		activeSite(),
		rulesSite(origin),
		v3Site(origin),
	}, append(append(h2Sites(), edgePortSites(origin)...), contentSites(origin)...)...)
}

// Expression IR helpers for the rules-v2 sites.
var (
	irTrue = &nodev1.RuleExpression{Op: "literal", ValueType: "boolean", Value: "true"}
	irPath = &nodev1.RuleExpression{Op: "field", Field: "http.request.uri.path", ValueType: "string"}
)

func irConst(v string) *nodev1.RuleExpression {
	return &nodev1.RuleExpression{Op: "const", ValueType: "string", Value: v}
}

func irCall(name, typ string, args ...*nodev1.RuleExpression) *nodev1.RuleExpression {
	return &nodev1.RuleExpression{Op: "call", Field: name, ValueType: typ, Children: args}
}

// pathStarts is starts_with(http.request.uri.path, prefix).
func pathStarts(prefix string) *nodev1.RuleExpression {
	return irCall("starts_with", "boolean", irPath, irConst(prefix))
}

// rulesSite exercises the rules-v2 actions (see the package comment).
func rulesSite(origin string) *nodev1.Site {
	s := site("site-rules", "rules.test", "console", 8082)
	s.OriginPool.Origins = append(s.OriginPool.Origins, &nodev1.Origin{
		Id: "o-api", Address: origin, Port: 80, Scheme: nodev1.OriginScheme_ORIGIN_SCHEME_HTTP, Weight: 1, Group: "api",
	})
	s.Protection = &nodev1.SiteProtection{UnderAttackChallenge: "js", PassTtlSeconds: 300}
	yes, no, rate := true, false, uint32(10000)
	s.Rules = []*nodev1.EdgeRule{
		{Id: "rw-api", Phase: "request-transform", Expression: pathStarts("/api/"), Action: &nodev1.RuleAction{
			Kind: "rewrite", PreserveQuery: &no, SetQuery: []*nodev1.QueryParam{{Name: "v", Value: "2"}},
			Target: irCall("wildcard_replace", "string", irPath, irConst("/API/*"), irConst("/internal/${1}")),
		}},
		{Id: "old", Phase: "redirect", Expression: pathStarts("/old/"), Action: &nodev1.RuleAction{
			Kind: "redirect", StatusCode: 301, PreserveQuery: &yes,
			Target:      irCall("regex_replace", "string", irPath, irConst("^/old/(.*)$"), irConst("/new/${1}")),
			SetQuery:    []*nodev1.QueryParam{{Name: "lang", Value: "zh CN"}},
			RemoveQuery: []string{"utm_source"},
		}},
		{Id: "slow", Phase: "config", Expression: pathStarts("/slow"), Action: &nodev1.RuleAction{Kind: "config", OriginReadTimeoutMs: 1000, CacheBypass: &yes}},
		{Id: "sampled", Phase: "config", Expression: pathStarts("/sampled"), Action: &nodev1.RuleAction{Kind: "config", LogSampleRate: &rate}},
		{Id: "ws", Phase: "config", Expression: pathStarts("/ws"), Action: &nodev1.RuleAction{Kind: "config", Websocket: &no}},
		{Id: "guarded", Phase: "config", Expression: pathStarts("/guarded"), Action: &nodev1.RuleAction{Kind: "config", UnderAttack: &yes}},
		{Id: "api", Phase: "origin", Expression: pathStarts("/internal/"), Action: &nodev1.RuleAction{Kind: "origin", OriginGroup: "api", HostHeader: "api.internal"}},
		{Id: "port", Phase: "origin", Expression: pathStarts("/port/"), Action: &nodev1.RuleAction{Kind: "origin", Port: 8083}},
	}
	s.BulkRedirects = []*nodev1.BulkRedirect{
		{Source: "/bulk-old", Target: "/bulk-new?from=bulk", StatusCode: 308, PreserveQuery: true},
		{Source: "rules.test/bulk-host", Target: "https://example.test/host", StatusCode: 302},
	}
	s.CacheRules = append([]*nodev1.CacheRule{{
		Id: "img", Priority: 10, Action: nodev1.CacheAction_CACHE_ACTION_CACHE, EdgeTtlSeconds: 60, BrowserTtlSeconds: 600,
		OriginCacheControl: nodev1.OriginCacheControl_ORIGIN_CACHE_CONTROL_OVERRIDE,
		Match: &nodev1.CacheRuleMatch{Condition: &nodev1.RuleExpression{Op: "and", Children: []*nodev1.RuleExpression{
			pathStarts("/img/"), {Op: "in", Field: "http.request.uri.path.extension", ValueType: "string", Values: []string{"png"}},
		}}},
	}}, s.CacheRules...)
	return s
}

// irField reads a field.
func irField(name, typ string) *nodev1.RuleExpression {
	return &nodev1.RuleExpression{Op: "field", Field: name, ValueType: typ}
}

// v3Site exercises the rules-v3 additions (see the package comment).
func v3Site(origin string) *nodev1.Site {
	s := site("site-v3", "v3.test", origin, 80)
	str := func(name string) *nodev1.RuleExpression { return irField(name, "string") }
	header := func(id, phase, kind, name string, target *nodev1.RuleExpression) *nodev1.EdgeRule {
		return &nodev1.EdgeRule{Id: id, Phase: phase, Expression: irTrue, Action: &nodev1.RuleAction{Kind: kind, Header: name, Target: target}}
	}
	path := func(p string) *nodev1.RuleExpression {
		return &nodev1.RuleExpression{Op: "eq", Field: "http.request.uri.path", ValueType: "string", Value: p}
	}
	s.Rules = []*nodev1.EdgeRule{
		header("req", "request-transform", "request_header", "x-req", str("http.request.id")),
		header("bad", "request-transform", "request_header", "x-bad", irCall("url_decode", "string", str("http.request.uri.args.bad"))),
		{Id: "login", Phase: "redirect", Expression: path("/login"), Action: &nodev1.RuleAction{
			Kind: "redirect", StatusCode: 303, Value: "/signin",
			SetQuery: []*nodev1.QueryParam{{Name: "next", Expression: str("http.request.uri.args.next")}},
		}},
		{Id: "go", Phase: "redirect", Expression: path("/go"), Action: &nodev1.RuleAction{
			Kind: "redirect", StatusCode: 302, Target: irCall("concat", "string", irConst("/"), str("http.request.uri.args.to")),
		}},
		{Id: "admin", Phase: "waf-custom", Action: &nodev1.RuleAction{Kind: "block", StatusCode: 403},
			Expression: &nodev1.RuleExpression{Op: "eq", Field: "http.request.cookies.role", ValueType: "string", Value: "admin"}},
		header("info", "origin", "request_header", "x-info", irCall("concat", "string",
			str("http.request.version"), irConst(" "), str("http.request.scheme"), irConst(" "),
			irCall("to_string", "string", irField("edge.server_port", "number")), irConst(" "), str("http.user_agent"))),
		{Id: "link1", Phase: "response-transform", Expression: irTrue, Action: &nodev1.RuleAction{Kind: "response_header", Header: "link", Value: "</a.css>; rel=preload", Append: true}},
		{Id: "link2", Phase: "response-transform", Expression: irTrue, Action: &nodev1.RuleAction{Kind: "response_header", Header: "link", Append: true,
			Target: irCall("concat", "string", irConst("<"), irPath, irConst(">; rel=canonical"))}},
		header("cache", "response-transform", "response_header", "x-cache-status", str("http.response.cache_status")),
		{Id: "ua", Phase: "response-transform", Action: &nodev1.RuleAction{Kind: "response_header", Header: "x-ua-match", Value: "1"},
			Expression: &nodev1.RuleExpression{Op: "wildcard", Field: "http.user_agent", ValueType: "string", Value: "*CURL*"}},
	}
	s.ErrorPages = &nodev1.SiteErrorPages{Pages: []*nodev1.ErrorPage{{Status: 403, Template: "<p>v3 {{status}} at {{time}} for {{path}}</p>"}}}
	return s
}

// sitemapSite caches one object per device class.
func sitemapSite() *nodev1.Site {
	s := site("site-smap", "smap.test", "console", 8082)
	s.CacheKey = &nodev1.CacheKeyPolicy{DeviceType: true}
	return s
}

// activeSite probes /health of its two origins every 5 seconds; one failed
// probe takes an origin out, one good probe brings it back.
func activeSite() *nodev1.Site {
	s := site("site-active", "active.test", "console", 8082)
	s.OriginPool.Origins = append(s.OriginPool.Origins, &nodev1.Origin{
		Id: "o2", Address: "console", Port: 8083, Scheme: nodev1.OriginScheme_ORIGIN_SCHEME_HTTP, Weight: 1,
	})
	s.OriginPool.ActiveHealthCheck = &nodev1.ActiveHealthCheck{
		Path: "/health", IntervalSeconds: 5, TimeoutSeconds: 2, HealthyThreshold: 1, UnhealthyThreshold: 1,
	}
	s.CacheRules = nil
	return s
}

// keepSite forwards Cache-Tag to clients.
func keepSite() *nodev1.Site {
	s := site("site-keep", "keep.test", "console", 8082)
	s.KeepCacheTag = true
	return s
}

// sliceSite caches 1 MiB slices.
func sliceSite() *nodev1.Site {
	s := site("site-slice", "slice.test", "console", 8082)
	s.RangeSlice = true
	return s
}

// swrSite keeps objects fresh for a second and serves them stale for a
// minute while a background update refreshes them.
func swrSite() *nodev1.Site {
	s := site("site-swr", "swr.test", "console", 8082)
	s.CacheRules[0].EdgeTtlSeconds = 1
	s.CacheRules[0].StaleWhileRevalidateSeconds = 60
	return s
}

// sieSite keeps objects fresh for a second and serves them stale for a
// minute when the origin fails (stale-if-error).
func sieSite() *nodev1.Site {
	s := site("site-sie", "sie.test", "console", 8082)
	s.CacheRules[0].EdgeTtlSeconds = 1
	s.CacheRules[0].StaleIfErrorSeconds = 60
	return s
}

// pagesSite has its own 403 and 503 pages and intercepts origin errors.
func pagesSite() *nodev1.Site {
	s := site("site-pages", "pages.test", "console", 8082)
	s.ErrorPages = &nodev1.SiteErrorPages{
		Pages: []*nodev1.ErrorPage{
			{Status: 403, Template: "<h1>pages.test {{status}} {{client_ip}} {{request_id}}</h1>"},
			{Status: 503, Template: "<h1>busy {{host}}</h1>"},
		},
		InterceptOriginErrors: true,
	}
	s.LogSampleRate = 10000
	return s
}

// affinitySite pins clients to one of two origins and caches nothing.
func affinitySite() *nodev1.Site {
	s := site("site-aff", "aff.test", "console", 8082)
	s.OriginPool.Origins = append(s.OriginPool.Origins, &nodev1.Origin{
		Id: "o2", Address: "console", Port: 8083, Scheme: nodev1.OriginScheme_ORIGIN_SCHEME_HTTP, Weight: 1,
	})
	s.OriginPool.SessionAffinity = &nodev1.SessionAffinity{TtlSeconds: 120}
	s.CacheRules = nil
	return s
}

// compressSite compresses text/plain with gzip, Brotli and Zstandard.
func compressSite(origin string) *nodev1.Site {
	s := site("site-compress", "compress.test", origin, 80)
	no := false
	s.Rules = []*nodev1.EdgeRule{
		{Id: "no-gzip", Phase: "config", Expression: pathStarts("/no-gzip"), Action: &nodev1.RuleAction{Kind: "config", Gzip: &no}},
		{Id: "gz-only", Phase: "compression", Expression: pathStarts("/gz-only"), Action: &nodev1.RuleAction{Kind: "compression", Compression: []string{"gzip"}}},
		{Id: "none", Phase: "compression", Expression: pathStarts("/no-compress"), Action: &nodev1.RuleAction{Kind: "compression"}},
	}
	types := []string{"text/plain"}
	s.Tls = &nodev1.TlsOptions{
		MinimumVersion: "1.2", CipherProfile: "modern",
		Gzip: true, GzipMinLength: 1, GzipTypes: types,
		Brotli: true, BrotliLevel: 5, BrotliMinLength: 1, BrotliTypes: types,
		Zstd: true, ZstdLevel: 3, ZstdMinLength: 1, ZstdTypes: types,
	}
	return s
}

// crsSite runs the OWASP CRS (paranoia level 1, threshold 5) and logs every
// request.
func crsSite(id, domain, origin, mode string, excluded ...uint32) *nodev1.Site {
	s := site(id, domain, origin, 80)
	s.Waf = &nodev1.SiteWaf{Mode: mode, ParanoiaLevel: 1, AnomalyThreshold: 5, RequestBodyLimit: 131072, ExcludedRuleIds: excluded}
	s.LogSampleRate = 10000
	return s
}

// underAttackSite challenges every request without a pass.
func underAttackSite(id, domain, origin, challenge string) *nodev1.Site {
	s := site(id, domain, origin, 80)
	s.Protection = &nodev1.SiteProtection{UnderAttack: true, UnderAttackChallenge: challenge, PassTtlSeconds: 300, PowDifficulty: 8, PowHighDifficulty: 8}
	return s
}

// ccSite bans addresses over 2 requests per second and escalates to
// cookie302 after 2 seconds over 20 requests per second. The long
// cooldown holds the level for the policy changes checked afterwards.
func ccSite(origin string) *nodev1.Site {
	s := site("site-cc", "cc.test", origin, 80)
	s.Protection = &nodev1.SiteProtection{Cc: &nodev1.CcPolicy{
		Enabled: true, MaxLevel: "cookie302", WindowSeconds: 5, SiteQps: 20, IpQps: 2, IpBanSeconds: 60,
		EscalateAfterSeconds: 2, CooldownSeconds: 300,
	}}
	return s
}

// authSite caches requests with Authorization (cache_authorized).
func authSite(origin string) *nodev1.Site {
	s := site("site-auth", "auth.test", origin, 80)
	s.CacheRules[0].CacheAuthorized = true
	return s
}

// keyedSite varies its cache key on Accept-Language.
func keyedSite(origin string) *nodev1.Site {
	s := site("site-keyed", "keyed.test", origin, 80)
	s.CacheKey = &nodev1.CacheKeyPolicy{Headers: []string{"accept-language"}}
	return s
}

// nodeIPv4 resolves the node container's address on this network.
func nodeIPv4() (string, error) {
	ips, err := net.LookupIP("node")
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("node has no IPv4 address: %v", ips)
}

// probeTargets are the targets the probes get, sorted by (node, address,
// port) like the console's.
func probeTargets(ip string) *nodev1.GetProbeTargetsResponse {
	const (
		tcp   = nodev1.ProbeMethod_PROBE_METHOD_TCP
		plain = nodev1.ProbeMethod_PROBE_METHOD_HTTP
		https = nodev1.ProbeMethod_PROBE_METHOD_HTTPS
	)
	return &nodev1.GetProbeTargetsResponse{IntervalSeconds: 5, TimeoutMs: 2000, Attempts: 3, Targets: []*nodev1.ProbeTarget{
		{NodeId: "node-e2e", Address: ip, Port: 80, Method: plain},
		{NodeId: "node-peer", Address: ip, Port: 9, Method: tcp},
		{NodeId: "node-peer", Address: ip, Port: 80, Method: plain},
		{NodeId: "node-peer", Address: ip, Port: 80, Method: tcp},
		{NodeId: "node-peer", Address: ip, Port: 8081, Method: plain, ProxyProtocol: true},
		{NodeId: "node-peer", Address: ip, Port: 8443, Method: https},
	}}
}

// tlsHealth asks node:8443 for a path over TLS with an SNI (none when
// empty) and reports the certificate's CN, the status and the body.
func tlsHealth(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	ip, err := nodeIPv4()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "8443"), 5*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	// The node's health certificate is self-signed; an empty ServerName
	// (dialing an IP) sends no SNI.
	tc := tls.Client(conn, &tls.Config{ServerName: q.Get("sni"), InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // test helper
	if err := tc.Handshake(); err != nil {
		fmt.Fprintf(w, "handshake-failed %v", err)
		return
	}
	cn := tc.ConnectionState().PeerCertificates[0].Subject.CommonName
	fmt.Fprintf(tc, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", cmpOr(q.Get("path"), "/.edgeweir/health"), cmpOr(q.Get("host"), "unknown.test"))
	resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		fmt.Fprintf(w, "%s no-response %v", cn, err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	fmt.Fprintf(w, "%s %d %s", cn, resp.StatusCode, strings.TrimSpace(string(body)))
}

func main() {
	listen := flag.String("listen", ":8443", "NodeService (TLS) address")
	helper := flag.String("helper", ":8081", "plain HTTP helper API for the test script")
	names := flag.String("dns-names", "console,localhost", "TLS certificate DNS names")
	origin := flag.String("origin", "whoami", "origin address")
	token := flag.String("token", "e2e-token", "enrollment token")
	allowed := flag.String("origin-allowed-cidrs", "", "comma-separated origin allow list (default: this container's networks)")
	tlsOrigin := flag.String("origin-tls", ":8444", "HTTPS origin address")
	caOut := flag.String("origin-ca-out", "/shared/origin-ca.pem", "where to write the HTTPS origin's CA certificate")
	flag.Parse()
	ca := originCA(*caOut)
	go serveTLSOrigin(*tlsOrigin, ca)
	serveH2Origins(ca)
	go serveTestOrigin(":8082")
	go serveTestOrigin(":8083")
	serveL4Origins()
	if *allowed != "" {
		allowList = strings.Split(*allowed, ",")
	} else {
		allowList = ownNetworks()
	}
	log.Printf("origin allow list: %v", allowList)

	c, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-e2e", ClusterID: "cluster-e2e", NodeName: "edge-e2e", ReportInterval: 2})
	if err != nil {
		log.Fatal(err)
	}
	c.AddToken(*token)
	for i, k := range challengeKeys {
		c.SetChallengeKey(k.GetId(), []byte(fmt.Sprintf("e2e challenge key %d, 32 bytes!!", i+1)))
	}
	c.SetCredential(&nodev1.OriginCredential{Id: purgeKeyID, Version: 1, SecretAccessKey: purgeKey})
	clientCA := g11Setup(c, filepath.Dir(*caOut))
	c.Publish(config(baseSites(*origin)...))

	tlsCfg, err := c.TLSConfig(strings.Split(*names, ","), []net.IP{net.IPv4(127, 0, 0, 1)})
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: *listen, Handler: c.Handler(), TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /pin", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, c.CA.Pin()) })
	contentHelpers(mux, c, c.Publish, func() *nodev1.NodeConfig { return config(baseSites(*origin)...) })
	g10Handlers(mux, c, *origin)
	g11Handlers(mux, c, *origin, clientCA)
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, *token) })
	mux.HandleFunc("GET /grpc", grpcCheck)
	mux.HandleFunc("GET /h2-probes", h2ProbeCounts)
	mux.HandleFunc("GET /ws", wsCheck)
	mux.HandleFunc("GET /origin-health", func(w http.ResponseWriter, _ *http.Request) {
		for _, h := range c.LastStatus().GetOriginHealth() {
			code := h.GetLastErrorCode()
			if code == "" {
				code = "-"
			}
			fmt.Fprintf(w, "%s %s %s %s\n", h.GetSiteId(), h.GetOriginId(), code, h.GetLastError())
		}
	})
	mux.HandleFunc("POST /purge-prefix", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		id := fmt.Sprintf("purge-%d", time.Now().UnixNano())
		c.AddTask(&nodev1.NodeTask{Id: id, CreatedAt: timestamppb.Now(), Kind: &nodev1.NodeTask_Purge{Purge: &nodev1.PurgeTask{
			Targets: []*nodev1.PurgeTarget{{SiteId: q.Get("site"), Type: nodev1.PurgeType_PURGE_TYPE_PREFIX, Host: q.Get("host"), Path: q.Get("path")}},
		}}}, false)
		fmt.Fprint(w, id)
	})
	queue := func(w http.ResponseWriter, prefix string, task *nodev1.NodeTask) {
		task.Id, task.CreatedAt = fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()), timestamppb.Now()
		c.AddTask(task, false)
		fmt.Fprint(w, task.Id)
	}
	mux.HandleFunc("POST /purge-tag", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		queue(w, "purge-tag", &nodev1.NodeTask{Kind: &nodev1.NodeTask_Purge{Purge: &nodev1.PurgeTask{
			Targets: []*nodev1.PurgeTarget{{SiteId: q.Get("site"), Type: nodev1.PurgeType_PURGE_TYPE_TAG, Tag: q.Get("tag")}},
		}}})
	})
	mux.HandleFunc("POST /purge-host", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		queue(w, "purge-host", &nodev1.NodeTask{Kind: &nodev1.NodeTask_Purge{Purge: &nodev1.PurgeTask{
			Targets: []*nodev1.PurgeTarget{{SiteId: q.Get("site"), Type: nodev1.PurgeType_PURGE_TYPE_HOST, Host: q.Get("host")}},
		}}})
	})
	mux.HandleFunc("POST /sitemap", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		task := &nodev1.SitemapPrefetchTask{SiteId: q.Get("site"), Url: q.Get("url")}
		if v, err := strconv.ParseUint(q.Get("max"), 10, 32); err == nil {
			task.MaxUrls = uint32(v)
		}
		for _, v := range strings.Split(q.Get("variants"), ",") {
			switch v {
			case "desktop":
				task.Variants = append(task.Variants, nodev1.DeviceVariant_DEVICE_VARIANT_DESKTOP)
			case "mobile":
				task.Variants = append(task.Variants, nodev1.DeviceVariant_DEVICE_VARIANT_MOBILE)
			}
		}
		queue(w, "sitemap", &nodev1.NodeTask{Kind: &nodev1.NodeTask_Sitemap{Sitemap: task}})
	})
	mux.HandleFunc("POST /prefetch", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		queue(w, "prefetch", &nodev1.NodeTask{Kind: &nodev1.NodeTask_Prefetch{Prefetch: &nodev1.PrefetchTask{
			Targets: []*nodev1.PrefetchTarget{{SiteId: q.Get("site"), Url: q.Get("url")}},
		}}})
	})
	mux.HandleFunc("GET /task-result", func(w http.ResponseWriter, r *http.Request) {
		for _, res := range c.TaskResults() {
			if res.GetTaskId() == r.URL.Query().Get("id") {
				fmt.Fprintf(w, "%s %s %d %d", res.GetState(), cmpOr(res.GetErrorCode(), "-"), res.GetSucceeded(), res.GetFailed())
				return
			}
		}
		http.NotFound(w, r)
	})
	mux.HandleFunc("POST /health", func(w http.ResponseWriter, r *http.Request) {
		code, err := strconv.Atoi(r.URL.Query().Get("status"))
		if err != nil || code < 100 || code > 599 {
			http.Error(w, "status must be 100-599", http.StatusBadRequest)
			return
		}
		healthOf(r.URL.Query().Get("port")).Store(int32(code))
	})
	mux.HandleFunc("GET /flaky", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, flakyOf(r.URL.Query().Get("port")).Load())
	})
	mux.HandleFunc("GET /active-health", func(w http.ResponseWriter, _ *http.Request) {
		for _, h := range c.LastStatus().GetOriginHealth() {
			if h.GetSource() == nodev1.OriginHealthSource_ORIGIN_HEALTH_SOURCE_ACTIVE {
				fmt.Fprintf(w, "%s %s %t %s\n", h.GetSiteId(), h.GetOriginId(), h.GetHealthy(), cmpOr(h.GetLastErrorCode(), "-"))
			}
		}
	})
	mux.HandleFunc("GET /task-results", func(w http.ResponseWriter, _ *http.Request) {
		for _, res := range c.TaskResults() {
			code := res.GetErrorCode()
			if code == "" {
				code = "-"
			}
			fmt.Fprintf(w, "%s %s %s\n", res.GetTaskId(), res.GetState(), code)
		}
	})
	mux.HandleFunc("GET /node-id", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, c.Options().NodeID) })
	mux.HandleFunc("GET /applied", func(w http.ResponseWriter, _ *http.Request) {
		s := c.LastStatus()
		fmt.Fprintf(w, "%d %s", s.GetAppliedRevision(), s.GetState())
	})
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, _ *http.Request) {
		var reqs uint64
		for _, s := range c.Stats() {
			reqs += s.GetRequests()
		}
		fmt.Fprintf(w, "%d %d", len(c.Stats()), reqs)
	})
	mux.HandleFunc("POST /publish", func(w http.ResponseWriter, _ *http.Request) {
		rev := c.Publish(config(append(baseSites(*origin), site("site-demo2", "demo2.test", *origin, 80))...))
		fmt.Fprint(w, rev)
	})
	mux.HandleFunc("POST /update", func(w http.ResponseWriter, _ *http.Request) {
		updated := site("site-demo2", "demo2.test", *origin, 80)
		updated.Domains = append(updated.Domains, &nodev1.Domain{Name: "alias.demo2.test"})
		updated.CacheGeneration++
		rev := c.Publish(config(append(baseSites(*origin), updated)...))
		fmt.Fprint(w, rev)
	})
	// POST /cc publishes the base sites with site-cc's site threshold set
	// to site_qps, or with its CC policy off (enabled=false).
	mux.HandleFunc("POST /cc", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		sites := baseSites(*origin)
		for _, s := range sites {
			if cc := s.GetProtection().GetCc(); s.GetId() == "site-cc" && cc != nil {
				cc.Enabled = q.Get("enabled") != "false"
				if v, err := strconv.ParseUint(q.Get("site_qps"), 10, 32); err == nil {
					cc.SiteQps = uint32(v)
				}
			}
		}
		fmt.Fprint(w, c.Publish(config(sites...)))
	})
	mux.HandleFunc("POST /ban", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		ttl, err := time.ParseDuration(q.Get("ttl") + "s")
		if q.Get("ttl") == "" {
			ttl, err = time.Hour, nil
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b := &nodev1.Ban{
			Id: fmt.Sprintf("ban-%d", time.Now().UnixNano()), Cidr: q.Get("cidr"), Scope: nodev1.BanScope_BAN_SCOPE_PLATFORM,
			Source: nodev1.BanSource_BAN_SOURCE_MANUAL, Reason: "abuse",
			CreatedAt: timestamppb.Now(), ExpiresAt: timestamppb.New(time.Now().Add(ttl)),
		}
		if site := q.Get("site"); site != "" {
			b.Scope, b.SiteId = nodev1.BanScope_BAN_SCOPE_SITE, site
		}
		fmt.Fprintf(w, "%s %d", b.Id, c.AddBan(b))
	})
	mux.HandleFunc("POST /unban", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, c.RemoveBan(r.URL.Query().Get("id")))
	})
	mux.HandleFunc("GET /ban-status", func(w http.ResponseWriter, _ *http.Request) {
		s := c.LastStatus()
		b := s.GetBans()
		kernel := "no"
		if slices.Contains(s.GetInfo().GetSupportedFeatures(), "kernel-ban-v1") {
			kernel = "yes"
		}
		fmt.Fprintf(w, "%d %d %d %d %s", b.GetAppliedSequence(), b.GetEntries(), b.GetUnapplied(), b.GetKernelEntries(), kernel)
	})
	mux.HandleFunc("GET /security-events", func(w http.ResponseWriter, _ *http.Request) {
		events, _ := c.SecurityEvents()
		for _, e := range events {
			fmt.Fprintf(w, "%s %s %s %s %s\n", strings.ToLower(strings.TrimPrefix(e.GetKind().String(), "SECURITY_EVENT_KIND_")),
				e.GetSiteId(), e.GetLevel(), cmpOr(e.GetAddress(), "-"), e.GetMetric())
		}
	})
	mux.HandleFunc("POST /crs", func(w http.ResponseWriter, r *http.Request) {
		sites := baseSites(*origin)
		cfg := config(sites...)
		if r.URL.Query().Get("enabled") == "false" {
			for _, s := range sites {
				s.Waf = nil
			}
			cfg.RequiredFeatures = slices.DeleteFunc(cfg.RequiredFeatures, func(f string) bool { return f == "modsecurity-v1" })
		}
		fmt.Fprint(w, c.Publish(cfg))
	})
	mux.HandleFunc("POST /disabled-page", func(w http.ResponseWriter, r *http.Request) {
		cfg := config(baseSites(*origin)...)
		if r.URL.Query().Get("enabled") != "false" {
			cfg.PlatformErrorPages = &nodev1.PlatformErrorPages{SiteDisabled: "<h1>disabled {{host}} {{request_id}}</h1>"}
		}
		fmt.Fprint(w, c.Publish(cfg))
	})
	mux.HandleFunc("GET /features", func(w http.ResponseWriter, _ *http.Request) {
		for _, f := range c.LastStatus().GetInfo().GetSupportedFeatures() {
			fmt.Fprintln(w, f)
		}
	})
	mux.HandleFunc("GET /logs", func(w http.ResponseWriter, _ *http.Request) {
		for _, l := range c.Logs() {
			ids := make([]string, 0, len(l.GetWafRuleIds()))
			for _, id := range l.GetWafRuleIds() {
				ids = append(ids, strconv.FormatUint(uint64(id), 10))
			}
			fmt.Fprintf(w, "%s %d %s %t %s\n", l.GetSiteId(), l.GetStatus(), l.GetPath(), l.GetWafBlocked(), cmpOr(strings.Join(ids, ","), "-"))
		}
	})
	mux.HandleFunc("GET /request-ids", func(w http.ResponseWriter, _ *http.Request) {
		for _, l := range c.Logs() {
			fmt.Fprintf(w, "%s %d %s %s\n", l.GetSiteId(), l.GetStatus(), l.GetPath(), cmpOr(l.GetRequestId(), "-"))
		}
	})
	mux.HandleFunc("GET /waf-rules", func(w http.ResponseWriter, _ *http.Request) {
		for _, m := range c.Stats() {
			for _, r := range m.GetWafRules() {
				fmt.Fprintf(w, "%s %s %d\n", m.GetSiteId(), r.GetValue(), r.GetCount())
			}
		}
	})
	mux.HandleFunc("GET /tls-health", tlsHealth)
	registerL4(mux, c, func() uint64 { return c.Publish(config(baseSites(*origin)...)) })
	mux.HandleFunc("GET /probe-token", func(w http.ResponseWriter, _ *http.Request) {
		token := fmt.Sprintf("probe-token-%d", time.Now().UnixNano())
		c.AddProbeToken(token)
		fmt.Fprint(w, token)
	})
	mux.HandleFunc("POST /probe-node", func(w http.ResponseWriter, r *http.Request) {
		on := r.URL.Query().Get("enabled") != "false"
		if on {
			ip, err := nodeIPv4()
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			c.SetProbeTargets(probeTargets(ip))
		}
		c.SetNodeProbe(on)
	})
	mux.HandleFunc("GET /probe-results", func(w http.ResponseWriter, _ *http.Request) {
		latest := map[string]*nodev1.ReportProbeResultsRequest{}
		for _, rep := range c.ProbeReports() {
			latest[rep.Caller] = rep.Request
		}
		for _, prober := range slices.Sorted(maps.Keys(latest)) {
			for _, res := range latest[prober].GetResults() {
				fmt.Fprintf(w, "%s %s %s %d %d %d %d %s\n", prober, res.GetNodeId(),
					strings.ToLower(strings.TrimPrefix(res.GetMethod().String(), "PROBE_METHOD_")), res.GetPort(),
					res.GetSent(), res.GetLost(), res.GetRttMs(), cmpOr(res.GetError(), "-"))
			}
		}
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		m := c.LastStatus().GetMetrics()
		fmt.Fprintf(w, "%g %g %d %d %d %d", m.GetCpuPercent(), m.GetLoad1(), m.GetMemoryTotalBytes(), m.GetMemoryUsedBytes(),
			m.GetEgressBps(), m.GetActiveConnections())
	})
	mux.HandleFunc("GET /security-state", func(w http.ResponseWriter, _ *http.Request) {
		for _, s := range c.LastStatus().GetSecurity() {
			fmt.Fprintf(w, "%s %s %d\n", s.GetSiteId(), s.GetLevel(), s.GetEscalatedPaths())
		}
	})
	go func() {
		log.Printf("helper API on %s", *helper)
		log.Fatal(http.ListenAndServe(*helper, mux))
	}()

	h, _ := configir.ContentHash(config())
	log.Printf("NodeService on %s, CA pin %s, token %s (empty config hash %s)", *listen, c.CA.Pin(), *token, h)
	if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
