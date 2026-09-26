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
package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
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

// serveTLSOrigin serves an HTTPS origin whose certificate (for origin.test
// only) is issued by a fresh CA, and writes that CA to caOut.
func serveTLSOrigin(addr, caOut string) {
	ca, err := pkitest.NewCA("Edgeweir e2e origin CA")
	if err != nil {
		log.Fatal(err)
	}
	cert, err := ca.IssueServer([]string{"origin.test"}, nil)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(caOut+".tmp", ca.PEM, 0o644); err != nil {
		log.Fatal(err)
	}
	if err := os.Rename(caOut+".tmp", caOut); err != nil {
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
	log.Printf("HTTPS origin on %s, CA in %s", addr, caOut)
	log.Fatal(srv.ListenAndServeTLS("", ""))
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

func config(sites ...*nodev1.Site) *nodev1.NodeConfig {
	return &nodev1.NodeConfig{
		Listeners: []*nodev1.Listener{
			{Port: 80, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTP},
			// Behind a load balancer that speaks the PROXY protocol.
			{Port: 8081, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTP, ProxyProtocol: true},
		},
		CacheZones:         []*nodev1.CacheZone{{Name: "default", MaxSizeMb: 256, KeysZoneMb: 8, InactiveSeconds: 600}},
		Sites:              sites,
		OriginAllowedCidrs: allowList,
	}
}

// baseSites are published in every revision.
func baseSites(origin string) []*nodev1.Site {
	return []*nodev1.Site{
		site("site-demo", "demo.test", origin, 80),
		site("site-loop", "loop.test", "node", 80),
		site("site-forbidden", "forbidden.test", "127.0.0.1", 80),
		site("site-hidden", "hidden.test", "hidden", 80),
		tlsSite("site-tls-ok", "tls-ok.test", "origin.test"),
		tlsSite("site-tls-bad", "tls-bad.test", "wrong.test"),
		keyedSite(origin),
		authSite(origin),
	}
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
	go serveTLSOrigin(*tlsOrigin, *caOut)
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
	c.Publish(config(baseSites(*origin)...))

	tlsCfg, err := c.TLSConfig(strings.Split(*names, ","), []net.IP{net.IPv4(127, 0, 0, 1)})
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: *listen, Handler: c.Handler(), TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /pin", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, c.CA.Pin()) })
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, *token) })
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
