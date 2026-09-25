// Command fakeconsole serves the fake NodeService used by the container
// smoke test (test/e2e). It is not part of any release artifact.
//
// It publishes one site (demo.test -> whoami:80, cache everything for 60s)
// and exposes a plain-HTTP helper API for the test script:
//
//	GET /pin      internal CA pin (--ca-sha256)
//	GET /token    single-use enrollment token
//	GET /applied  "<applied_revision> <state>" from the last ReportStatus
//	GET /stats    number of uploaded MinuteStats buckets
//	POST /publish publish a new revision adding site demo2.test
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/edgeweir/edgeweir-node/internal/configir"
	nodev1 "github.com/edgeweir/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/edgeweir/edgeweir-node/internal/testutil/fakeconsole"
)

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

func config(sites ...*nodev1.Site) *nodev1.NodeConfig {
	return &nodev1.NodeConfig{
		Listeners:  []*nodev1.Listener{{Port: 80, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTP}},
		CacheZones: []*nodev1.CacheZone{{Name: "default", MaxSizeMb: 256, KeysZoneMb: 8, InactiveSeconds: 600}},
		Sites:      sites,
	}
}

func main() {
	listen := flag.String("listen", ":8443", "NodeService (TLS) address")
	helper := flag.String("helper", ":8081", "plain HTTP helper API for the test script")
	names := flag.String("dns-names", "console,localhost", "TLS certificate DNS names")
	origin := flag.String("origin", "whoami", "origin address")
	token := flag.String("token", "e2e-token", "enrollment token")
	flag.Parse()

	c, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-e2e", ClusterID: "cluster-e2e", NodeName: "edge-e2e", ReportInterval: 2})
	if err != nil {
		log.Fatal(err)
	}
	c.AddToken(*token)
	c.Publish(config(site("site-demo", "demo.test", *origin, 80)))

	tlsCfg, err := c.TLSConfig(strings.Split(*names, ","), []net.IP{net.IPv4(127, 0, 0, 1)})
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: *listen, Handler: c.Handler(), TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /pin", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, c.CA.Pin()) })
	mux.HandleFunc("GET /token", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, *token) })
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
		rev := c.Publish(config(site("site-demo", "demo.test", *origin, 80), site("site-demo2", "demo2.test", *origin, 80)))
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
