package main

import (
	"fmt"
	"net/http"
	"slices"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

// G13 (access-control-v1, ADR-0039): the sites, with the base site's
// "cache everything" rule:
//
//	ac.g13.test     (and *.ac.g13.test) whoami: site block list g13-block
//	                (198.51.100.130-131), site allow list g13-allow
//	                (198.51.100.131-132); hotlink protection of .png (empty
//	                referers and the site's own domains pass, 403 otherwise);
//	                user agents *Googlebot* allowed, *BadBot* denied; CORS
//	                for /api/ from https://app.g13.test with credentials,
//	                GET and POST, content-type, X-Total exposed, max age
//	                600; security headers nosniff, X-Frame-Options DENY,
//	                Referrer-Policy no-referrer, Server and X-Powered-By
//	                hidden
//	redir.g13.test  whoami: hotlink protection of .png answered with a 302
//	                to /hotlink.png
//	ws.g13.test     the WebSocket echo at console:8090 (GET /ws?host=
//	                &origin=): upgrades only from http://ws.g13.test, idle
//	                timeout 120 s
var g13Lists = []*nodev1.IpList{
	{Id: "g13-block", Name: "g13 block", Kind: "collection", Entries: []string{"198.51.100.130/31"}},
	{Id: "g13-allow", Name: "g13 allow", Kind: "collection", Entries: []string{"198.51.100.131/32", "198.51.100.132/32"}},
}

// g13Config is the base configuration with the G13 sites.
func g13Config(origin string) *nodev1.NodeConfig {
	ac := site("site-g13", "ac.g13.test", origin, 80)
	ac.Domains = append(ac.Domains, &nodev1.Domain{Name: "ac.g13.test", Wildcard: true})
	ac.AccessControl = &nodev1.AccessControl{
		BlockListIds: []string{"g13-block"},
		AllowListIds: []string{"g13-allow"},
		Hotlink:      &nodev1.Hotlink{AllowEmpty: true, AllowSiteDomains: true, Extensions: []string{"png"}},
		UserAgents: &nodev1.UserAgentRules{Rules: []*nodev1.UserAgentRule{
			{Pattern: "*Googlebot*", Allow: true}, {Pattern: "*BadBot*"},
		}},
		Cors: &nodev1.Cors{
			AllowedOrigins: []string{"https://app.g13.test"}, AllowCredentials: true, AllowedMethods: []string{"GET", "POST"},
			AllowedHeaders: []string{"content-type"}, ExposedHeaders: []string{"X-Total"}, MaxAgeSeconds: 600,
			PathPrefixes: []string{"/api/"},
		},
		SecurityHeaders: &nodev1.SecurityHeaders{Nosniff: true, FrameOptions: "DENY", ReferrerPolicy: "no-referrer", HideServer: true, RemovePoweredBy: true},
	}
	redir := site("site-g13r", "redir.g13.test", origin, 80)
	redir.AccessControl = &nodev1.AccessControl{Hotlink: &nodev1.Hotlink{Extensions: []string{"png"}, RedirectUrl: "/hotlink.png"}}
	ws := site("site-g13w", "ws.g13.test", "console", 8090)
	ws.AccessControl = &nodev1.AccessControl{Websocket: &nodev1.WebSocketAccess{Origins: []string{"http://ws.g13.test"}, IdleTimeoutSeconds: 120}}
	cfg := config(append(baseSites(origin), ac, redir, ws)...)
	cfg.IpLists = append(slices.Clone(cfg.IpLists), g13Lists...)
	cfg.RequiredFeatures = append(cfg.RequiredFeatures, configir.FeatureAccessControl)
	return cfg
}

// g13Handlers: POST /g13 publishes g13Config (?enabled=false: the base
// configuration again).
func g13Handlers(mux *http.ServeMux, c *fakeconsole.Console, origin string) {
	mux.HandleFunc("POST /g13", func(w http.ResponseWriter, r *http.Request) {
		cfg := g13Config(origin)
		if r.URL.Query().Get("enabled") == "false" {
			cfg = config(baseSites(origin)...)
		}
		fmt.Fprint(w, c.Publish(cfg))
	})
}
