package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

// g10Site is a site whose requests reach the origin with X-G10-Site: id,
// and with TLS options, so nginx renders its server names (domains-v2).
func g10Site(id, origin string, domains ...*nodev1.Domain) *nodev1.Site {
	s := site(id, "", origin, 80)
	s.Domains = domains
	s.Tls = &nodev1.TlsOptions{MinimumVersion: "1.2", CipherProfile: "modern", Gzip: true, GzipMinLength: 1, GzipTypes: []string{"text/plain"}}
	s.Rules = []*nodev1.EdgeRule{{
		Id: "g10", Phase: "request-transform", Expression: irTrue,
		Action: &nodev1.RuleAction{Kind: "request_header", Header: "x-g10-site", Value: id},
	}}
	return s
}

// g10Config (domains-v2, unknown-host-v1): exact.sfx.test and every
// subdomain of sfx.test go to site-sfx, those of deep.sfx.test to
// site-sfx-deep (the longer suffix), api<digits>.re.test to site-re;
// unknown hosts are closed (444), node IP access goes to site-default,
// scan protection bans after 10 requests in 60 seconds for 60 seconds;
// the subdomains of gone-sfx.test belong to a disabled site.
func g10Config(origin string) *nodev1.NodeConfig {
	suffix, regex := nodev1.DomainMatch_DOMAIN_MATCH_SUFFIX, nodev1.DomainMatch_DOMAIN_MATCH_REGEX
	cfg := config(append(baseSites(origin),
		g10Site("site-sfx", origin, &nodev1.Domain{Name: "exact.sfx.test"}, &nodev1.Domain{Name: "sfx.test", Match: suffix}),
		g10Site("site-sfx-deep", origin, &nodev1.Domain{Name: "deep.sfx.test", Match: suffix}),
		g10Site("site-re", origin, &nodev1.Domain{Name: `api\d+\.re\.test`, Match: regex, Order: 16}),
		g10Site("site-default", origin, &nodev1.Domain{Name: "default.test"}),
	)...)
	cfg.OfflineHosts = append(cfg.OfflineHosts, &nodev1.OfflineHost{Name: "gone-sfx.test", Match: suffix, Reason: "disabled"})
	cfg.UnknownHosts = &nodev1.UnknownHosts{UnknownHost: "close", IpAccess: "site", DefaultSiteId: "site-default", ScanThreshold: 10, ScanBanSeconds: 60}
	cfg.RequiredFeatures = append(cfg.RequiredFeatures, configir.FeatureDomainsV2, configir.FeatureUnknownHost)
	return cfg
}

// g10Handlers: POST /g10 publishes g10Config (?enabled=false: the base
// configuration again); GET /auto-bans lists the automatic bans the node
// reported, "<scope> <site> <cidr> <reason> <metric> <observed>/<threshold>".
func g10Handlers(mux *http.ServeMux, c *fakeconsole.Console, origin string) {
	mux.HandleFunc("POST /g10", func(w http.ResponseWriter, r *http.Request) {
		cfg := g10Config(origin)
		if r.URL.Query().Get("enabled") == "false" {
			cfg = config(baseSites(origin)...)
		}
		fmt.Fprint(w, c.Publish(cfg))
	})
	mux.HandleFunc("GET /auto-bans", func(w http.ResponseWriter, _ *http.Request) {
		for _, b := range c.ReportedBans() {
			scope := strings.ToLower(strings.TrimPrefix(b.GetScope().String(), "BAN_SCOPE_"))
			fmt.Fprintf(w, "%s %s %s %s %s %g/%g\n", scope, cmpOr(b.GetSiteId(), "-"), b.GetCidr(), b.GetReason(), b.GetMetric(), b.GetObserved(), b.GetThreshold())
		}
	})
}
