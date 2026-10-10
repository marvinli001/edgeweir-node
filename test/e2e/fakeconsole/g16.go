package main

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

// G16 (access-logs-v2, stats-dims-v1, ADR-0041): the sites, with the base
// site's "cache everything" rule:
//
//	log.g16.test  whoami, every request sampled, with the query string,
//	              the X-Trace-Id header and the connection's peer
//	blk.g16.test  whoami, nothing sampled, blocked requests always logged;
//	              rule g16-block blocks /g16-block
func g16Config(origin string) *nodev1.NodeConfig {
	l := site("site-g16", "log.g16.test", origin, 80)
	l.LogSampleRate = 10000
	l.LogQuery, l.LogPeer, l.LogHeaders = true, true, []string{"x-trace-id"}
	b := site("site-g16b", "blk.g16.test", origin, 80)
	b.LogBlocked = true
	b.Rules = []*nodev1.EdgeRule{{Id: "g16-block", Phase: "waf-custom",
		Expression: &nodev1.RuleExpression{Op: "eq", Field: "http.request.uri.path", ValueType: "string", Value: "/g16-block"},
		Action:     &nodev1.RuleAction{Kind: "block", StatusCode: 403}}}
	cfg := config(append(baseSites(origin), l, b)...)
	cfg.RequiredFeatures = append(cfg.RequiredFeatures, configir.FeatureAccessLogsV2)
	return cfg
}

// g16Handlers: POST /g16 publishes g16Config (?enabled=false: the base
// configuration again); GET /g16/logs lists the access log lines of the
// G16 sites, "<site> <status> <path> key=value ..." (values with spaces
// as "_"); GET /g16/stats the dimensions of the uploaded minutes of the
// G16 sites, one "<site> <dimension> <key> <count>" line per value.
func g16Handlers(mux *http.ServeMux, c *fakeconsole.Console, origin string) {
	mux.HandleFunc("POST /g16", func(w http.ResponseWriter, r *http.Request) {
		cfg := g16Config(origin)
		if r.URL.Query().Get("enabled") == "false" {
			cfg = config(baseSites(origin)...)
		}
		fmt.Fprint(w, c.Publish(cfg))
	})
	word := func(s string) string { return cmpOr(strings.ReplaceAll(s, " ", "_"), "-") }
	mux.HandleFunc("GET /g16/logs", func(w http.ResponseWriter, _ *http.Request) {
		for _, l := range c.Logs() {
			if !strings.HasPrefix(l.GetSiteId(), "site-g16") {
				continue
			}
			var headers []string
			for k, v := range l.GetHeaders() {
				headers = append(headers, k+":"+v)
			}
			slices.Sort(headers)
			fmt.Fprintf(w, "%s %d %s rate=%d ua=%s referer=%s http=%s scheme=%s tls=%s country=%s asn=%d as=%s upstream=%d upstream_addr=%s ms=%d bytes=%d type=%s reason=%s rule=%s query=%s headers=%s peer=%s\n",
				l.GetSiteId(), l.GetStatus(), l.GetPath(), l.GetSampleRate(), word(l.GetUserAgent()), word(l.GetReferer()), word(l.GetHttpVersion()),
				word(l.GetScheme()), word(l.GetTlsVersion()), word(l.GetCountry()), l.GetAsn(), word(l.GetAsName()), l.GetUpstreamStatus(),
				word(l.GetUpstreamAddr()), l.GetUpstreamMs(), l.GetRequestBytes(), word(l.GetContentType()), word(l.GetBlockReason()),
				word(l.GetBlockRuleId()), word(l.GetQuery()), word(strings.Join(headers, ",")), word(l.GetPeerIp()))
		}
	})
	mux.HandleFunc("GET /g16/stats", func(w http.ResponseWriter, _ *http.Request) {
		for _, m := range c.Stats() {
			site := m.GetSiteId()
			if !strings.HasPrefix(site, "site-g16") {
				continue
			}
			for _, x := range m.GetCountries() {
				fmt.Fprintf(w, "%s country %s %d %d\n", site, cmpOr(x.GetCountry(), "-"), x.GetRequests(), x.GetBytesSent())
			}
			for _, x := range m.GetAsns() {
				fmt.Fprintf(w, "%s asn %d_%s %d\n", site, x.GetAsn(), word(x.GetName()), x.GetRequests())
			}
			for _, x := range m.GetReferers() {
				fmt.Fprintf(w, "%s referer %s %d\n", site, x.GetValue(), x.GetCount())
			}
			for name, values := range map[string]map[string]uint64{"browser": m.GetBrowsers(), "os": m.GetOperatingSystems(),
				"device": m.GetDevices(), "http": m.GetHttpVersions(), "tls": m.GetTlsVersions(), "reason": m.GetBlockReasons()} {
				for k, n := range values {
					fmt.Fprintf(w, "%s %s %s %d\n", site, name, k, n)
				}
			}
		}
	})
}
