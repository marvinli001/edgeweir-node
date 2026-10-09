package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

// G14 (waf-v2, rules-body-v1, challenge-v2, ADR-0040): the sites, with the
// base site's "cache everything" rule:
//
//	waf.g14.test  the body echo at console:8096 (POST: "body <length>
//	              <sha256>", GET: the path), OWASP CRS in block mode with
//	              exclusion entries (/g14-excluded/ prefix: 930100, 930110,
//	              942100; exact /g14-target: 942100 for ARGS:id), rules
//	              body limit 65536,
//	              no sampled logs; rules: config crs detect for
//	              /g14-detect, ban /g14-ban, respond /g14-respond (JSON) and
//	              /g14-teapot (the 418 error page), close /g14-close, skip
//	              crs for /g14-skipcrs, a log line for /g14-log, block a
//	              JSON body whose cmd.0 contains "rm", answer 422 for a
//	              truncated body at /g14-upload, rate limit /g14-rl to 2 a
//	              minute with a 60 s ban
//	ch.g14.test   whoami: Under Attack (js) with verified crawlers, the
//	              site's challenge texts, a ban after 3 failed answers
func g14Config(origin string) *nodev1.NodeConfig {
	path := &nodev1.RuleExpression{Op: "field", Field: "http.request.uri.path", ValueType: "string"}
	is := func(p string) *nodev1.RuleExpression {
		return &nodev1.RuleExpression{Op: "eq", Field: "http.request.uri.path", ValueType: "string", Value: p}
	}
	starts := func(p string) *nodev1.RuleExpression { return irCall("starts_with", "boolean", path, irConst(p)) }
	rule := func(id, phase string, e *nodev1.RuleExpression, a *nodev1.RuleAction) *nodev1.EdgeRule {
		return &nodev1.EdgeRule{Id: id, Phase: phase, Expression: e, Action: a}
	}
	w := site("site-g14", "waf.g14.test", "console", 8096)
	w.RulesBodyLimit = 65536
	w.Waf = &nodev1.SiteWaf{Mode: "block", ParanoiaLevel: 1, AnomalyThreshold: 5, RequestBodyLimit: 131072, Exclusions: []*nodev1.WafExclusion{
		// 930100 and 930110 (path traversal) match the "/../" of the
		// requests that reach the prefix only once normalized.
		{Path: "/g14-excluded/", RuleIds: []uint32{930100, 930110, 942100}},
		{Path: "/g14-target", Exact: true, RuleIds: []uint32{942100}, Targets: []string{"ARGS:id"}},
	}}
	w.Rules = []*nodev1.EdgeRule{
		rule("g14-detect", "config", starts("/g14-detect"), &nodev1.RuleAction{Kind: "config", Crs: "detect"}),
		rule("g14-ban", "waf-custom", is("/g14-ban"), &nodev1.RuleAction{Kind: "ban", BanSeconds: 600}),
		rule("g14-respond", "waf-custom", is("/g14-respond"), &nodev1.RuleAction{Kind: "respond", StatusCode: 200, ContentType: "application/json", Body: `{"ok":true}`}),
		rule("g14-teapot", "waf-custom", is("/g14-teapot"), &nodev1.RuleAction{Kind: "respond", StatusCode: 418, ErrorPage: true}),
		rule("g14-close", "waf-custom", is("/g14-close"), &nodev1.RuleAction{Kind: "close"}),
		rule("g14-skipcrs", "waf-custom", starts("/g14-skipcrs"), &nodev1.RuleAction{Kind: "skip", Skip: []string{"crs"}}),
		rule("g14-log", "waf-custom", starts("/g14-log"), &nodev1.RuleAction{Kind: "log", AccessLog: true}),
		rule("g14-json", "waf-custom", &nodev1.RuleExpression{Op: "contains", ValueType: "string", Value: "rm",
			Children: []*nodev1.RuleExpression{irCall("json_value", "string", irConst("cmd.0"))}}, &nodev1.RuleAction{Kind: "block", StatusCode: 403}),
		rule("g14-upload", "waf-custom", &nodev1.RuleExpression{Op: "and", Children: []*nodev1.RuleExpression{
			is("/g14-upload"), {Op: "eq", Field: "http.request.body.truncated", ValueType: "boolean", Value: "true"},
		}}, &nodev1.RuleAction{Kind: "respond", StatusCode: 422, ContentType: "text/plain", Body: "truncated"}),
		rule("g14-rl", "ratelimit", starts("/g14-rl"), &nodev1.RuleAction{Kind: "rate_limit", StatusCode: 429, Limit: 2, WindowSeconds: 60, Key: "ip.src", BanSeconds: 60}),
	}
	ch := site("site-g14c", "ch.g14.test", origin, 80)
	ch.Protection = &nodev1.SiteProtection{UnderAttack: true, UnderAttackChallenge: "js", PassTtlSeconds: 300, AllowVerifiedBots: true,
		ChallengeText:    &nodev1.ChallengeText{TitleZh: "G14 检查", HintZh: "请稍候", TitleEn: "G14 check", HintEn: "One moment <please>"},
		FailureThreshold: 3, FailureBanSeconds: 60}
	cfg := config(append(baseSites(origin), w, ch)...)
	cfg.RequiredFeatures = append(cfg.RequiredFeatures, configir.FeatureWAFV2, configir.FeatureRulesBody, configir.FeatureChallengeV2)
	return cfg
}

// serveBodyEcho answers POST requests with the length and SHA-256 of the
// body it received, other requests with the names of their X-Edgeweir-*
// headers ("header <name>") and their path.
func serveBodyEcho(addr string) {
	// No ServeMux: it would redirect paths with "..", which the CRS checks
	// send as the client wrote them.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			for name := range r.Header {
				if strings.HasPrefix(strings.ToLower(name), "x-edgeweir") {
					fmt.Fprintf(w, "header %s\n", strings.ToLower(name))
				}
			}
			fmt.Fprintf(w, "%s from g14\n", r.URL.Path)
			return
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sum := sha256.Sum256(b)
		fmt.Fprintf(w, "body %d %s\n", len(b), hex.EncodeToString(sum[:]))
	})
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("G14 body echo on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

// g14Handlers: POST /g14 publishes g14Config (?enabled=false: the base
// configuration again); GET /g14/bans lists the reported own bans,
// "<scope> <site> <cidr> <reason> <rule> <observed>/<threshold>"; GET
// /g14/logs the access log lines, "<site> <status> <path> <sample rate>
// <rule ids>".
func g14Handlers(mux *http.ServeMux, c *fakeconsole.Console, origin string) {
	go serveBodyEcho(":8096")
	mux.HandleFunc("POST /g14", func(w http.ResponseWriter, r *http.Request) {
		cfg := g14Config(origin)
		if r.URL.Query().Get("enabled") == "false" {
			cfg = config(baseSites(origin)...)
		}
		fmt.Fprint(w, c.Publish(cfg))
	})
	mux.HandleFunc("GET /g14/bans", func(w http.ResponseWriter, _ *http.Request) {
		for _, b := range c.ReportedBans() {
			scope := strings.ToLower(strings.TrimPrefix(b.GetScope().String(), "BAN_SCOPE_"))
			fmt.Fprintf(w, "%s %s %s %s %s %g/%g\n", scope, cmpOr(b.GetSiteId(), "-"), b.GetCidr(), b.GetReason(),
				cmpOr(b.GetRuleId(), "-"), b.GetObserved(), b.GetThreshold())
		}
	})
	mux.HandleFunc("GET /g14/logs", func(w http.ResponseWriter, _ *http.Request) {
		for _, l := range c.Logs() {
			fmt.Fprintf(w, "%s %d %s %s %s\n", l.GetSiteId(), l.GetStatus(), l.GetPath(), strconv.FormatUint(uint64(l.GetSampleRate()), 10),
				cmpOr(strings.Join(l.GetRuleIds(), ","), "-"))
		}
	})
}
