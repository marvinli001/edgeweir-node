package configir

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// g14Config is the v0.29.0 vector, canonical, after change.
func g14Config(t *testing.T, change func(c *nodev1.NodeConfig, a *nodev1.Site)) *nodev1.NodeConfig {
	t.Helper()
	cfg, _ := v0290Vector(t)
	Canonicalize(cfg)
	if change != nil {
		change(cfg, vectorSite(cfg, "a"))
	}
	return cfg
}

func buildG14(cfg *nodev1.NodeConfig) (*Plan, error) {
	return Build(cfg, Options{ExtraFeatures: []string{FeatureModSecurity}})
}

func TestG14FeaturesSupported(t *testing.T) {
	for _, f := range []string{"waf-v2", "rules-body-v1", "challenge-v2"} {
		if !slices.Contains(SupportedFeatures, f) {
			t.Errorf("SupportedFeatures lacks %s: %v", f, SupportedFeatures)
		}
	}
}

// TestBodyArgumentVectors runs the console's form name and JSON path
// vectors (test/lua/body_vectors.json) against the validators.
func TestBodyArgumentVectors(t *testing.T) {
	raw, err := os.ReadFile("../../test/lua/body_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Form []struct {
			Input string `json:"input"`
			Valid bool   `json:"valid"`
		} `json:"validFormName"`
		Path []struct {
			Input string `json:"input"`
			Valid bool   `json:"valid"`
		} `json:"validJsonPath"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Form) == 0 || len(v.Path) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range v.Form {
		if validFormName(c.Input) != c.Valid {
			t.Errorf("validFormName(%q) != %v", c.Input, c.Valid)
		}
	}
	for _, c := range v.Path {
		if validJSONPath(c.Input) != c.Valid {
			t.Errorf("validJSONPath(%q) != %v", c.Input, c.Valid)
		}
	}
}

func bodyCall(name, arg string) *nodev1.RuleExpression {
	return &nodev1.RuleExpression{Op: "eq", ValueType: "string", Value: "x", Children: []*nodev1.RuleExpression{
		{Op: "call", Field: name, ValueType: "string", Children: []*nodev1.RuleExpression{{Op: "const", ValueType: "string", Value: arg}}},
	}}
}

// TestRequestOnlyFields: the body and crawler fields and the body
// functions only in the request phases, not in cache rule conditions.
func TestRequestOnlyFields(t *testing.T) {
	exprs := map[string]*nodev1.RuleExpression{
		"size":      {Op: "gt", Field: "http.request.body.size", ValueType: "number", Value: "1"},
		"raw":       {Op: "contains", Field: "http.request.body.raw", ValueType: "string", Value: "x"},
		"truncated": {Op: "eq", Field: "http.request.body.truncated", ValueType: "boolean", Value: "true"},
		"filenames": {Op: "contains", Field: "http.request.body.filenames", ValueType: "string", Value: ".php"},
		"verified":  {Op: "eq", Field: "http.request.bot.verified", ValueType: "boolean", Value: "true"},
		"bot name":  {Op: "eq", Field: "http.request.bot.name", ValueType: "string", Value: "googlebot"},
		"form":      bodyCall("form_value", "user"),
		"json":      bodyCall("json_value", "a.b.0"),
	}
	for name, e := range exprs {
		for _, phase := range rulePhases {
			err := validateCondition(e, phase, nil, nil)
			if want := slices.Contains(requestPhases, phase); (err == nil) != want {
				t.Errorf("%s in %s: %v", name, phase, err)
			}
		}
		site := &nodev1.Site{Id: "s", CacheRules: []*nodev1.CacheRule{{Id: "c", Match: &nodev1.CacheRuleMatch{Condition: e}}}}
		if validateCacheRuleConditions(site, nil, nil) == nil {
			t.Errorf("%s accepted in a cache rule condition", name)
		}
	}
	// Value expressions: form_value in a redirect target, not in a
	// response header.
	value := &nodev1.RuleExpression{Op: "call", Field: "form_value", ValueType: "string", Children: []*nodev1.RuleExpression{{Op: "const", ValueType: "string", Value: "next"}}}
	if err := validateValueExpression(value, "redirect", nil); err != nil {
		t.Error(err)
	}
	if validateValueExpression(value, "response-transform", nil) == nil {
		t.Error("form_value accepted in a response phase")
	}
	for name, e := range map[string]*nodev1.RuleExpression{
		"field argument": {Op: "eq", ValueType: "string", Value: "x", Children: []*nodev1.RuleExpression{
			{Op: "call", Field: "form_value", ValueType: "string", Children: []*nodev1.RuleExpression{{Op: "field", Field: "http.host", ValueType: "string"}}},
		}},
		"empty name":         bodyCall("form_value", ""),
		"control name":       bodyCall("form_value", "a\x01"),
		"long name":          bodyCall("form_value", strings.Repeat("n", 257)),
		"empty segment":      bodyCall("json_value", "a..b"),
		"leading dot":        bodyCall("json_value", ".a"),
		"33 segments":        bodyCall("json_value", strings.Repeat("a.", 32)+"a"),
		"two arguments":      {Op: "eq", ValueType: "string", Value: "x", Children: []*nodev1.RuleExpression{{Op: "call", Field: "json_value", ValueType: "string", Children: []*nodev1.RuleExpression{{Op: "const", ValueType: "string", Value: "a"}, {Op: "const", ValueType: "string", Value: "b"}}}}},
		"number result":      {Op: "eq", ValueType: "number", Value: "1", Children: []*nodev1.RuleExpression{{Op: "call", Field: "json_value", ValueType: "number", Children: []*nodev1.RuleExpression{{Op: "const", ValueType: "string", Value: "a"}}}}},
		"unknown body field": {Op: "eq", Field: "http.request.body", ValueType: "string", Value: "x"},
	} {
		if validateCondition(e, "waf-custom", nil, nil) == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if validateCondition(bodyCall("form_value", strings.Repeat("n", 256)), "waf-custom", nil, nil) != nil ||
		validateCondition(bodyCall("json_value", strings.Repeat("a.", 31)+"a"), "waf-custom", nil, nil) != nil {
		t.Error("the longest name or path refused")
	}
	// Body fields are no rate limit keys.
	rate := &nodev1.RuleAction{Kind: "rate_limit", StatusCode: 429, Limit: 1, WindowSeconds: 1, Key: "http.request.body.raw"}
	if validAction(rate, "ratelimit", nil, false) {
		t.Error("a body field as a rate limit key")
	}
}

// TestWAFV2Actions: the platform scope of bans in platform rules only, and
// every action in waf-custom only.
func TestWAFV2Actions(t *testing.T) {
	if _, err := buildG14(g14Config(t, nil)); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(c *nodev1.NodeConfig, a *nodev1.Site){
		"site rule at platform scope": func(_ *nodev1.NodeConfig, a *nodev1.Site) {
			vectorRule(a.Rules, "r-ban").Action.BanScope = BanScopePlatform
		},
		"platform rule with an unknown scope": func(c *nodev1.NodeConfig, _ *nodev1.Site) { c.PlatformRules[0].Action.BanScope = "global" },
		"ban too short":                       func(_ *nodev1.NodeConfig, a *nodev1.Site) { vectorRule(a.Rules, "r-ban").Action.BanSeconds = 59 },
		"ban prefix /15":                      func(_ *nodev1.NodeConfig, a *nodev1.Site) { vectorRule(a.Rules, "r-ban").Action.BanPrefixV4 = 15 },
		"ban in config": func(_ *nodev1.NodeConfig, a *nodev1.Site) {
			r := vectorRule(a.Rules, "r-crs")
			r.Action = &nodev1.RuleAction{Kind: "ban", BanSeconds: 600}
		},
		"close in ratelimit": func(_ *nodev1.NodeConfig, a *nodev1.Site) {
			vectorRule(a.Rules, "r-rate").Action = &nodev1.RuleAction{Kind: "close"}
		},
		"respond with a status code of 302": func(_ *nodev1.NodeConfig, a *nodev1.Site) {
			vectorRule(a.Rules, "r-respond").Action.StatusCode = 302
		},
		"respond with a control character": func(_ *nodev1.NodeConfig, a *nodev1.Site) {
			vectorRule(a.Rules, "r-respond").Action.Body = "a\x00b"
		},
		"respond 8193 bytes": func(_ *nodev1.NodeConfig, a *nodev1.Site) {
			vectorRule(a.Rules, "r-respond").Action.Body = strings.Repeat("x", 8193)
		},
		"error page with a type": func(_ *nodev1.NodeConfig, a *nodev1.Site) {
			vectorRule(a.Rules, "r-page").Action.ContentType = "text/plain"
		},
		"unsorted skip": func(_ *nodev1.NodeConfig, a *nodev1.Site) {
			vectorRule(a.Rules, "r-skip").Action.Skip = []string{"rules", "crs"}
		},
		"skip nothing":   func(_ *nodev1.NodeConfig, a *nodev1.Site) { vectorRule(a.Rules, "r-skip").Action.Skip = nil },
		"access log":     func(_ *nodev1.NodeConfig, a *nodev1.Site) { vectorRule(a.Rules, "r-respond").Action.AccessLog = true },
		"rate limit ban": func(_ *nodev1.NodeConfig, a *nodev1.Site) { vectorRule(a.Rules, "r-rate").Action.BanSeconds = 86401 },
		"crs on":         func(_ *nodev1.NodeConfig, a *nodev1.Site) { vectorRule(a.Rules, "r-crs").Action.Crs = "on" },
		"crs in cache": func(_ *nodev1.NodeConfig, a *nodev1.Site) {
			r := vectorRule(a.Rules, "r-crs")
			r.Phase = "cache"
			r.Action = &nodev1.RuleAction{Kind: "config", CacheBypass: proto.Bool(true), Crs: "off"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildG14(g14Config(t, change)); !errors.Is(err, ErrRejected) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	ok := map[string]*nodev1.RuleAction{
		"ban /16 /48":       {Kind: "ban", BanSeconds: 604800, BanPrefixV4: 16, BanPrefixV6: 48},
		"respond 204":       {Kind: "respond", StatusCode: 204, ContentType: "text/plain"},
		"respond text":      {Kind: "respond", StatusCode: 503, ContentType: "text/html", Body: "<p>a\tb\r\n</p>"},
		"respond 8192":      {Kind: "respond", StatusCode: 200, ContentType: "text/plain", Body: strings.Repeat("x", 8192)},
		"skip every target": {Kind: "skip", Skip: slices.Clone(skipTargets)},
		"close":             {Kind: "close"},
		"log":               {Kind: "log", AccessLog: true},
	}
	for name, a := range ok {
		if !validAction(a, "waf-custom", nil, false) {
			t.Errorf("%s refused", name)
		}
	}
	if !validAction(&nodev1.RuleAction{Kind: "ban", BanSeconds: 60, BanScope: BanScopePlatform}, "waf-custom", nil, true) {
		t.Error("platform scope refused in a platform rule")
	}
}

func TestRulesBodyLimit(t *testing.T) {
	for limit, ok := range map[uint32]bool{0: true, 1024: true, 65536: true, 1 << 20: true, 1023: false, 1<<20 + 1: false, 1: false} {
		cfg := g14Config(t, func(_ *nodev1.NodeConfig, a *nodev1.Site) { a.RulesBodyLimit = limit })
		p, err := buildG14(cfg)
		if (err == nil) != ok {
			t.Errorf("rules body limit %d: %v", limit, err)
			continue
		}
		if ok && planSite(t, p, "a").RulesBodyLimit != limit {
			t.Errorf("rules body limit %d: plan %d", limit, planSite(t, p, "a").RulesBodyLimit)
		}
		if ok {
			raw, _ := json.Marshal(planSite(t, p, "a"))
			if has := strings.Contains(string(raw), `"rules_body_limit":`); has != (limit != 0) {
				t.Errorf("rules body limit %d in the site table: %v", limit, has)
			}
		}
	}
}

func TestWAFExclusions(t *testing.T) {
	ids := func(n int) []uint32 {
		out := make([]uint32, n)
		for i := range out {
			out[i] = 920000 + uint32(i)
		}
		return out
	}
	set := func(e ...*nodev1.WafExclusion) func(*nodev1.NodeConfig, *nodev1.Site) {
		return func(_ *nodev1.NodeConfig, a *nodev1.Site) { a.Waf.Exclusions = e }
	}
	for name, test := range map[string]struct {
		change func(*nodev1.NodeConfig, *nodev1.Site)
		ok     bool
	}{
		"none":               {set(), true},
		"path prefix":        {set(&nodev1.WafExclusion{Path: "/a/中文", RuleIds: []uint32{942100}}), true},
		"200 rule ids":       {set(&nodev1.WafExclusion{Path: "/", RuleIds: ids(200)}), true},
		"201 rule ids":       {set(&nodev1.WafExclusion{Path: "/", RuleIds: ids(201)}), false},
		"no rule id":         {set(&nodev1.WafExclusion{Path: "/"}), false},
		"unsorted rule ids":  {set(&nodev1.WafExclusion{Path: "/", RuleIds: []uint32{942100, 941100}}), false},
		"duplicate rule ids": {set(&nodev1.WafExclusion{Path: "/", RuleIds: []uint32{942100, 942100}}), false},
		"rule id 899999":     {set(&nodev1.WafExclusion{Path: "/", RuleIds: []uint32{899999}}), false},
		"rule id 1000000":    {set(&nodev1.WafExclusion{Path: "/", RuleIds: []uint32{1000000}}), false},
		"evaluation 949110":  {set(&nodev1.WafExclusion{Path: "/", RuleIds: []uint32{949110}}), false},
		"evaluation 901100":  {set(&nodev1.WafExclusion{Path: "/", RuleIds: []uint32{901100}}), false},
		"evaluation 959100":  {set(&nodev1.WafExclusion{Path: "/", RuleIds: []uint32{959100}}), false},
		"evaluation 980170":  {set(&nodev1.WafExclusion{Path: "/", RuleIds: []uint32{980170}}), false},
		"relative path":      {set(&nodev1.WafExclusion{Path: "api/", RuleIds: []uint32{942100}}), false},
		"query":              {set(&nodev1.WafExclusion{Path: "/a?b", RuleIds: []uint32{942100}}), false},
		"fragment":           {set(&nodev1.WafExclusion{Path: "/a#b", RuleIds: []uint32{942100}}), false},
		"space":              {set(&nodev1.WafExclusion{Path: "/a b", RuleIds: []uint32{942100}}), false},
		"no-break space":     {set(&nodev1.WafExclusion{Path: "/a b", RuleIds: []uint32{942100}}), false},
		"ideographic space":  {set(&nodev1.WafExclusion{Path: "/a　b", RuleIds: []uint32{942100}}), false},
		"control":            {set(&nodev1.WafExclusion{Path: "/a\x7fb", RuleIds: []uint32{942100}}), false},
		"1024 bytes":         {set(&nodev1.WafExclusion{Path: "/" + strings.Repeat("a", 1023), RuleIds: []uint32{942100}}), true},
		"1025 bytes":         {set(&nodev1.WafExclusion{Path: "/" + strings.Repeat("a", 1024), RuleIds: []uint32{942100}}), false},
		"targets": {set(&nodev1.WafExclusion{RuleIds: []uint32{942100}, Targets: []string{
			"ARGS:a.b-c_d[e]", "REQUEST_COOKIES:sid", "REQUEST_HEADERS:X-Token"}}), true},
		"unsorted targets": {set(&nodev1.WafExclusion{RuleIds: []uint32{942100}, Targets: []string{"REQUEST_COOKIES:sid", "ARGS:a"}}), false},
		"header with dot":  {set(&nodev1.WafExclusion{RuleIds: []uint32{942100}, Targets: []string{"REQUEST_HEADERS:x.y"}}), false},
		"other collection": {set(&nodev1.WafExclusion{RuleIds: []uint32{942100}, Targets: []string{"ARGS_NAMES:a"}}), false},
		"name of 65":       {set(&nodev1.WafExclusion{RuleIds: []uint32{942100}, Targets: []string{"ARGS:" + strings.Repeat("a", 65)}}), false},
		"comma":            {set(&nodev1.WafExclusion{RuleIds: []uint32{942100}, Targets: []string{"ARGS:a,b"}}), false},
		"whole collection": {set(&nodev1.WafExclusion{RuleIds: []uint32{942100}, Targets: []string{"ARGS"}}), false},
		"17 targets": {func(_ *nodev1.NodeConfig, a *nodev1.Site) {
			e := &nodev1.WafExclusion{RuleIds: []uint32{942100}}
			for i := range 17 {
				e.Targets = append(e.Targets, "ARGS:a"+string(rune('a'+i)))
			}
			a.Waf.Exclusions = []*nodev1.WafExclusion{e}
		}, false},
		"101 exclusions": {func(_ *nodev1.NodeConfig, a *nodev1.Site) {
			a.Waf.Exclusions = nil
			for range 101 {
				a.Waf.Exclusions = append(a.Waf.Exclusions, &nodev1.WafExclusion{Path: "/", RuleIds: []uint32{942100}})
			}
		}, false},
	} {
		_, err := buildG14(g14Config(t, test.change))
		if (err == nil) != test.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A site without the CRS: exclusions of a disabled CRS are not checked.
	if _, err := buildG14(g14Config(t, func(_ *nodev1.NodeConfig, a *nodev1.Site) { a.Waf = nil })); err != nil {
		t.Error(err)
	}
}

// TestWAFExclusionToken: the token is the same for the same content and
// differs for any other site, path, match, rule or target.
func TestWAFExclusionToken(t *testing.T) {
	base := WAFExclusionToken("a", "/api/", false, []uint32{941100, 942100}, []string{"ARGS:q"})
	if len(base) != 16 || strings.Trim(base, "0123456789abcdef") != "" {
		t.Fatalf("token %q", base)
	}
	if again := WAFExclusionToken("a", "/api/", false, []uint32{941100, 942100}, []string{"ARGS:q"}); again != base {
		t.Fatal("token not deterministic")
	}
	for name, other := range map[string]string{
		"site":    WAFExclusionToken("b", "/api/", false, []uint32{941100, 942100}, []string{"ARGS:q"}),
		"path":    WAFExclusionToken("a", "/api", false, []uint32{941100, 942100}, []string{"ARGS:q"}),
		"exact":   WAFExclusionToken("a", "/api/", true, []uint32{941100, 942100}, []string{"ARGS:q"}),
		"rule":    WAFExclusionToken("a", "/api/", false, []uint32{941100}, []string{"ARGS:q"}),
		"target":  WAFExclusionToken("a", "/api/", false, []uint32{941100, 942100}, nil),
		"joined":  WAFExclusionToken("a", "/api/", false, []uint32{9411009, 42100}, []string{"ARGS:q"}),
		"shifted": WAFExclusionToken("a/", "api/", false, []uint32{941100, 942100}, []string{"ARGS:q"}),
	} {
		if other == base {
			t.Errorf("%s does not change the token", name)
		}
	}
	// The site table carries path, match and token; rule ids and targets
	// only go to the ModSecurity configuration.
	p, err := buildG14(g14Config(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(planSite(t, p, "a").WAF)
	var got struct {
		Exclusions []map[string]any `json:"exclusions"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Exclusions) != 3 || got.Exclusions[1]["path"] != "/login" || got.Exclusions[1]["exact"] != true ||
		got.Exclusions[1]["token"] != p.Sites[0].WAF.Exclusions[1].Token || len(got.Exclusions[0]) != 2 {
		t.Fatalf("site table exclusions %s", raw)
	}
	if strings.Contains(string(raw), "942100") || strings.Contains(string(raw), "ARGS") {
		t.Fatalf("rule ids or targets in the site table: %s", raw)
	}
}

func TestChallengeV2Protection(t *testing.T) {
	for name, test := range map[string]struct {
		change func(*nodev1.SiteProtection)
		ok     bool
	}{
		"off":                {func(p *nodev1.SiteProtection) { p.FailureThreshold, p.FailureBanSeconds = 0, 0 }, true},
		"off with a ban":     {func(p *nodev1.SiteProtection) { p.FailureThreshold, p.FailureBanSeconds = 0, 600 }, true},
		"off, 59 s":          {func(p *nodev1.SiteProtection) { p.FailureThreshold, p.FailureBanSeconds = 0, 59 }, false},
		"threshold 2":        {func(p *nodev1.SiteProtection) { p.FailureThreshold = 2 }, false},
		"threshold 3":        {func(p *nodev1.SiteProtection) { p.FailureThreshold = 3 }, true},
		"threshold 100":      {func(p *nodev1.SiteProtection) { p.FailureThreshold = 100 }, true},
		"threshold 101":      {func(p *nodev1.SiteProtection) { p.FailureThreshold = 101 }, false},
		"no ban":             {func(p *nodev1.SiteProtection) { p.FailureBanSeconds = 0 }, false},
		"ban 59":             {func(p *nodev1.SiteProtection) { p.FailureBanSeconds = 59 }, false},
		"ban 86400":          {func(p *nodev1.SiteProtection) { p.FailureBanSeconds = 86400 }, true},
		"ban 86401":          {func(p *nodev1.SiteProtection) { p.FailureBanSeconds = 86401 }, false},
		"200 characters":     {func(p *nodev1.SiteProtection) { p.ChallengeText.TitleZh = strings.Repeat("验", 200) }, true},
		"201 characters":     {func(p *nodev1.SiteProtection) { p.ChallengeText.HintEn = strings.Repeat("a", 201) }, false},
		"control character":  {func(p *nodev1.SiteProtection) { p.ChallengeText.HintZh = "a\nb" }, false},
		"delete character":   {func(p *nodev1.SiteProtection) { p.ChallengeText.TitleEn = "a\x7f" }, false},
		"markup is accepted": {func(p *nodev1.SiteProtection) { p.ChallengeText.TitleEn = `<b>"x" & 'y'</b>` }, true},
	} {
		cfg := g14Config(t, func(_ *nodev1.NodeConfig, a *nodev1.Site) { test.change(a.Protection) })
		if _, err := buildG14(cfg); (err == nil) != test.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
	p, err := buildG14(g14Config(t, func(_ *nodev1.NodeConfig, a *nodev1.Site) {
		a.Protection.FailureThreshold, a.Protection.FailureBanSeconds = 0, 600
		a.Protection.ChallengeText = &nodev1.ChallengeText{}
	}))
	if err != nil {
		t.Fatal(err)
	}
	pr := planSite(t, p, "a").Protection
	if pr.FailureThreshold != 0 || pr.FailureBanSeconds != 0 || pr.ChallengeText != nil {
		t.Fatalf("protection %+v", pr)
	}
	raw, _ := json.Marshal(pr)
	for _, key := range []string{"failure_threshold", "failure_ban_seconds", "challenge_text"} {
		if strings.Contains(string(raw), key) {
			t.Errorf("%s in the site table without it: %s", key, raw)
		}
	}
	p, _ = buildG14(g14Config(t, nil))
	raw, _ = json.Marshal(planSite(t, p, "a").Protection)
	for _, want := range []string{`"allow_verified_bots":true`, `"challenge_text":{"title_zh":"访问验证"`, `"title_en":"Checking your browser"}`, `"failure_threshold":5`, `"failure_ban_seconds":900`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("site table protection lacks %s: %s", want, raw)
		}
	}
}
