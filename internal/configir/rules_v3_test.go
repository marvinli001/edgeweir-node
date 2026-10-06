package configir

import (
	"errors"
	"slices"
	"strings"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func irNumber(v string) *nodev1.RuleExpression {
	return &nodev1.RuleExpression{Op: "const", ValueType: "number", Value: v}
}

func TestExpressionsV3(t *testing.T) {
	asn := []string{"geoip-asn-v1"}
	conditions := map[string]struct {
		e        *nodev1.RuleExpression
		phase    string
		features []string
		ok       bool
	}{
		"cookie":                  {&nodev1.RuleExpression{Op: "eq", Field: "http.request.cookies.role", ValueType: "string", Value: "admin"}, "waf-custom", nil, true},
		"cookie name case":        {&nodev1.RuleExpression{Op: "eq", Field: "http.request.cookies.Session_ID", ValueType: "string"}, "waf-custom", nil, true},
		"cookie name token":       {&nodev1.RuleExpression{Op: "eq", Field: "http.request.cookies.a b", ValueType: "string"}, "waf-custom", nil, false},
		"cookie without name":     {&nodev1.RuleExpression{Op: "eq", Field: "http.request.cookies.", ValueType: "string"}, "waf-custom", nil, false},
		"arg":                     {&nodev1.RuleExpression{Op: "eq", Field: "http.request.uri.args.a[]", ValueType: "string", Value: "1"}, "waf-custom", nil, true},
		"arg with &":              {&nodev1.RuleExpression{Op: "eq", Field: "http.request.uri.args.a&b", ValueType: "string"}, "waf-custom", nil, false},
		"arg with =":              {&nodev1.RuleExpression{Op: "eq", Field: "http.request.uri.args.a=b", ValueType: "string"}, "waf-custom", nil, false},
		"arg typed number":        {&nodev1.RuleExpression{Op: "eq", Field: "http.request.uri.args.a", ValueType: "number", Value: "1"}, "waf-custom", nil, false},
		"version":                 {&nodev1.RuleExpression{Op: "eq", Field: "http.request.version", ValueType: "string", Value: "HTTP/2.0"}, "waf-custom", nil, true},
		"timestamp":               {&nodev1.RuleExpression{Op: "ge", Field: "http.request.timestamp.sec", ValueType: "number", Value: "1700000000"}, "waf-custom", nil, true},
		"server port":             {&nodev1.RuleExpression{Op: "in", Field: "edge.server_port", ValueType: "number", Values: []string{"80", "443"}}, "waf-custom", nil, true},
		"as name":                 {&nodev1.RuleExpression{Op: "contains", Field: "ip.geoip.as_name", ValueType: "string", Value: "Cloud"}, "waf-custom", asn, true},
		"as name without ASN":     {&nodev1.RuleExpression{Op: "contains", Field: "ip.geoip.as_name", ValueType: "string", Value: "Cloud"}, "waf-custom", nil, false},
		"cache status":            {&nodev1.RuleExpression{Op: "eq", Field: "http.response.cache_status", ValueType: "string", Value: "HIT"}, "response-transform", nil, true},
		"cache status early":      {&nodev1.RuleExpression{Op: "eq", Field: "http.response.cache_status", ValueType: "string", Value: "HIT"}, "origin", nil, false},
		"wildcard":                {&nodev1.RuleExpression{Op: "wildcard", Field: "http.user_agent", ValueType: "string", Value: "*curl*"}, "waf-custom", nil, true},
		"strict wildcard":         {&nodev1.RuleExpression{Op: "strict_wildcard", Field: "http.referer", ValueType: "string", Value: "https://*.a.test/*"}, "waf-custom", nil, true},
		"wildcard on a call":      {irCompare("wildcard", "string", "*.test", irCall("lower", "string", irHost)), "waf-custom", nil, true},
		"wildcard on a number":    {&nodev1.RuleExpression{Op: "wildcard", Field: "edge.server_port", ValueType: "number", Value: "8*"}, "waf-custom", nil, false},
		"wildcard escape":         {&nodev1.RuleExpression{Op: "wildcard", Field: "http.host", ValueType: "string", Value: `a\b`}, "waf-custom", nil, false},
		"nine wildcards":          {&nodev1.RuleExpression{Op: "wildcard", Field: "http.host", ValueType: "string", Value: strings.Repeat("*", 9)}, "waf-custom", nil, false},
		"wildcard too long":       {&nodev1.RuleExpression{Op: "wildcard", Field: "http.host", ValueType: "string", Value: strings.Repeat("a", 1025)}, "waf-custom", nil, false},
		"strict other":            {&nodev1.RuleExpression{Op: "strict_contains", Field: "http.host", ValueType: "string", Value: "a"}, "waf-custom", nil, false},
		"md5":                     {irCompare("eq", "string", "x", irCall("md5", "string", irPath)), "waf-custom", nil, true},
		"sha256 of ip":            {irCompare("eq", "string", "x", irCall("sha256", "string", irField("ip.src", "ip"))), "waf-custom", nil, false},
		"to_string ip":            {irCompare("eq", "string", "x", irCall("to_string", "string", irField("ip.src", "ip"))), "waf-custom", nil, true},
		"to_string boolean call":  {irCompare("eq", "string", "true", irCall("to_string", "string", irCall("starts_with", "boolean", irPath, irConst("/")))), "waf-custom", nil, true},
		"to_string of two":        {irCompare("eq", "string", "x", irCall("to_string", "string", irPath, irPath)), "waf-custom", nil, false},
		"to_string returns":       {irCompare("eq", "number", "1", irCall("to_string", "number", irPath)), "waf-custom", nil, false},
		"substring":               {irCompare("eq", "string", "/a", irCall("substring", "string", irPath, irNumber("0"), irNumber("2"))), "waf-custom", nil, true},
		"substring negative":      {irCompare("eq", "string", ".js", irCall("substring", "string", irPath, irNumber("-3"))), "waf-custom", nil, true},
		"substring bounds":        {irCompare("eq", "string", "", irCall("substring", "string", irPath, irNumber("-65536"), irNumber("65536"))), "waf-custom", nil, true},
		"substring start range":   {irCompare("eq", "string", "", irCall("substring", "string", irPath, irNumber("65537"))), "waf-custom", nil, false},
		"substring negative len":  {irCompare("eq", "string", "", irCall("substring", "string", irPath, irNumber("0"), irNumber("-1"))), "waf-custom", nil, false},
		"substring string start":  {irCompare("eq", "string", "", irCall("substring", "string", irPath, irConst("1"))), "waf-custom", nil, false},
		"substring field start":   {irCompare("eq", "string", "", irCall("substring", "string", irPath, irField("edge.server_port", "number"))), "waf-custom", nil, false},
		"substring not canonical": {irCompare("eq", "string", "", irCall("substring", "string", irPath, irNumber("01"))), "waf-custom", nil, false},
		"number elsewhere":        {irCompare("eq", "string", "", irCall("concat", "string", irPath, irNumber("1"))), "waf-custom", nil, false},
		"number const condition":  {&nodev1.RuleExpression{Op: "eq", ValueType: "number", Value: "1", Children: []*nodev1.RuleExpression{irNumber("1")}}, "waf-custom", nil, false},
	}
	for name, tc := range conditions {
		t.Run(name, func(t *testing.T) {
			err := validateCondition(tc.e, tc.phase, nil, tc.features)
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v err=%v", tc.ok, err)
			}
			if err != nil && !errors.Is(err, ErrRejected) {
				t.Fatalf("not ErrRejected: %v", err)
			}
		})
	}
}

func TestRuleActionsV3(t *testing.T) {
	country := irField("ip.geoip.country", "string")
	cacheStatus := irField("http.response.cache_status", "string")
	param := func(name, value string, e *nodev1.RuleExpression) []*nodev1.QueryParam {
		return []*nodev1.QueryParam{{Name: name, Value: value, Expression: e}}
	}
	features := []string{"geoip-country-v1"}
	cases := map[string]struct {
		phase string
		a     *nodev1.RuleAction
		ok    bool
	}{
		"request header target":       {"origin", &nodev1.RuleAction{Kind: "request_header", Header: "x-client-country", Target: country}, true},
		"request header in transform": {"request-transform", &nodev1.RuleAction{Kind: "request_header", Header: "x-req", Target: irField("http.request.id", "string")}, true},
		"response header target":      {"response-transform", &nodev1.RuleAction{Kind: "response_header", Header: "x-cache-status", Target: cacheStatus}, true},
		"response header append":      {"response-transform", &nodev1.RuleAction{Kind: "response_header", Header: "link", Value: "</a.css>; rel=preload", Append: true}, true},
		"append computed":             {"response-transform", &nodev1.RuleAction{Kind: "response_header", Header: "link", Target: irConst("<b>"), Append: true}, true},
		"append on request header":    {"request-transform", &nodev1.RuleAction{Kind: "request_header", Header: "x-a", Value: "a", Append: true}, false},
		"append and remove":           {"response-transform", &nodev1.RuleAction{Kind: "response_header", Header: "link", Remove: true, Append: true}, false},
		"target and remove":           {"response-transform", &nodev1.RuleAction{Kind: "response_header", Header: "x-a", Remove: true, Target: irConst("x")}, false},
		"target and value":            {"request-transform", &nodev1.RuleAction{Kind: "request_header", Header: "x-a", Value: "a", Target: irConst("b")}, false},
		"boolean target":              {"request-transform", &nodev1.RuleAction{Kind: "request_header", Header: "x-a", Target: irCall("starts_with", "boolean", irPath, irConst("/"))}, false},
		"response field too early":    {"origin", &nodev1.RuleAction{Kind: "request_header", Header: "x-a", Target: cacheStatus}, false},
		"protected header":            {"origin", &nodev1.RuleAction{Kind: "request_header", Header: "cookie", Target: irConst("a=b")}, false},
		"GeoIP without the database":  {"origin", &nodev1.RuleAction{Kind: "request_header", Header: "x-as", Target: irField("ip.geoip.as_name", "string")}, false},
		"303":                         {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/a", StatusCode: 303}, true},
		"304":                         {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/a", StatusCode: 304}, false},
		"query expression":            {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/signin", StatusCode: 303, SetQuery: param("next", "", irField("http.request.uri.args.next", "string"))}, true},
		"query expression in rewrite": {"request-transform", &nodev1.RuleAction{Kind: "rewrite", Value: "/b", SetQuery: param("sig", "", irCall("md5", "string", irPath))}, true},
		"query value and expression":  {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/a", StatusCode: 301, SetQuery: param("a", "1", irConst("2"))}, false},
		"query number expression":     {"request-transform", &nodev1.RuleAction{Kind: "rewrite", Value: "/a", SetQuery: param("a", "", irCall("len", "number", irPath))}, false},
		"query condition-only call":   {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/a", StatusCode: 301, SetQuery: param("a", "", irCall("regex_replace", "string", irPath, irConst("("), irConst("")))}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := validAction(tc.a, tc.phase, features); got != tc.ok {
				t.Fatalf("validAction = %v, want %v", got, tc.ok)
			}
		})
	}
}

func TestBulkRedirectsKeepTheirStatuses(t *testing.T) {
	for status, ok := range map[uint32]bool{301: true, 302: true, 303: false, 307: true, 308: true} {
		err := validateBulkRedirects([]*nodev1.BulkRedirect{{Source: "/a", Target: "/b", StatusCode: status}})
		if (err == nil) != ok {
			t.Errorf("status %d: err=%v", status, err)
		}
	}
}

func TestSupportedFeaturesRulesV3(t *testing.T) {
	if !slices.Contains(SupportedFeatures, FeatureRulesV3) || FeatureRulesV3 != "rules-v3" {
		t.Fatalf("SupportedFeatures lacks rules-v3: %v", SupportedFeatures)
	}
	c := &nodev1.NodeConfig{Sites: []*nodev1.Site{site("site-a", "a.test")}, RequiredFeatures: []string{FeatureRulesV2, FeatureRulesV3}}
	if _, err := Build(c, Options{}); err != nil {
		t.Fatal(err)
	}
}
