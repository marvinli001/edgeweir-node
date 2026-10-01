package configir

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"google.golang.org/protobuf/proto"
)

func irField(name, typ string) *nodev1.RuleExpression {
	return &nodev1.RuleExpression{Op: "field", Field: name, ValueType: typ}
}

func irConst(v string) *nodev1.RuleExpression {
	return &nodev1.RuleExpression{Op: "const", ValueType: "string", Value: v}
}

func irCall(name, typ string, args ...*nodev1.RuleExpression) *nodev1.RuleExpression {
	return &nodev1.RuleExpression{Op: "call", Field: name, ValueType: typ, Children: args}
}

// irCompare compares a computed left side with value.
func irCompare(op, typ, value string, left *nodev1.RuleExpression) *nodev1.RuleExpression {
	return &nodev1.RuleExpression{Op: op, ValueType: typ, Value: value, Children: []*nodev1.RuleExpression{left}}
}

var (
	irPath = irField("http.request.uri.path", "string")
	irHost = irField("http.host", "string")
)

func TestExpressionFunctions(t *testing.T) {
	lists := map[string]bool{"list": true}
	nested := func(depth int) *nodev1.RuleExpression {
		e := irHost
		for range depth {
			e = irCall("lower", "string", e)
		}
		return e
	}
	conditions := map[string]struct {
		e     *nodev1.RuleExpression
		phase string
		ok    bool
	}{
		"lower eq":                     {irCompare("eq", "string", "a.test", irCall("lower", "string", irHost)), "waf-custom", true},
		"upper ne":                     {irCompare("ne", "string", "A", irCall("upper", "string", irHost)), "waf-custom", true},
		"len gt":                       {irCompare("gt", "number", "1024", irCall("len", "number", irField("http.request.uri.query", "string"))), "waf-custom", true},
		"url_decode contains":          {irCompare("contains", "string", "<script", irCall("url_decode", "string", irField("http.request.uri.query", "string"))), "waf-custom", true},
		"concat matches":               {irCompare("matches", "string", "^a/", irCall("concat", "string", irHost, irPath)), "waf-custom", true},
		"concat of eight":              {irCompare("eq", "string", "x", irCall("concat", "string", irHost, irHost, irHost, irHost, irHost, irHost, irHost, irHost)), "waf-custom", true},
		"len in":                       {&nodev1.RuleExpression{Op: "in", ValueType: "number", Values: []string{"1", "2"}, Children: []*nodev1.RuleExpression{irCall("len", "number", irHost)}}, "waf-custom", true},
		"standalone starts_with":       {irCall("starts_with", "boolean", irPath, irConst("/api/")), "waf-custom", true},
		"not ends_with":                {&nodev1.RuleExpression{Op: "not", Children: []*nodev1.RuleExpression{irCall("ends_with", "boolean", irPath, irConst(".php"))}}, "waf-custom", true},
		"boolean call compared":        {irCompare("eq", "boolean", "true", irCall("starts_with", "boolean", irPath, irConst(""))), "waf-custom", true},
		"field node left":              {irCompare("eq", "string", "/", irPath), "waf-custom", true},
		"const left":                   {irCompare("eq", "string", "a", irConst("a")), "waf-custom", true},
		"four calls deep":              {irCompare("eq", "string", "a", nested(4)), "waf-custom", true},
		"full_uri":                     {&nodev1.RuleExpression{Op: "eq", Field: "http.request.full_uri", ValueType: "string", Value: "https://a.test/"}, "redirect", true},
		"extension":                    {&nodev1.RuleExpression{Op: "in", Field: "http.request.uri.path.extension", ValueType: "string", Values: []string{"png"}}, "cache", true},
		"media type in compression":    {&nodev1.RuleExpression{Op: "eq", Field: "http.response.content_type.media_type", ValueType: "string", Value: "text/html"}, "compression", true},
		"response code in compression": {&nodev1.RuleExpression{Op: "eq", Field: "http.response.code", ValueType: "number", Value: "200"}, "compression", true},
		"media type in request phase":  {&nodev1.RuleExpression{Op: "eq", Field: "http.response.content_type.media_type", ValueType: "string", Value: "text/html"}, "waf-custom", false},
		"response field as argument":   {irCompare("eq", "string", "x", irCall("lower", "string", irField("http.response.headers.server", "string"))), "origin", false},
		"five calls deep":              {irCompare("eq", "string", "a", nested(5)), "waf-custom", false},
		"unknown function":             {irCompare("eq", "string", "a", irCall("trim", "string", irHost)), "waf-custom", false},
		"wrong result type":            {irCompare("eq", "string", "1", irCall("len", "string", irHost)), "waf-custom", false},
		"comparison type mismatch":     {irCompare("eq", "number", "1", irCall("lower", "string", irHost)), "waf-custom", false},
		"too few arguments":            {irCall("starts_with", "boolean", irPath), "waf-custom", false},
		"too many arguments":           {irCompare("eq", "string", "a", irCall("lower", "string", irHost, irHost)), "waf-custom", false},
		"concat of one":                {irCompare("eq", "string", "a", irCall("concat", "string", irHost)), "waf-custom", false},
		"concat of nine":               {irCompare("eq", "string", "x", irCall("concat", "string", irHost, irHost, irHost, irHost, irHost, irHost, irHost, irHost, irHost)), "waf-custom", false},
		"number argument":              {irCompare("eq", "number", "1", irCall("len", "number", irCall("len", "number", irHost))), "waf-custom", false},
		"ip argument":                  {irCompare("eq", "number", "1", irCall("len", "number", irField("ip.src", "ip"))), "waf-custom", false},
		"string call alone":            {irCall("lower", "string", irHost), "waf-custom", false},
		"field alone":                  {irHost, "waf-custom", false},
		"const alone":                  {irConst("true"), "waf-custom", false},
		"regex_replace in condition":   {irCompare("eq", "string", "x", irCall("regex_replace", "string", irPath, irConst("a"), irConst("b"))), "waf-custom", false},
		"wildcard in condition":        {irCompare("eq", "string", "x", irCall("wildcard_replace", "string", irPath, irConst("/*"), irConst("${1}"))), "waf-custom", false},
		"in_list computed":             {&nodev1.RuleExpression{Op: "in_list", ValueType: "ip", Value: "list", Children: []*nodev1.RuleExpression{irField("ip.src", "ip")}}, "waf-custom", false},
		"contains on number":           {irCompare("contains", "number", "1", irCall("len", "number", irHost)), "waf-custom", false},
		"lt on string":                 {irCompare("lt", "string", "3", irCall("lower", "string", irHost)), "waf-custom", false},
		"two children":                 {&nodev1.RuleExpression{Op: "eq", ValueType: "string", Value: "a", Children: []*nodev1.RuleExpression{irHost, irHost}}, "waf-custom", false},
		"field and children":           {&nodev1.RuleExpression{Op: "eq", Field: "http.host", ValueType: "string", Value: "a", Children: []*nodev1.RuleExpression{irHost}}, "waf-custom", false},
		"field node with value":        {irCompare("eq", "string", "a", &nodev1.RuleExpression{Op: "field", Field: "http.host", ValueType: "string", Value: "x"}), "waf-custom", false},
		"field node wrong type":        {irCompare("eq", "number", "1", irField("http.host", "number")), "waf-custom", false},
		"const node not string":        {irCompare("eq", "number", "1", &nodev1.RuleExpression{Op: "const", ValueType: "number", Value: "1"}), "waf-custom", false},
		"const node with field":        {irCompare("eq", "string", "a", &nodev1.RuleExpression{Op: "const", Field: "http.host", ValueType: "string", Value: "a"}), "waf-custom", false},
		"call with value":              {irCompare("eq", "string", "a", &nodev1.RuleExpression{Op: "call", Field: "lower", ValueType: "string", Value: "x", Children: []*nodev1.RuleExpression{irHost}}), "waf-custom", false},
		"matches outside the subset":   {irCompare("matches", "string", "(?i)a", irCall("lower", "string", irHost)), "waf-custom", false},
	}
	for name, test := range conditions {
		t.Run(name, func(t *testing.T) {
			err := validateCondition(test.e, test.phase, lists, nil)
			if test.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !test.ok && !errors.Is(err, ErrRejected) {
				t.Fatalf("accepted (%v)", err)
			}
		})
	}
	// GeoIP fields need the local database also as arguments.
	geo := irCompare("eq", "string", "nz", irCall("lower", "string", irField("ip.geoip.country", "string")))
	if err := validateCondition(geo, "waf-custom", nil, nil); err == nil {
		t.Fatal("GeoIP argument accepted without the database")
	}
	if err := validateCondition(geo, "waf-custom", nil, []string{"geoip-country-v1"}); err != nil {
		t.Fatal(err)
	}
	// The node budget counts arguments.
	wide := irCompare("eq", "string", "a", irCall("concat", "string", irHost, irHost))
	var or []*nodev1.RuleExpression
	for range 64 {
		or = append(or, proto.CloneOf(wide))
	}
	if err := validateCondition(&nodev1.RuleExpression{Op: "or", Children: or}, "waf-custom", nil, nil); err == nil {
		t.Fatal("257 nodes accepted")
	}
}

func TestValueExpressions(t *testing.T) {
	regex := func(pattern, replacement string) *nodev1.RuleExpression {
		return irCall("regex_replace", "string", irPath, irConst(pattern), irConst(replacement))
	}
	wildcard := func(pattern, replacement string, flag ...string) *nodev1.RuleExpression {
		args := []*nodev1.RuleExpression{irPath, irConst(pattern), irConst(replacement)}
		for _, f := range flag {
			args = append(args, irConst(f))
		}
		return irCall("wildcard_replace", "string", args...)
	}
	for name, test := range map[string]struct {
		e  *nodev1.RuleExpression
		ok bool
	}{
		"const":                       {irConst("/static"), true},
		"field":                       {irPath, true},
		"concat":                      {irCall("concat", "string", irConst("https://a.test"), irPath), true},
		"regex_replace":               {regex("^/old/(.*)$", "/new/${1}"), true},
		"regex_replace two groups":    {regex("^/(a)/(b)", "${2}${1}"), true},
		"literal dollars":             {regex("^/(p)$", "/$1/$${1}/${0}/${9}/${12}/${x}"), true},
		"escaped and class parens":    {regex(`\(([(])`, "${1}"), true},
		"wildcard_replace":            {wildcard("https://*.example.test/*", "https://example.test/${1}/${2}"), true},
		"wildcard case-sensitive":     {wildcard("/IMG/*", "/images/${1}", "s"), true},
		"wildcard escapes":            {wildcard(`/a\*b/\\*`, "/${1}"), true},
		"wildcard eight":              {wildcard("********", "${8}"), true},
		"both replace functions":      {irCall("concat", "string", regex("a", "b"), wildcard("/*", "${1}")), true},
		"lower of regex_replace":      {irCall("lower", "string", regex("a", "b")), true},
		"regex_replace twice":         {irCall("concat", "string", regex("a", "b"), regex("c", "d")), false},
		"wildcard_replace twice":      {irCall("concat", "string", wildcard("/*", "${1}"), wildcard("/*", "${1}")), false},
		"number":                      {irCall("len", "number", irPath), false},
		"boolean":                     {irCall("starts_with", "boolean", irPath, irConst("/")), false},
		"ip field":                    {irField("ip.src", "ip"), false},
		"comparison":                  {&nodev1.RuleExpression{Op: "eq", Field: "http.host", ValueType: "string", Value: "a"}, false},
		"literal":                     {&nodev1.RuleExpression{Op: "literal", ValueType: "boolean", Value: "true"}, false},
		"pattern from a field":        {irCall("regex_replace", "string", irPath, irHost, irConst("x")), false},
		"replacement from a call":     {irCall("regex_replace", "string", irPath, irConst("a"), irCall("lower", "string", irConst("x"))), false},
		"pattern outside the subset":  {regex("(?i)a", "b"), false},
		"missing group":               {regex("^/a", "${1}"), false},
		"group beyond the pattern":    {regex("^/(a)", "${2}"), false},
		"control in replacement":      {regex("a", "b\n"), false},
		"long replacement":            {regex("a", strings.Repeat("b", 1025)), false},
		"nine wildcards":              {wildcard("*********", "x"), false},
		"other escape":                {wildcard(`/a\b*`, "x"), false},
		"trailing backslash":          {wildcard(`/a\`, "x"), false},
		"control in wildcard":         {wildcard("/a\x7f*", "x"), false},
		"long wildcard":               {wildcard(strings.Repeat("a", 1025), "x"), false},
		"capture beyond wildcards":    {wildcard("/*", "${2}"), false},
		"unknown flag":                {wildcard("/*", "x", "i"), false},
		"flag from a field":           {irCall("wildcard_replace", "string", irPath, irConst("/*"), irConst("x"), irHost), false},
		"five arguments":              {wildcard("/*", "x", "s", "s"), false},
		"regex_replace two arguments": {irCall("regex_replace", "string", irPath, irConst("a")), false},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateValueExpression(test.e, "redirect", nil)
			if test.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !test.ok && !errors.Is(err, ErrRejected) {
				t.Fatalf("accepted (%v)", err)
			}
		})
	}
	if err := validateValueExpression(irField("http.response.content_type.media_type", "string"), "request-transform", nil); err == nil {
		t.Fatal("response field accepted in a request phase")
	}
}

func TestReplacementHelpers(t *testing.T) {
	for p, want := range map[string]int{"": 0, "(a)(b)": 2, `\(a`: 0, `[(]`: 0, `[\]()](a)`: 1, "((a)|b)": 2} {
		if got := patternGroups(p); got != want {
			t.Errorf("patternGroups(%q) = %d, want %d", p, got, want)
		}
	}
	for p, want := range map[string]int{"": 0, "/*": 1, `/\*`: 0, `\\*`: 1, "**": 2, `\`: -1, `\a`: -1, "\x01": -1, "é*": 1} {
		if got := wildcardStars(p); got != want {
			t.Errorf("wildcardStars(%q) = %d, want %d", p, got, want)
		}
	}
	for _, test := range []struct {
		r      string
		groups int
		ok     bool
	}{
		{"/x", 0, true}, {"${1}", 1, true}, {"${1}", 0, false}, {"${8}", 8, true}, {"$${2}", 1, false},
		{"${0}${9}${10}$1${}${a}$", 0, true}, {"${1", 0, true}, {"é", 0, true}, {"\t", 0, false},
	} {
		if got := validReplacement(test.r, test.groups); got != test.ok {
			t.Errorf("validReplacement(%q, %d) = %v", test.r, test.groups, got)
		}
	}
}

func TestRuleActionsV2(t *testing.T) {
	yes, no := true, false
	rate := func(v uint32) *uint32 { return &v }
	target := irCall("regex_replace", "string", irPath, irConst("^/old/(.*)$"), irConst("/new/${1}"))
	query := func(names ...string) []*nodev1.QueryParam {
		var out []*nodev1.QueryParam
		for _, n := range names {
			out = append(out, &nodev1.QueryParam{Name: n, Value: "v"})
		}
		return out
	}
	for name, test := range map[string]struct {
		phase string
		a     *nodev1.RuleAction
		ok    bool
	}{
		"static redirect":            {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "https://a.test/x?y=1#z", StatusCode: 308}, true},
		"dynamic redirect":           {"redirect", &nodev1.RuleAction{Kind: "redirect", Target: target, StatusCode: 301, PreserveQuery: &yes}, true},
		"redirect query edits":       {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/a", StatusCode: 302, SetQuery: []*nodev1.QueryParam{{Name: "lang", Value: "zh CN"}, {Name: "src", Value: ""}}, RemoveQuery: []string{"session", "utm_source"}}, true},
		"sixteen edits":              {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/a", StatusCode: 302, RemoveQuery: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p"}}, true},
		"seventeen edits":            {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/a", StatusCode: 302, RemoveQuery: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q"}}, false},
		"value and target":           {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/a", Target: irConst("/b"), StatusCode: 301}, false},
		"neither value nor target":   {"redirect", &nodev1.RuleAction{Kind: "redirect", StatusCode: 301}, false},
		"invalid target":             {"redirect", &nodev1.RuleAction{Kind: "redirect", Target: irCall("len", "number", irPath), StatusCode: 301}, false},
		"redirect status":            {"redirect", &nodev1.RuleAction{Kind: "redirect", Target: target, StatusCode: 303}, false},
		"unsorted set_query":         {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/a", StatusCode: 301, SetQuery: query("b", "a")}, false},
		"duplicate remove_query":     {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/a", StatusCode: 301, RemoveQuery: []string{"a", "a"}}, false},
		"set and removed":            {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/a", StatusCode: 301, SetQuery: query("a"), RemoveQuery: []string{"a"}}, false},
		"non-ASCII query value":      {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/a", StatusCode: 301, SetQuery: []*nodev1.QueryParam{{Name: "a", Value: "é"}}}, false},
		"long query value":           {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/a", StatusCode: 301, SetQuery: []*nodev1.QueryParam{{Name: "a", Value: strings.Repeat("v", 257)}}}, false},
		"invalid query name":         {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/a", StatusCode: 301, RemoveQuery: []string{"a b"}}, false},
		"long query name":            {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/a", StatusCode: 301, RemoveQuery: []string{strings.Repeat("a", 65)}}, false},
		"redirect with compression":  {"redirect", &nodev1.RuleAction{Kind: "redirect", Value: "/a", StatusCode: 301, Compression: []string{"br"}}, false},
		"static rewrite":             {"request-transform", &nodev1.RuleAction{Kind: "rewrite", Value: "/b", RemoveQuery: []string{"debug"}}, true},
		"dynamic rewrite":            {"request-transform", &nodev1.RuleAction{Kind: "rewrite", Target: target, PreserveQuery: &no, SetQuery: query("v")}, true},
		"rewrite with a status":      {"request-transform", &nodev1.RuleAction{Kind: "rewrite", Value: "/b", StatusCode: 301}, false},
		"rewrite with origin group":  {"request-transform", &nodev1.RuleAction{Kind: "rewrite", Value: "/a", OriginGroup: "api"}, false},
		"rewrite target and value":   {"request-transform", &nodev1.RuleAction{Kind: "rewrite", Value: "/a", Target: target}, false},
		"origin":                     {"origin", &nodev1.RuleAction{Kind: "origin", OriginGroup: "api", HostHeader: "api.example.test", Sni: "api.example.test", Port: 8443}, true},
		"origin port":                {"origin", &nodev1.RuleAction{Kind: "origin", Port: 8080}, true},
		"origin host with port":      {"origin", &nodev1.RuleAction{Kind: "origin", HostHeader: "api.example.test:8080"}, true},
		"empty origin":               {"origin", &nodev1.RuleAction{Kind: "origin"}, false},
		"uppercase group":            {"origin", &nodev1.RuleAction{Kind: "origin", OriginGroup: "API"}, false},
		"long group":                 {"origin", &nodev1.RuleAction{Kind: "origin", OriginGroup: strings.Repeat("a", 33)}, false},
		"invalid host":               {"origin", &nodev1.RuleAction{Kind: "origin", HostHeader: "bad host"}, false},
		"invalid SNI":                {"origin", &nodev1.RuleAction{Kind: "origin", Sni: "a..b"}, false},
		"port out of range":          {"origin", &nodev1.RuleAction{Kind: "origin", Port: 70000}, false},
		"origin in config":           {"config", &nodev1.RuleAction{Kind: "origin", OriginGroup: "api"}, false},
		"origin with header":         {"origin", &nodev1.RuleAction{Kind: "origin", Port: 80, Header: "x-a"}, false},
		"config v2":                  {"config", &nodev1.RuleAction{Kind: "config", Gzip: &yes, Brotli: &no, Zstd: &no, Websocket: &no, UnderAttack: &yes, CcEnabled: &no, CcMaxLevel: "js", OriginConnectTimeoutMs: 2000, OriginSendTimeoutMs: 30000, OriginReadTimeoutMs: 3600000, LogSampleRate: rate(100)}, true},
		"config sample rate zero":    {"config", &nodev1.RuleAction{Kind: "config", LogSampleRate: rate(0)}, true},
		"config gzip true in cache":  {"cache", &nodev1.RuleAction{Kind: "config", Gzip: &yes}, true},
		"config v2 in cache":         {"cache", &nodev1.RuleAction{Kind: "config", Websocket: &no}, false},
		"config empty":               {"config", &nodev1.RuleAction{Kind: "config"}, false},
		"config only zero timeouts":  {"config", &nodev1.RuleAction{Kind: "config", CcMaxLevel: ""}, false},
		"unknown CC level":           {"config", &nodev1.RuleAction{Kind: "config", CcMaxLevel: "slider"}, false},
		"short timeout":              {"config", &nodev1.RuleAction{Kind: "config", OriginReadTimeoutMs: 50}, false},
		"long connect timeout":       {"config", &nodev1.RuleAction{Kind: "config", OriginConnectTimeoutMs: 120001}, false},
		"long read timeout":          {"config", &nodev1.RuleAction{Kind: "config", OriginReadTimeoutMs: 3600001}, false},
		"sample rate":                {"config", &nodev1.RuleAction{Kind: "config", LogSampleRate: rate(10001)}, false},
		"config in origin phase":     {"origin", &nodev1.RuleAction{Kind: "config", Brotli: &no}, false},
		"compression":                {"compression", &nodev1.RuleAction{Kind: "compression", Compression: []string{"br", "gzip"}}, true},
		"compression off":            {"compression", &nodev1.RuleAction{Kind: "compression"}, true},
		"unknown coding":             {"compression", &nodev1.RuleAction{Kind: "compression", Compression: []string{"deflate"}}, false},
		"duplicate coding":           {"compression", &nodev1.RuleAction{Kind: "compression", Compression: []string{"br", "br"}}, false},
		"compression elsewhere":      {"response-transform", &nodev1.RuleAction{Kind: "compression", Compression: []string{"br"}}, false},
		"header in compression":      {"compression", &nodev1.RuleAction{Kind: "response_header", Header: "x-a", Value: "1"}, false},
		"block with a value":         {"waf-custom", &nodev1.RuleAction{Kind: "block", StatusCode: 403, Value: "x"}, false},
		"block with a false boolean": {"waf-custom", &nodev1.RuleAction{Kind: "block", StatusCode: 403, CacheBypass: &no}, false},
		"header with preserve_query": {"request-transform", &nodev1.RuleAction{Kind: "request_header", Header: "x-a", PreserveQuery: &no}, false},
		"rate limit with a group":    {"ratelimit", &nodev1.RuleAction{Kind: "rate_limit", StatusCode: 429, Limit: 1, WindowSeconds: 1, Key: "ip.src", OriginGroup: "a"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			rule := &nodev1.EdgeRule{Id: "r", Phase: test.phase, Expression: &nodev1.RuleExpression{Op: "literal", ValueType: "boolean", Value: "true"}, Action: test.a}
			err := validateRuleSet([]*nodev1.EdgeRule{rule}, nil, nil, 64)
			if test.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !test.ok && !errors.Is(err, ErrRejected) {
				t.Fatalf("accepted (%v)", err)
			}
		})
	}
	// compression is the last phase.
	order := []*nodev1.EdgeRule{
		{Id: "a", Phase: "compression", Expression: &nodev1.RuleExpression{Op: "literal", ValueType: "boolean", Value: "true"}, Action: &nodev1.RuleAction{Kind: "compression"}},
		{Id: "b", Phase: "response-transform", Expression: &nodev1.RuleExpression{Op: "literal", ValueType: "boolean", Value: "true"}, Action: &nodev1.RuleAction{Kind: "response_header", Header: "x-a"}},
	}
	if err := validateRuleSet(order, nil, nil, 64); err == nil {
		t.Fatal("compression before response-transform accepted")
	}
	slices.Reverse(order)
	if err := validateRuleSet(order, nil, nil, 64); err != nil {
		t.Fatal(err)
	}
}

func TestBulkRedirects(t *testing.T) {
	valid := []*nodev1.BulkRedirect{
		{Source: "/old", Target: "/new", StatusCode: 301, PreserveQuery: true},
		{Source: "/中", Target: "https://b.test/x?y=1#z", StatusCode: 308},
		{Source: "a.test/old", Target: "/a", StatusCode: 302},
	}
	c := &nodev1.NodeConfig{Sites: []*nodev1.Site{site("site-a", "a.test")}}
	c.Sites[0].BulkRedirects = valid
	plan, err := Build(c, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []BulkRedirect{{"/old", "/new", 301, true}, {"/中", "https://b.test/x?y=1#z", 308, false}, {"a.test/old", "/a", 302, false}}
	if !slices.Equal(plan.Sites[0].BulkRedirects, want) {
		t.Fatalf("bulk redirects %+v", plan.Sites[0].BulkRedirects)
	}
	for name, change := range map[string]func([]*nodev1.BulkRedirect) []*nodev1.BulkRedirect{
		"unsorted":        func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect { l[0], l[1] = l[1], l[0]; return l },
		"duplicate":       func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect { l[1].Source = "/old"; return l },
		"one byte source": func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect { l[0].Source = "/"; return l },
		"long source": func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect {
			l[2].Source = "a.test/" + strings.Repeat("a", 506)
			return l
		},
		"query in source":   func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect { l[0].Source = "/old?x"; return l },
		"space in source":   func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect { l[0].Source = "/o ld"; return l },
		"nbsp in source":    func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect { l[1].Source = "/ "; return l },
		"control in source": func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect { l[0].Source = "/o\x7f"; return l },
		"uppercase host":    func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect { l[2].Source = "A.test/old"; return l },
		"host without path": func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect { l[2].Source = "a.test"; return l },
		"relative target":   func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect { l[0].Target = "new"; return l },
		"protocol-relative": func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect { l[0].Target = "//b.test/"; return l },
		"ftp target":        func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect { l[0].Target = "ftp://b.test/"; return l },
		"long target": func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect {
			l[0].Target = "/" + strings.Repeat("a", 1024)
			return l
		},
		"control in target": func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect { l[0].Target = "/a\nb"; return l },
		"status":            func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect { l[0].StatusCode = 303; return l },
		"too many redirects": func(l []*nodev1.BulkRedirect) []*nodev1.BulkRedirect {
			var out []*nodev1.BulkRedirect
			for i := range 5001 {
				out = append(out, &nodev1.BulkRedirect{Source: fmt.Sprintf("/%05d", i), Target: "/", StatusCode: 301})
			}
			return out
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := proto.CloneOf(c)
			bad.Sites[0].BulkRedirects = change(bad.Sites[0].BulkRedirects)
			if _, err := Build(bad, Options{}); !errors.Is(err, ErrRejected) {
				t.Fatalf("accepted (%v)", err)
			}
		})
	}
	// Disabled sites are checked too.
	bad := proto.CloneOf(c)
	bad.Sites[0].Enabled = false
	bad.Sites[0].BulkRedirects[0].StatusCode = 200
	if _, err := Build(bad, Options{}); !errors.Is(err, ErrRejected) {
		t.Fatalf("disabled site accepted (%v)", err)
	}
	// 5000 entries are fine.
	big := proto.CloneOf(c)
	big.Sites[0].BulkRedirects = nil
	for i := range 5000 {
		big.Sites[0].BulkRedirects = append(big.Sites[0].BulkRedirects, &nodev1.BulkRedirect{Source: fmt.Sprintf("/%05d", i), Target: "/", StatusCode: 301})
	}
	if _, err := Build(big, Options{}); err != nil {
		t.Fatal(err)
	}
}

func TestOriginGroups(t *testing.T) {
	c := &nodev1.NodeConfig{Sites: []*nodev1.Site{site("site-a", "a.test")}}
	o := proto.CloneOf(c.Sites[0].OriginPool.Origins[0])
	o.Id, o.Group = "o-api", "api_v2-1"
	c.Sites[0].OriginPool.Origins = append(c.Sites[0].OriginPool.Origins, o)
	plan, err := Build(c, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Sites[0].Origins; len(got) != 2 || got[0].Group != "" || got[1].Group != "api_v2-1" {
		t.Fatalf("origins %+v", got)
	}
	raw, _ := json.Marshal(plan.Sites[0].Origins)
	if strings.Count(string(raw), `"group"`) != 1 {
		t.Fatalf("site table origins %s", raw)
	}
	for _, group := range []string{"API", "a.b", strings.Repeat("a", 33), " "} {
		bad := proto.CloneOf(c)
		bad.Sites[0].OriginPool.Origins[1].Group = group
		if _, err := Build(bad, Options{}); !errors.Is(err, ErrRejected) {
			t.Errorf("group %q accepted (%v)", group, err)
		}
	}
}

func TestCacheRuleConditions(t *testing.T) {
	cond := &nodev1.RuleExpression{Op: "and", Children: []*nodev1.RuleExpression{
		irCall("starts_with", "boolean", irPath, irConst("/img/")),
		{Op: "in", Field: "http.request.uri.path.extension", ValueType: "string", Values: []string{"png", "webp"}},
		{Op: "in_list", Field: "ip.src", ValueType: "ip", Value: "office"},
	}}
	c := &nodev1.NodeConfig{
		IpLists: []*nodev1.IpList{{Id: "office", Kind: "collection", Entries: []string{"192.0.2.0/24"}}},
		Sites:   []*nodev1.Site{site("site-a", "a.test")},
	}
	c.Sites[0].CacheRules = []*nodev1.CacheRule{{
		Id: "c1", Action: nodev1.CacheAction_CACHE_ACTION_CACHE, EdgeTtlSeconds: 60, BrowserTtlSeconds: 31536000,
		Match: &nodev1.CacheRuleMatch{Condition: cond, StatusCodes: []uint32{200}},
	}}
	plan, err := Build(c, Options{})
	if err != nil {
		t.Fatal(err)
	}
	r := plan.Sites[0].CacheRules[0]
	if !proto.Equal(r.Condition, cond) || r.BrowserTTL != 31536000 || !slices.Equal(r.StatusCodes, []uint32{200}) {
		t.Fatalf("cache rule %+v", r)
	}
	raw, _ := json.Marshal(r)
	if !strings.Contains(string(raw), `"condition":{"op":"and"`) || !strings.Contains(string(raw), `"browser_ttl":31536000`) {
		t.Fatalf("site table cache rule %s", raw)
	}
	for name, change := range map[string]func(*nodev1.CacheRule){
		"browser TTL":     func(r *nodev1.CacheRule) { r.BrowserTtlSeconds = 31536001 },
		"with prefixes":   func(r *nodev1.CacheRule) { r.Match.PathPrefixes = []string{"/a"} },
		"with paths":      func(r *nodev1.CacheRule) { r.Match.Paths = []string{"/a"} },
		"with extensions": func(r *nodev1.CacheRule) { r.Match.Extensions = []string{"png"} },
		"with expression": func(r *nodev1.CacheRule) { r.Match.Expression = "true" },
		"response field": func(r *nodev1.CacheRule) {
			r.Match.Condition = &nodev1.RuleExpression{Op: "eq", Field: "http.response.code", ValueType: "number", Value: "200"}
		},
		"value function": func(r *nodev1.CacheRule) {
			r.Match.Condition = irCompare("eq", "string", "/", irCall("regex_replace", "string", irPath, irConst("a"), irConst("b")))
		},
		"unknown list": func(r *nodev1.CacheRule) {
			r.Match.Condition = &nodev1.RuleExpression{Op: "in_list", Field: "ip.src", ValueType: "ip", Value: "missing"}
		},
		"GeoIP without database": func(r *nodev1.CacheRule) {
			r.Match.Condition = &nodev1.RuleExpression{Op: "eq", Field: "ip.geoip.country", ValueType: "string", Value: "NZ"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := proto.CloneOf(c)
			change(bad.Sites[0].CacheRules[0])
			if _, err := Build(bad, Options{}); !errors.Is(err, ErrRejected) {
				t.Fatalf("accepted (%v)", err)
			}
		})
	}
}

func TestCanonicalizeV0130(t *testing.T) {
	action := func() *nodev1.RuleAction {
		return &nodev1.RuleAction{Kind: "redirect", Value: "/a", StatusCode: 301,
			SetQuery: []*nodev1.QueryParam{{Name: "b", Value: "2"}, {Name: "a", Value: "1"}}, RemoveQuery: []string{"y", "x"}}
	}
	c := &nodev1.NodeConfig{
		PlatformRules: []*nodev1.EdgeRule{{Id: "p", Phase: "redirect", Action: action()}},
		Sites: []*nodev1.Site{{Id: "s", Rules: []*nodev1.EdgeRule{{Id: "r2", Phase: "redirect", Action: action()}, {Id: "r1", Phase: "redirect", Action: action()}},
			BulkRedirects: []*nodev1.BulkRedirect{{Source: "/b"}, {Source: "a.test/a"}, {Source: "/a"}}}},
	}
	Canonicalize(c)
	for _, r := range append(c.PlatformRules, c.Sites[0].Rules...) {
		a := r.Action
		if a.SetQuery[0].Name != "a" || a.SetQuery[1].Name != "b" || !slices.Equal(a.RemoveQuery, []string{"x", "y"}) {
			t.Fatalf("rule %s action %v", r.Id, a)
		}
	}
	if c.Sites[0].Rules[0].Id != "r2" {
		t.Fatal("rules reordered")
	}
	var sources []string
	for _, b := range c.Sites[0].BulkRedirects {
		sources = append(sources, b.Source)
	}
	if !slices.Equal(sources, []string{"/a", "/b", "a.test/a"}) {
		t.Fatalf("bulk redirects %v", sources)
	}
}

func TestSupportedFeaturesRulesV2(t *testing.T) {
	if !slices.Contains(SupportedFeatures, FeatureRulesV2) {
		t.Fatalf("SupportedFeatures lacks %s", FeatureRulesV2)
	}
	c := &nodev1.NodeConfig{Sites: []*nodev1.Site{site("site-a", "a.test")}, RequiredFeatures: []string{FeatureRulesV2}}
	if _, err := Build(c, Options{}); err != nil {
		t.Fatal(err)
	}
}
