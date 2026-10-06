package configir

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"google.golang.org/protobuf/reflect/protoreflect"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// rulePhases in execution order. compression (proto v0.13.0, feature
// rules-v2) runs in the edge layer's header filter after
// response-transform.
var rulePhases = []string{"request-transform", "redirect", "config", "waf-custom", "ratelimit", "cache", "origin", "response-transform", "compression"}

// responsePhases may read http.response.* fields.
var responsePhases = []string{"response-transform", "compression"}

var fieldTypes = map[string]string{"http.host": "string", "http.request.method": "string", "http.request.uri.path": "string", "http.request.uri.query": "string", "http.request.uri": "string", "http.response.code": "number", "ip.src": "ip", "ssl": "boolean", "ip.geoip.country": "string", "ip.geoip.subdivision": "string", "ip.geoip.asnum": "number", "tls.ja4": "string",
	// rules-v2: scheme://host followed by the request URI as received; the
	// lowercase extension of the last path segment; the lowercase media type
	// of the response's Content-Type without parameters.
	"http.request.full_uri": "string", "http.request.uri.path.extension": "string", "http.response.content_type.media_type": "string",
	// rules-v3: the Referer and User-Agent request headers; the request's
	// HTTP version, scheme, id (X-Request-Id) and arrival in Unix seconds;
	// the listener's port; the AS name; the edge cache status of the
	// response ("" for responses the node made itself).
	"http.referer": "string", "http.user_agent": "string", "http.request.version": "string", "http.request.scheme": "string",
	"http.request.id": "string", "http.request.timestamp.sec": "number", "edge.server_port": "number", "ip.geoip.as_name": "string",
	"http.response.cache_status": "string"}

// namedFields are the rules-v3 fields of one request cookie
// (http.request.cookies.<name>, an RFC 6265 token, case-sensitive) and one
// query parameter (http.request.uri.args.<name>, as sent: printable ASCII
// without `"`, `#`, `&` and `=`), both strings.
var namedFields = map[string]*regexp.Regexp{
	"http.request.cookies.":  regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$"),
	"http.request.uri.args.": regexp.MustCompile(`^[\x21\x24\x25\x27-\x3c\x3e-\x7e]{1,64}$`),
}

// geoFeatures is the local capability each GeoIP field needs (see
// geoip.Features). The console sends geoip-city-v1 for subdivision rules too;
// this check keeps a node without a City MMDB from accepting them.
var geoFeatures = map[string]string{"ip.geoip.country": "geoip-country-v1", "ip.geoip.subdivision": "geoip-subdivision-v1", "ip.geoip.asnum": "geoip-asn-v1", "ip.geoip.as_name": "geoip-asn-v1"}
var protectedHeaders = []string{"host", "authorization", "proxy-authorization", "cookie", "set-cookie", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer", "cdn-loop"}

func ruleHeader(s string) bool {
	return tokenRE.MatchString(s) && s == strings.ToLower(s) && !slices.Contains(protectedHeaders, s) && !strings.HasPrefix(s, "x-edgeweir-")
}
func ruleText(s string) bool {
	return len(s) <= 16384 && !hasControl(s)
}

// hasControl reports whether s contains a byte below 0x20 or 0x7f.
func hasControl(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return r < 32 || r == 127 })
}
func ruleValue(s, typ string) bool {
	switch typ {
	case "string":
		return len(s) <= 16384
	case "boolean":
		return s == "true" || s == "false"
	case "number":
		v, e := strconv.ParseInt(s, 10, 64)
		return e == nil && v >= -9007199254740991 && v <= 9007199254740991 && strconv.FormatInt(v, 10) == s
	case "ip":
		p, e := netip.ParsePrefix(s)
		return e == nil && !p.Addr().Is4In6() && p.Masked().String() == s
	}
	return false
}

// ruleFunction is the signature of a function of the expression language
// (proto v0.13.0, feature rules-v2; v0.22.0, feature rules-v3). args are
// the kinds of the arguments (the last one repeats): "string" a string
// value node, "any" a value node of any type, "start" and "length" op
// "const" nodes of value_type "number" within substringBounds. valueOnly
// functions appear only in value expressions (RuleAction.target), at most
// once each, and take constant pattern and replacement arguments.
type ruleFunction struct {
	result    string
	min, max  int
	valueOnly bool
	args      []string
}

var stringArgs = []string{"string"}

var ruleFunctions = map[string]ruleFunction{
	"lower":            {"string", 1, 1, false, stringArgs},
	"upper":            {"string", 1, 1, false, stringArgs},
	"len":              {"number", 1, 1, false, stringArgs},
	"starts_with":      {"boolean", 2, 2, false, stringArgs},
	"ends_with":        {"boolean", 2, 2, false, stringArgs},
	"url_decode":       {"string", 1, 1, false, stringArgs},
	"concat":           {"string", 2, 8, false, stringArgs},
	"regex_replace":    {"string", 3, 3, true, stringArgs},
	"wildcard_replace": {"string", 3, 4, true, stringArgs},
	// rules-v3
	"url_encode":    {"string", 1, 1, false, stringArgs},
	"base64_encode": {"string", 1, 1, false, stringArgs},
	"base64_decode": {"string", 1, 1, false, stringArgs},
	"md5":           {"string", 1, 1, false, stringArgs},
	"sha1":          {"string", 1, 1, false, stringArgs},
	"sha256":        {"string", 1, 1, false, stringArgs},
	"substring":     {"string", 2, 3, false, []string{"string", "start", "length"}},
	"to_string":     {"string", 1, 1, false, []string{"any"}},
}

// substringBounds are the bounds of substring's integer arguments: the
// start byte (negative counts from the end) and the length.
var substringBounds = map[string][2]int64{"start": {-65536, 65536}, "length": {0, 65536}}

// Bounds of expressions: nodes per expression (conditions and value
// expressions each), nesting of and/or/not and of function calls.
const (
	maxExpressionNodes = 256
	maxExpressionDepth = 64
	maxCallDepth       = 4
	// Replacement templates of regex_replace and wildcard_replace.
	maxReplacement     = 1024
	maxWildcardPattern = 1024
	maxWildcards       = 8
	maxReplaceGroup    = 8
)

// exprCheck validates one expression: a condition (EdgeRule.expression,
// CacheRuleMatch.condition) or a value expression (RuleAction.target).
type exprCheck struct {
	phase    string
	lists    map[string]bool
	features []string
	budget   int
	// value: a value expression, where regex_replace and wildcard_replace
	// may appear once each (used records them).
	value bool
	used  map[string]bool
}

var errInvalidExpression = fmt.Errorf("%w: invalid rule expression", ErrRejected)

// validateCondition checks a condition of phase. lists are the IP lists
// in_list may name, features the node's local capabilities (GeoIP).
func validateCondition(e *nodev1.RuleExpression, phase string, lists map[string]bool, features []string) error {
	c := &exprCheck{phase: phase, lists: lists, features: features, budget: maxExpressionNodes}
	return c.condition(e, 0)
}

// validateValueExpression checks a value expression of phase: a string
// field, constant or function call.
func validateValueExpression(e *nodev1.RuleExpression, phase string, features []string) error {
	c := &exprCheck{phase: phase, features: features, budget: maxExpressionNodes, value: true, used: map[string]bool{}}
	typ, err := c.valueNode(e, 0)
	if err != nil {
		return err
	}
	if typ != "string" {
		return errInvalidExpression
	}
	return nil
}

// fieldType returns the type of field in this phase, "" when unknown or
// unavailable.
func (c *exprCheck) fieldType(field string) string {
	typ := fieldTypes[field]
	for _, prefix := range []string{"http.request.headers.", "http.response.headers."} {
		if strings.HasPrefix(field, prefix) && tokenRE.MatchString(strings.TrimPrefix(field, prefix)) {
			typ = "string"
		}
	}
	for prefix, re := range namedFields {
		if strings.HasPrefix(field, prefix) && re.MatchString(strings.TrimPrefix(field, prefix)) {
			typ = "string"
		}
	}
	if strings.HasPrefix(field, "http.response.") && !slices.Contains(responsePhases, c.phase) {
		return ""
	}
	return typ
}

func (c *exprCheck) geo(field string) error {
	if feature, ok := geoFeatures[field]; ok && !slices.Contains(c.features, feature) {
		return fmt.Errorf("%w: GeoIP database unavailable", ErrRejected)
	}
	return nil
}

func (c *exprCheck) condition(e *nodev1.RuleExpression, depth int) error {
	c.budget--
	bad := errInvalidExpression
	if e == nil || depth > maxExpressionDepth || c.budget < 0 {
		return bad
	}
	switch e.Op {
	case "and", "or", "not":
		if len(e.Children) == 0 || (e.Op == "not" && len(e.Children) != 1) || e.Field != "" || e.Value != "" || e.ValueType != "" || len(e.Values) > 0 {
			return bad
		}
		for _, child := range e.Children {
			if err := c.condition(child, depth+1); err != nil {
				return err
			}
		}
		return nil
	case "literal":
		if e.ValueType != "boolean" || !ruleValue(e.Value, "boolean") || e.Field != "" || len(e.Children) > 0 || len(e.Values) > 0 {
			return bad
		}
		return nil
	case "call":
		// A boolean function stands alone as a condition.
		typ, err := c.call(e, 1)
		if err != nil {
			return err
		}
		if typ != "boolean" {
			return bad
		}
		return nil
	case "field", "const":
		return bad
	}
	var typ string
	if len(e.Children) > 0 {
		// The left side is computed: exactly one value node.
		if e.Field != "" || len(e.Children) != 1 || e.Op == "in_list" {
			return bad
		}
		var err error
		if typ, err = c.valueNode(e.Children[0], 0); err != nil {
			return err
		}
		if typ != e.ValueType {
			return bad
		}
	} else {
		typ = c.fieldType(e.Field)
		if typ == "" || typ != e.ValueType {
			return bad
		}
		if err := c.geo(e.Field); err != nil {
			return err
		}
	}
	if e.Op == "in_list" {
		if typ != "ip" || !c.lists[e.Value] || len(e.Values) > 0 {
			return bad
		}
		return nil
	}
	if e.Op == "in" {
		if e.Value != "" || len(e.Values) == 0 || len(e.Values) > 256 {
			return bad
		}
		for _, v := range e.Values {
			if !ruleValue(v, typ) {
				return bad
			}
		}
		return nil
	}
	if len(e.Values) > 0 || !ruleValue(e.Value, typ) {
		return bad
	}
	switch e.Op {
	case "eq", "ne":
		return nil
	case "lt", "le", "gt", "ge":
		if typ == "number" {
			return nil
		}
	case "contains":
		if typ == "string" {
			return nil
		}
	case "matches":
		if typ == "string" && validPattern(e.Value) {
			return nil
		}
	case "wildcard", "strict_wildcard":
		// rules-v3: a full match of a wildcard pattern (strict: case-sensitive).
		if typ == "string" && wildcardStars(e.Value) >= 0 {
			return nil
		}
	}
	return bad
}

// valueNode checks a value node (field, const or call) and returns its
// type. depth is the number of calls around it.
func (c *exprCheck) valueNode(e *nodev1.RuleExpression, depth int) (string, error) {
	c.budget--
	bad := errInvalidExpression
	if e == nil || c.budget < 0 {
		return "", bad
	}
	switch e.Op {
	case "field":
		typ := c.fieldType(e.Field)
		if typ == "" || typ != e.ValueType || e.Value != "" || len(e.Values) > 0 || len(e.Children) > 0 {
			return "", bad
		}
		return typ, c.geo(e.Field)
	case "const":
		if e.ValueType != "string" || e.Field != "" || len(e.Values) > 0 || len(e.Children) > 0 || !ruleValue(e.Value, "string") {
			return "", bad
		}
		return "string", nil
	case "call":
		return c.call(e, depth+1)
	}
	return "", bad
}

// call checks a function call at nesting depth (1: outermost).
func (c *exprCheck) call(e *nodev1.RuleExpression, depth int) (string, error) {
	bad := errInvalidExpression
	f, ok := ruleFunctions[e.Field]
	if !ok || depth > maxCallDepth || e.ValueType != f.result || e.Value != "" || len(e.Values) > 0 || len(e.Children) < f.min || len(e.Children) > f.max {
		return "", bad
	}
	if f.valueOnly {
		if !c.value || c.used[e.Field] {
			return "", bad
		}
		c.used[e.Field] = true
	}
	for i, arg := range e.Children {
		kind := f.args[min(i, len(f.args)-1)]
		if kind == "start" || kind == "length" {
			if !c.integerArg(arg, substringBounds[kind]) {
				return "", bad
			}
			continue
		}
		typ, err := c.valueNode(arg, depth)
		if err != nil {
			return "", err
		}
		// Patterns, replacements and the flag are constants.
		if (kind == "string" && typ != "string") || (f.valueOnly && i > 0 && arg.Op != "const") {
			return "", bad
		}
	}
	switch e.Field {
	case "regex_replace":
		pattern := e.Children[1].Value
		if !validPattern(pattern) || !validReplacement(e.Children[2].Value, patternGroups(pattern)) {
			return "", bad
		}
	case "wildcard_replace":
		stars := wildcardStars(e.Children[1].Value)
		if stars < 0 || !validReplacement(e.Children[2].Value, stars) || (len(e.Children) == 4 && e.Children[3].Value != "s") {
			return "", bad
		}
	}
	return f.result, nil
}

// integerArg checks an integer argument of substring: an op "const" node
// of value_type "number" within bounds.
func (c *exprCheck) integerArg(e *nodev1.RuleExpression, bounds [2]int64) bool {
	c.budget--
	if e == nil || c.budget < 0 || e.Op != "const" || e.ValueType != "number" || e.Field != "" || len(e.Values) > 0 || len(e.Children) > 0 || !ruleValue(e.Value, "number") {
		return false
	}
	v, _ := strconv.ParseInt(e.Value, 10, 64)
	return v >= bounds[0] && v <= bounds[1]
}

// validReplacement checks a replacement template: literal text without
// control characters, at most 1024 bytes, where ${1} to ${8} insert a
// capture (at most groups); every other "$" is a literal.
func validReplacement(r string, groups int) bool {
	if len(r) > maxReplacement || hasControl(r) {
		return false
	}
	for i := 0; i+3 < len(r); i++ {
		if r[i] == '$' && r[i+1] == '{' && r[i+2] >= '1' && r[i+2] <= '0'+maxReplaceGroup && r[i+3] == '}' {
			if int(r[i+2]-'0') > groups {
				return false
			}
			i += 3
		}
	}
	return true
}

// patternGroups counts the capturing groups of a valid pattern: unescaped
// "(" outside classes (validPattern refuses "(?").
func patternGroups(p string) int {
	n, class := 0, false
	for i := 0; i < len(p); i++ {
		switch c := p[i]; {
		case c == '\\':
			i++
		case class:
			class = c != ']'
		case c == '[':
			class = true
		case c == '(':
			n++
		}
	}
	return n
}

// wildcardStars returns the number of wildcards of a wildcard_replace
// pattern, or -1 when it is invalid: at most 1024 bytes without control
// characters, a backslash only in `\*` or `\\`, at most 8 unescaped "*".
func wildcardStars(p string) int {
	if len(p) > maxWildcardPattern || hasControl(p) {
		return -1
	}
	n := 0
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '\\':
			if i+1 >= len(p) || (p[i+1] != '*' && p[i+1] != '\\') {
				return -1
			}
			i++
		case '*':
			n++
		}
	}
	if n > maxWildcards {
		return -1
	}
	return n
}

// Regular expressions (`matches`) are the subset that the console's JavaScript
// (packages/rule-engine validatePattern, which this is a line-for-line port of),
// this validator and PCRE2 without UTF in lua/edgeweir/expressions.lua read
// alike, matched against the UTF-8 bytes of the value. Everything outside it is
// rejected, including constructs the engines read differently: `(?...)`, back-
// references, `\s`, `\v`, `\z`, `\p{...}`, possessive or repeated quantifiers,
// repeated groups, `{,n}`, `[[:alpha:]]`, `[]...]` and non-ASCII text. Keep the
// three in step with test/lua/expression-vectors.json.
const patternPunctuation = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"

// patternItem is one escape or class member; n == 0 means invalid. kind is 'c'
// (one character, code), 's' (\d \D \w \W), 'a' (\b \B) or '-' (a bare dash).
type patternItem struct {
	n    int
	kind byte
	code byte
}

func patternEscape(p string, i int, inClass bool) patternItem {
	if i+1 >= len(p) {
		return patternItem{}
	}
	switch e := p[i+1]; e {
	case 'd', 'D', 'w', 'W':
		return patternItem{2, 's', 0}
	case 'b', 'B':
		if !inClass {
			return patternItem{2, 'a', 0}
		}
	case 't':
		return patternItem{2, 'c', '\t'}
	case 'n':
		return patternItem{2, 'c', '\n'}
	case 'f':
		return patternItem{2, 'c', '\f'}
	case 'r':
		return patternItem{2, 'c', '\r'}
	case 'x':
		if i+3 < len(p) && p[i+2] >= '0' && p[i+2] <= '7' && strings.IndexByte("0123456789abcdefABCDEF", p[i+3]) >= 0 {
			v, _ := strconv.ParseUint(p[i+2:i+4], 16, 8)
			return patternItem{4, 'c', byte(v)}
		}
	default:
		if strings.IndexByte(patternPunctuation, e) >= 0 {
			return patternItem{2, 'c', e}
		}
	}
	return patternItem{}
}

func patternClassAtom(p string, j, body int) patternItem {
	switch c := p[j]; {
	case c == '\\':
		return patternEscape(p, j, true)
	case c == '-' && (j == body || (j+1 < len(p) && p[j+1] == ']')):
		return patternItem{1, '-', '-'}
	case c == '-' || c == '[' || c < ' ' || c > '~':
		return patternItem{}
	default:
		return patternItem{1, 'c', c}
	}
}

// patternClass checks the class that starts at p[i] ('[') and returns the index
// after its ']', or -1.
func patternClass(p string, i int) int {
	body := i + 1
	if body < len(p) && p[body] == '^' {
		body++
	}
	j := body
	for j >= len(p) || p[j] != ']' {
		if j >= len(p) {
			return -1
		}
		low := patternClassAtom(p, j, body)
		if low.n == 0 {
			return -1
		}
		end := j + low.n
		if end+1 < len(p) && p[end] == '-' && p[end+1] != ']' {
			if low.kind != 'c' {
				return -1
			}
			high := patternClassAtom(p, end+1, body)
			if high.n == 0 || high.kind != 'c' || high.code < low.code {
				return -1
			}
			end += 1 + high.n
		}
		j = end
	}
	// PCRE2 reads [:x:], [.x.] and [=x=] as POSIX syntax and refuses them outside a class.
	text := p[body:j]
	if text == "" || (len(text) > 1 && strings.IndexByte(":.=", text[0]) >= 0 && text[len(text)-1] == text[0]) {
		return -1
	}
	return j + 1
}

// patternBraces returns the length of the {n}, {n,} or {n,m} quantifier at p[i]
// (n <= m <= 1000, no leading zeros), or 0.
func patternBraces(p string, i int) int {
	count := func(j int) (int, int) {
		k := j
		for k < len(p) && k-j < 4 && p[k] >= '0' && p[k] <= '9' {
			k++
		}
		if k == j || (p[j] == '0' && k > j+1) {
			return 0, -1
		}
		n, _ := strconv.Atoi(p[j:k])
		return n, k
	}
	low, j := count(i + 1)
	if j < 0 {
		return 0
	}
	high := low
	if j < len(p) && p[j] == ',' {
		j++
		if j < len(p) && p[j] != '}' {
			if high, j = count(j); j < 0 {
				return 0
			}
		}
	}
	if j >= len(p) || p[j] != '}' || low > 1000 || high > 1000 || high < low {
		return 0
	}
	return j + 1 - i
}

// validPattern reports whether p is in the subset: printable ASCII, at most 256
// bytes; literals; `.` (any byte except "\n"); `^` and `$` (start and end of the
// value); `\b` `\B`; `\d` `\D` `\w` `\W` (ASCII); `\t` `\n` `\r` `\f`;
// `\x00`-`\x7f`; a backslash before ASCII punctuation; classes of those
// characters, `\d` `\D` `\w` `\W` and ranges, with a bare `-` only first or
// last; `* + ? {n} {n,} {n,m}`, optionally lazy, after a character, class or
// escape; `|` and capturing groups, never repeated.
func validPattern(p string) bool {
	if len(p) > 256 {
		return false
	}
	depth := 0
	// What a quantifier here would repeat: 'n' nothing, 'a' an atom, 'q' a
	// quantifier (only a lazy '?' may follow), 'f' an anchor, group or lazy
	// quantifier (never repeated).
	previous := byte('n')
	for i := 0; i < len(p); {
		c, n, next := p[i], 1, byte('a')
		switch {
		case c == '\\':
			item := patternEscape(p, i, false)
			if item.n == 0 {
				return false
			}
			n = item.n
			if item.kind == 'a' {
				next = 'f'
			}
		case c == '[':
			end := patternClass(p, i)
			if end < 0 {
				return false
			}
			n = end - i
		case c == '(':
			if i+1 < len(p) && p[i+1] == '?' {
				return false
			}
			depth++
			next = 'n'
		case c == ')':
			if depth--; depth < 0 {
				return false
			}
			next = 'f'
		case c == '|':
			next = 'n'
		case c == '^' || c == '$':
			next = 'f'
		case c == '?' && previous == 'q':
			next = 'f'
		case c == '*' || c == '+' || c == '?' || c == '{':
			if previous != 'a' {
				return false
			}
			if c == '{' {
				if n = patternBraces(p, i); n == 0 {
					return false
				}
			}
			next = 'q'
		case c == ']' || c == '}' || c < ' ' || c > '~':
			return false
		}
		previous = next
		i += n
	}
	return depth == 0
}

// actionFields are the RuleAction fields each kind may carry besides kind;
// every other field must stay empty (unset, "", 0, false or no items).
var actionFields = map[string][]protoreflect.Name{
	"block":           {"status_code"},
	"log":             {},
	"allow":           {},
	"challenge":       {"challenge"},
	"redirect":        {"value", "status_code", "target", "preserve_query", "set_query", "remove_query"},
	"rewrite":         {"value", "target", "preserve_query", "set_query", "remove_query"},
	"request_header":  {"header", "value", "remove", "target"},
	"response_header": {"header", "value", "remove", "target", "append"},
	"config": {"cache_bypass", "force_https", "gzip", "brotli", "zstd", "websocket", "under_attack", "cc_enabled",
		"cc_max_level", "origin_connect_timeout_ms", "origin_send_timeout_ms", "origin_read_timeout_ms", "log_sample_rate",
		"request_body_limit"},
	"rate_limit":  {"status_code", "limit", "window_seconds", "key"},
	"origin":      {"origin_group", "host_header", "sni", "port"},
	"compression": {"compression"},
}

// Codings of compression rules (RuleAction.compression).
var compressionCodings = []string{"zstd", "br", "gzip"}

// redirectStatuses of redirect rules (303 since proto v0.22.0, feature
// rules-v3) and bulk redirects (without 303).
var redirectStatuses = []uint32{301, 302, 303, 307, 308}
var bulkRedirectStatuses = []uint32{301, 302, 307, 308}

// queryNameRE matches the query parameter names redirects and rewrites set
// or remove (RFC 3986 unreserved characters).
var queryNameRE = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,64}$`)

// originGroupRE matches origin groups (Origin.group, RuleAction.origin_group).
var originGroupRE = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

// Bounds of the rules-v2 actions.
const (
	maxQueryEdits        = 16
	maxQueryValue        = 256
	maxConnectTimeoutMS  = 120_000
	maxSendReadTimeoutMS = 3_600_000
	minOriginTimeoutMS   = 100
	maxLogSampleRate     = 10_000
	maxBrowserTTLSeconds = 31_536_000
	maxBulkRedirects     = 5000
	maxBulkSource        = 512
	maxBulkTarget        = 1024
)

// onlyFields reports whether a carries no field outside its kind's.
func onlyFields(a *nodev1.RuleAction) bool {
	allowed, ok := actionFields[a.Kind]
	if !ok {
		return false
	}
	only := true
	a.ProtoReflect().Range(func(field protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		if name := field.Name(); name != "kind" && !slices.Contains(allowed, name) {
			only = false
		}
		return only
	})
	return only
}

// validRedirectLocation reports whether v is a static redirect target: an
// absolute http(s) URL with a host and no user information, or a local
// path starting with a single "/" without a backslash.
func validRedirectLocation(v string) bool {
	if strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") && !strings.Contains(v, "\\") {
		return true
	}
	u, err := url.Parse(v)
	return err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") && u.User == nil
}

// validRewritePath reports whether v is a static rewrite path.
func validRewritePath(v string) bool {
	return strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "//") && !strings.ContainsAny(v, "?\\#")
}

// validQueryEdits checks set_query and remove_query: at most 16 each,
// sorted by name without duplicates, names never in both lists, values
// printable ASCII of at most 256 bytes or (rules-v3) a string value
// expression of phase with an empty value.
func validQueryEdits(a *nodev1.RuleAction, phase string, features []string) bool {
	if len(a.SetQuery) > maxQueryEdits || len(a.RemoveQuery) > maxQueryEdits {
		return false
	}
	names := make([]string, 0, len(a.SetQuery))
	for _, p := range a.SetQuery {
		if p == nil || len(p.Value) > maxQueryValue || strings.ContainsFunc(p.Value, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
			return false
		}
		if p.Expression != nil && (p.Value != "" || validateValueExpression(p.Expression, phase, features) != nil) {
			return false
		}
		names = append(names, p.Name)
	}
	sortedNames := func(list []string) bool {
		for i, name := range list {
			if !queryNameRE.MatchString(name) || (i > 0 && list[i-1] >= name) {
				return false
			}
		}
		return true
	}
	if !sortedNames(names) || !sortedNames(a.RemoveQuery) {
		return false
	}
	for _, name := range names {
		if slices.Contains(a.RemoveQuery, name) {
			return false
		}
	}
	return true
}

// validTarget checks the location of a redirect or rewrite: exactly one of
// the static value (checked by static) and the value expression target.
func validTarget(a *nodev1.RuleAction, phase string, features []string, static func(string) bool) bool {
	if a.Target != nil {
		return a.Value == "" && validateValueExpression(a.Target, phase, features) == nil
	}
	return static(a.Value)
}

// validHeaderValue checks the value of a header action: the static value,
// or (rules-v3) a string value expression of phase instead of it; neither
// goes with remove, whose header has no value to compute. append (response
// headers) adds a line and never goes with remove either.
func validHeaderValue(a *nodev1.RuleAction, phase string, features []string) bool {
	if a.Append && a.Remove {
		return false
	}
	return a.Target == nil || (!a.Remove && a.Value == "" && validateValueExpression(a.Target, phase, features) == nil)
}

func validOriginTimeout(ms, max uint32) bool {
	return ms == 0 || (ms >= minOriginTimeoutMS && ms <= max)
}

// validConfigAction checks a config action. The rules-v2 fields are only
// valid in phase config; at least one field is set.
func validConfigAction(a *nodev1.RuleAction, phase string) bool {
	v2 := a.Brotli != nil || a.Zstd != nil || a.Websocket != nil || a.UnderAttack != nil || a.CcEnabled != nil ||
		a.CcMaxLevel != "" || a.OriginConnectTimeoutMs != 0 || a.OriginSendTimeoutMs != 0 || a.OriginReadTimeoutMs != 0 ||
		a.LogSampleRate != nil || a.RequestBodyLimit != nil
	return (phase == "config" || (phase == "cache" && !v2)) &&
		(a.RequestBodyLimit == nil || *a.RequestBodyLimit <= MaxRequestBodyLimit) &&
		(a.CcMaxLevel == "" || slices.Contains(ChallengeTypes, a.CcMaxLevel)) &&
		validOriginTimeout(a.OriginConnectTimeoutMs, maxConnectTimeoutMS) &&
		validOriginTimeout(a.OriginSendTimeoutMs, maxSendReadTimeoutMS) &&
		validOriginTimeout(a.OriginReadTimeoutMs, maxSendReadTimeoutMS) &&
		(a.LogSampleRate == nil || *a.LogSampleRate <= maxLogSampleRate) &&
		(a.CacheBypass != nil || a.ForceHttps != nil || a.Gzip != nil || v2)
}

// validOriginAction checks an origin action: an origin group, Host header,
// SNI or port, at least one of them.
func validOriginAction(a *nodev1.RuleAction) bool {
	return (a.OriginGroup == "" || originGroupRE.MatchString(a.OriginGroup)) &&
		(a.HostHeader == "" || validHostHeader(a.HostHeader)) &&
		(a.Sni == "" || ValidHostname(a.Sni)) &&
		a.Port <= 65535 &&
		(a.OriginGroup != "" || a.HostHeader != "" || a.Sni != "" || a.Port != 0)
}

func validCompressionAction(a *nodev1.RuleAction) bool {
	for i, coding := range a.Compression {
		if !slices.Contains(compressionCodings, coding) || slices.Contains(a.Compression[:i], coding) {
			return false
		}
	}
	return true
}

// validAction checks the action of a rule of phase.
func validAction(a *nodev1.RuleAction, phase string, features []string) bool {
	if a == nil || !ruleText(a.Value) || !onlyFields(a) {
		return false
	}
	switch a.Kind {
	case "block":
		return phase == "waf-custom" && (a.StatusCode == 403 || a.StatusCode == 451)
	case "log", "allow":
		return phase == "waf-custom"
	case "challenge":
		return phase == "waf-custom" && slices.Contains(ChallengeTypes, a.Challenge)
	case "redirect":
		return phase == "redirect" && slices.Contains(redirectStatuses, a.StatusCode) && validQueryEdits(a, phase, features) &&
			validTarget(a, phase, features, validRedirectLocation)
	case "rewrite":
		return phase == "request-transform" && validQueryEdits(a, phase, features) && validTarget(a, phase, features, validRewritePath)
	case "request_header":
		return (phase == "request-transform" || phase == "origin") && ruleHeader(a.Header) && validHeaderValue(a, phase, features)
	case "response_header":
		return phase == "response-transform" && ruleHeader(a.Header) && validHeaderValue(a, phase, features)
	case "config":
		return validConfigAction(a, phase)
	case "rate_limit":
		return (a.StatusCode == 403 || a.StatusCode == 429) && phase == "ratelimit" && a.Limit >= 1 && a.Limit <= 100000 && a.WindowSeconds >= 1 && a.WindowSeconds <= 3600 && (a.Key == "ip.src" || a.Key == "http.host" || a.Key == "tls.ja4" || (strings.HasPrefix(a.Key, "http.request.headers.") && tokenRE.MatchString(strings.TrimPrefix(a.Key, "http.request.headers."))))
	case "origin":
		return phase == "origin" && validOriginAction(a)
	case "compression":
		return phase == "compression" && validCompressionAction(a)
	}
	return false
}

func validateRuleSet(rules []*nodev1.EdgeRule, lists map[string]bool, features []string, maxRules int) error {
	if len(rules) > maxRules {
		return fmt.Errorf("%w: too many rules", ErrRejected)
	}
	previous := -1
	ids := map[string]bool{}
	for _, r := range rules {
		phase := slices.Index(rulePhases, r.GetPhase())
		if phase < previous || phase < 0 || !idRE.MatchString(r.GetId()) || ids[r.GetId()] {
			return fmt.Errorf("%w: invalid rule order or ID", ErrRejected)
		}
		ids[r.Id] = true
		previous = phase
		if err := validateCondition(r.Expression, r.Phase, lists, features); err != nil {
			return err
		}
		if !validAction(r.Action, r.Phase, features) {
			return fmt.Errorf("%w: unsupported rule action %q in phase %q", ErrRejected, r.GetAction().GetKind(), r.Phase)
		}
	}
	return nil
}

func validateRules(c *nodev1.NodeConfig, features []string) error {
	lists := map[string]bool{}
	platform := map[string]bool{}
	if len(c.IpLists) > 4096 {
		return fmt.Errorf("%w: too many IP lists", ErrRejected)
	}
	for _, l := range c.IpLists {
		if !idRE.MatchString(l.GetId()) || lists[l.GetId()] || len(l.GetEntries()) > 10000 || !slices.Contains([]string{"collection", "allow", "block"}, l.GetKind()) {
			return fmt.Errorf("%w: invalid IP list", ErrRejected)
		}
		lists[l.Id] = true
		platform[l.Id] = l.Platform
		for _, entry := range l.Entries {
			if !ruleValue(entry, "ip") {
				return fmt.Errorf("%w: invalid IP list entry", ErrRejected)
			}
		}
	}
	if err := validateRuleSet(c.PlatformRules, platform, features, 32); err != nil {
		return err
	}
	for _, site := range c.Sites {
		if err := validateRuleSet(site.GetRules(), lists, features, 64); err != nil {
			return err
		}
		if err := validateCacheRuleConditions(site, lists, features); err != nil {
			return err
		}
		if err := validateBulkRedirects(site.GetBulkRedirects()); err != nil {
			return fmt.Errorf("site %q: %w", site.GetId(), err)
		}
		for _, o := range site.GetOriginPool().GetOrigins() {
			if g := o.GetGroup(); g != "" && !originGroupRE.MatchString(g) {
				return fmt.Errorf("%w: site %q origin %q: invalid origin group", ErrRejected, site.GetId(), o.GetId())
			}
		}
	}
	return nil
}

// validateCacheRuleConditions checks the typed request conditions of a
// site's cache rules (phase cache, IP lists like site rules) and their
// browser TTLs. A rule with a condition has no structured request lists.
func validateCacheRuleConditions(site *nodev1.Site, lists map[string]bool, features []string) error {
	for _, r := range site.GetCacheRules() {
		m := r.GetMatch()
		if r.GetBrowserTtlSeconds() > maxBrowserTTLSeconds {
			return fmt.Errorf("%w: site %q cache rule %q: browser TTL out of range", ErrRejected, site.GetId(), r.GetId())
		}
		if m.GetCondition() == nil {
			continue
		}
		if len(m.GetPathPrefixes()) > 0 || len(m.GetPaths()) > 0 || len(m.GetExtensions()) > 0 {
			return fmt.Errorf("%w: site %q cache rule %q: condition with path lists", ErrRejected, site.GetId(), r.GetId())
		}
		if err := validateCondition(m.GetCondition(), "cache", lists, features); err != nil {
			return fmt.Errorf("site %q cache rule %q: %w", site.GetId(), r.GetId(), err)
		}
	}
	return nil
}

// validBulkSource reports whether s is a bulk redirect source: "/path" or
// "host/path" (lowercase host name), 2-512 bytes without control
// characters, whitespace or "?".
func validBulkSource(s string) bool {
	if len(s) < 2 || len(s) > maxBulkSource || strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f || r == 0xfeff || unicode.IsSpace(r) }) || strings.Contains(s, "?") {
		return false
	}
	if s[0] == '/' {
		return true
	}
	host, _, ok := strings.Cut(s, "/")
	return ok && ValidHostname(host)
}

// validateBulkRedirects checks a site's exact-match redirect table: at most
// 5000 entries sorted by source without duplicates.
func validateBulkRedirects(list []*nodev1.BulkRedirect) error {
	if len(list) > maxBulkRedirects {
		return fmt.Errorf("%w: too many bulk redirects", ErrRejected)
	}
	for i, b := range list {
		if !validBulkSource(b.GetSource()) || (i > 0 && list[i-1].GetSource() >= b.GetSource()) {
			return fmt.Errorf("%w: invalid or unsorted bulk redirect source %q", ErrRejected, b.GetSource())
		}
		if len(b.GetTarget()) > maxBulkTarget || hasControl(b.GetTarget()) || !validRedirectLocation(b.GetTarget()) || !slices.Contains(bulkRedirectStatuses, b.GetStatusCode()) {
			return fmt.Errorf("%w: invalid bulk redirect for %q", ErrRejected, b.GetSource())
		}
	}
	return nil
}
