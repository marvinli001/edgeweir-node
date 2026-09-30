package configir

import (
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

var rulePhases = []string{"request-transform", "redirect", "config", "waf-custom", "ratelimit", "cache", "origin", "response-transform"}
var fieldTypes = map[string]string{"http.host": "string", "http.request.method": "string", "http.request.uri.path": "string", "http.request.uri.query": "string", "http.request.uri": "string", "http.response.code": "number", "ip.src": "ip", "ssl": "boolean", "ip.geoip.country": "string", "ip.geoip.subdivision": "string", "ip.geoip.asnum": "number"}

// geoFeatures is the local capability each GeoIP field needs (see
// geoip.Features). The console sends geoip-city-v1 for subdivision rules too;
// this check keeps a node without a City MMDB from accepting them.
var geoFeatures = map[string]string{"ip.geoip.country": "geoip-country-v1", "ip.geoip.subdivision": "geoip-subdivision-v1", "ip.geoip.asnum": "geoip-asn-v1"}
var protectedHeaders = []string{"host", "authorization", "proxy-authorization", "cookie", "set-cookie", "content-length", "transfer-encoding", "connection", "upgrade", "te", "trailer", "cdn-loop"}

func ruleHeader(s string) bool {
	return tokenRE.MatchString(s) && s == strings.ToLower(s) && !slices.Contains(protectedHeaders, s) && !strings.HasPrefix(s, "x-edgeweir-")
}
func ruleText(s string) bool {
	return len(s) <= 16384 && !strings.ContainsFunc(s, func(r rune) bool { return r < 32 || r == 127 })
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

func validateExpression(e *nodev1.RuleExpression, phase string, lists map[string]bool, features []string, depth int, budget *int) error {
	*budget--
	bad := func() error { return fmt.Errorf("%w: invalid rule expression", ErrRejected) }
	if e == nil || depth > 64 || *budget < 0 {
		return bad()
	}
	switch e.Op {
	case "and", "or", "not":
		if len(e.Children) == 0 || (e.Op == "not" && len(e.Children) != 1) || e.Field != "" || e.Value != "" || e.ValueType != "" || len(e.Values) > 0 {
			return bad()
		}
		for _, c := range e.Children {
			if err := validateExpression(c, phase, lists, features, depth+1, budget); err != nil {
				return err
			}
		}
		return nil
	case "literal":
		if e.ValueType != "boolean" || !ruleValue(e.Value, "boolean") || e.Field != "" || len(e.Children) > 0 || len(e.Values) > 0 {
			return bad()
		}
		return nil
	}
	if len(e.Children) > 0 {
		return bad()
	}
	typ := fieldTypes[e.Field]
	for _, prefix := range []string{"http.request.headers.", "http.response.headers."} {
		if strings.HasPrefix(e.Field, prefix) && tokenRE.MatchString(strings.TrimPrefix(e.Field, prefix)) {
			typ = "string"
		}
	}
	if typ == "" || typ != e.ValueType || (strings.HasPrefix(e.Field, "http.response.") && phase != "response-transform") {
		return bad()
	}
	if feature, ok := geoFeatures[e.Field]; ok {
		if !slices.Contains(features, feature) {
			return fmt.Errorf("%w: GeoIP database unavailable", ErrRejected)
		}
	}
	if e.Op == "in_list" {
		if typ != "ip" || !lists[e.Value] || len(e.Values) > 0 {
			return bad()
		}
		return nil
	}
	if e.Op == "in" {
		if e.Value != "" || len(e.Values) == 0 || len(e.Values) > 256 {
			return bad()
		}
		for _, v := range e.Values {
			if !ruleValue(v, typ) {
				return bad()
			}
		}
		return nil
	}
	if len(e.Values) > 0 || !ruleValue(e.Value, typ) {
		return bad()
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
	}
	return bad()
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
		budget := 256
		if err := validateExpression(r.Expression, r.Phase, lists, features, 0, &budget); err != nil {
			return err
		}
		a := r.Action
		if a == nil || !ruleText(a.Value) {
			return fmt.Errorf("%w: invalid rule action", ErrRejected)
		}
		valid := false
		switch a.Kind {
		case "block":
			valid = r.Phase == "waf-custom" && (a.StatusCode == 403 || a.StatusCode == 451)
		case "log", "allow":
			valid = r.Phase == "waf-custom"
		case "redirect":
			u, err := url.Parse(a.Value)
			location := strings.HasPrefix(a.Value, "/") && !strings.HasPrefix(a.Value, "//") && !strings.Contains(a.Value, "\\")
			if err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https") && u.User == nil {
				location = true
			}
			valid = r.Phase == "redirect" && location && slices.Contains([]uint32{301, 302, 307, 308}, a.StatusCode)
		case "rewrite":
			valid = r.Phase == "request-transform" && strings.HasPrefix(a.Value, "/") && !strings.HasPrefix(a.Value, "//") && !strings.ContainsAny(a.Value, "?\\#")
		case "request_header":
			valid = (r.Phase == "request-transform" || r.Phase == "origin") && ruleHeader(a.Header)
		case "response_header":
			valid = r.Phase == "response-transform" && ruleHeader(a.Header)
		case "config":
			valid = !a.GetGzip() && (r.Phase == "config" || r.Phase == "cache") && (a.CacheBypass != nil || a.ForceHttps != nil || a.Gzip != nil)
		case "rate_limit":
			valid = (a.StatusCode == 403 || a.StatusCode == 429) && r.Phase == "ratelimit" && a.Limit >= 1 && a.Limit <= 100000 && a.WindowSeconds >= 1 && a.WindowSeconds <= 3600 && (a.Key == "ip.src" || a.Key == "http.host" || (strings.HasPrefix(a.Key, "http.request.headers.") && tokenRE.MatchString(strings.TrimPrefix(a.Key, "http.request.headers."))))
		}
		if !valid {
			return fmt.Errorf("%w: unsupported rule action %q in phase %q", ErrRejected, a.Kind, r.Phase)
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
	}
	return nil
}
