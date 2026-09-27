package configir

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

var rulePhases = []string{"request-transform", "redirect", "config", "waf-custom", "ratelimit", "cache", "origin", "response-transform"}
var fieldTypes = map[string]string{"http.host": "string", "http.request.method": "string", "http.request.uri.path": "string", "http.request.uri.query": "string", "http.request.uri": "string", "http.response.code": "number", "ip.src": "ip", "ssl": "boolean", "ip.geoip.country": "string", "ip.geoip.subdivision": "string", "ip.geoip.asnum": "number"}

// geoFeatures is the node capability each GeoIP field needs (see geoip.Features).
var geoFeatures = map[string]string{"ip.geoip.country": "geoip-country-v1", "ip.geoip.subdivision": "geoip-city-v1", "ip.geoip.asnum": "geoip-asn-v1"}
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
		if typ != "string" || len(e.Value) > 256 || strings.Contains(e.Value, "(?") || regexp.MustCompile(`\\[1-9]|\)[+*?{]|[+*}]\s*[+*{]`).MatchString(e.Value) {
			return bad()
		}
		if _, err := regexp.Compile(e.Value); err == nil {
			return nil
		}
	}
	return bad()
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
