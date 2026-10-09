package configir

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// FeatureAccessControl (proto v0.28.0, ADR-0039): Site.access_control, a
// site's own block and allow lists, geo access, CORS (preflights answered
// at the edge), hotlink protection, user agent rules, WebSocket origins and
// idle timeout, and security response headers. The console requires it
// when a site has access_control.
const FeatureAccessControl = "access-control-v1"

// Limits of a site's access control (the console's).
const (
	maxSiteLists          = 16
	maxAccessPrefixes     = 32
	maxHotlinkSources     = 200
	maxHotlinkExtensions  = 64
	maxHotlinkRedirect    = 2048
	maxUserAgentRules     = 200
	maxUserAgentPattern   = 512
	maxCORSOrigins        = 100
	maxCORSMethods        = 16
	maxCORSHeaders        = 64
	maxCORSMaxAge         = 86400
	maxGeoEntries         = 256
	maxSubdivisionName    = 64
	maxWebSocketOrigins   = 100
	minWebSocketIdle      = 60
	maxWebSocketIdle      = 86400
	maxPermissionsPolicy  = 1024
	DefaultWebSocketIdle  = 3600
	accessOriginWildcard  = "*"
	accessHostAnyWildcard = "*"
)

// AccessControl is a site's access control in the site table (snake_case,
// parts omitted when unused). The data plane checks it in the edge layer
// (edgeweir.access): block lists, geo, CORS preflights, hotlink and user
// agents after the platform lists and before access authentication; CORS
// and security response headers in the header filter; WebSocket origins
// after the WebSocket switch. List ids name NodeConfig.ip_lists.
type AccessControl struct {
	BlockListIDs    []string               `json:"block_list_ids,omitempty"`
	AllowListIDs    []string               `json:"allow_list_ids,omitempty"`
	Hotlink         *HotlinkAccess         `json:"hotlink,omitempty"`
	UserAgents      *UserAgentAccess       `json:"user_agents,omitempty"`
	CORS            *CORSAccess            `json:"cors,omitempty"`
	Geo             *GeoAccess             `json:"geo,omitempty"`
	WebSocket       *WebSocketAccess       `json:"websocket,omitempty"`
	SecurityHeaders *SecurityHeadersAccess `json:"security_headers,omitempty"`
}

// HotlinkAccess is hotlink protection by Referer (and Origin): host forms
// "a.com", "*.a.com", ".a.com" and "*"; RedirectURL "" answers 403.
type HotlinkAccess struct {
	AllowEmpty          bool     `json:"allow_empty,omitempty"`
	AllowSiteDomains    bool     `json:"allow_site_domains,omitempty"`
	Allowed             []string `json:"allowed,omitempty"`
	Denied              []string `json:"denied,omitempty"`
	CheckOrigin         bool     `json:"check_origin,omitempty"`
	Extensions          []string `json:"extensions,omitempty"`
	PathPrefixes        []string `json:"path_prefixes,omitempty"`
	ExcludePathPrefixes []string `json:"exclude_path_prefixes,omitempty"`
	RedirectURL         string   `json:"redirect_url,omitempty"`
}

// UserAgentAccess holds user agent rules in the operator's order: an allow
// rule that matches passes, else a deny rule that matches refuses.
type UserAgentAccess struct {
	Rules               []UserAgentRule `json:"rules"`
	PathPrefixes        []string        `json:"path_prefixes,omitempty"`
	ExcludePathPrefixes []string        `json:"exclude_path_prefixes,omitempty"`
}

// UserAgentRule is a wildcard pattern ("" matches an empty or missing
// User-Agent) with its action.
type UserAgentRule struct {
	Pattern string `json:"pattern"`
	Allow   bool   `json:"allow,omitempty"`
}

// CORSAccess answers preflights at the edge and sets CORS response headers
// on requests in scope. Origin forms "scheme://host[:port]", "*." hosts,
// "*" alone (without credentials).
type CORSAccess struct {
	AllowedOrigins     []string `json:"allowed_origins"`
	AllowCredentials   bool     `json:"allow_credentials,omitempty"`
	AllowedMethods     []string `json:"allowed_methods"`
	AllowedHeaders     []string `json:"allowed_headers,omitempty"`
	EchoRequestHeaders bool     `json:"echo_request_headers,omitempty"`
	ExposedHeaders     []string `json:"exposed_headers,omitempty"`
	MaxAgeSeconds      uint32   `json:"max_age_seconds"`
	PreflightToOrigin  bool     `json:"preflight_to_origin,omitempty"`
	KeepOriginHeaders  bool     `json:"keep_origin_headers,omitempty"`
	PathPrefixes       []string `json:"path_prefixes,omitempty"`
}

// GeoAccess allows (AllowOnly) or denies requests in scope by country,
// "CC-subdivision" or ASN.
type GeoAccess struct {
	AllowOnly          bool     `json:"allow_only,omitempty"`
	Countries          []string `json:"countries,omitempty"`
	Subdivisions       []string `json:"subdivisions,omitempty"`
	ASNs               []uint32 `json:"asns,omitempty"`
	PathPrefixes       []string `json:"path_prefixes,omitempty"`
	ExceptPathPrefixes []string `json:"except_path_prefixes,omitempty"`
}

// WebSocketAccess restricts WebSocket upgrades to Origins (empty: every
// origin) and sets the idle timeout of upgraded connections in seconds
// (the default applied).
type WebSocketAccess struct {
	Origins            []string `json:"origins,omitempty"`
	IdleTimeoutSeconds uint32   `json:"idle_timeout_seconds"`
}

// SecurityHeadersAccess are the security response headers of a site ("":
// not set).
type SecurityHeadersAccess struct {
	Nosniff           bool   `json:"nosniff,omitempty"`
	FrameOptions      string `json:"frame_options,omitempty"`
	ReferrerPolicy    string `json:"referrer_policy,omitempty"`
	PermissionsPolicy string `json:"permissions_policy,omitempty"`
	HideServer        bool   `json:"hide_server,omitempty"`
	RemovePoweredBy   bool   `json:"remove_powered_by,omitempty"`
}

var (
	frameOptions     = []string{"", "DENY", "SAMEORIGIN"}
	referrerPolicies = []string{"", "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
		"same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url"}
	countryRE      = regexp.MustCompile(`^[A-Z]{2}$`)
	accessIPv4RE   = regexp.MustCompile(`^(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}$`)
	accessLabelRE  = regexp.MustCompile(`^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$`)
	accessOriginRE = regexp.MustCompile(`(?i)^(https?)://([^/?#@\s]+)$`)
	originPortRE   = regexp.MustCompile(`^[1-9][0-9]{0,4}$`)
	printableRE    = regexp.MustCompile(`^[\x20-\x7e]+$`)
)

// buildAccessControl validates a site's access control exactly as the
// console writes it (ADR-0039): what it never sends rejects the whole
// configuration, like an invalid access authentication rule (the closest
// analogue: both decide who reaches the site before its rules, so a part
// silently dropped would open the site). lists are the ids of
// NodeConfig.ip_lists; features the node's own (GeoIP databases, as for
// rules reading ip.geoip.*). Without any part it returns nil, so that the
// site table of a site without access control stays as before.
func buildAccessControl(s *nodev1.Site, lists map[string]bool, features []string) (*AccessControl, error) {
	a := s.GetAccessControl()
	if a == nil {
		return nil, nil
	}
	out := &AccessControl{}
	var err error
	if out.BlockListIDs, err = siteLists("block", a.GetBlockListIds(), lists); err != nil {
		return nil, err
	}
	if out.AllowListIDs, err = siteLists("allow", a.GetAllowListIds(), lists); err != nil {
		return nil, err
	}
	for _, id := range out.BlockListIDs {
		if slices.Contains(out.AllowListIDs, id) {
			return nil, fmt.Errorf("%w: IP list %q is both a block and an allow list of the site", ErrRejected, id)
		}
	}
	if h := a.GetHotlink(); h != nil {
		if out.Hotlink, err = buildHotlink(h); err != nil {
			return nil, err
		}
	}
	if u := a.GetUserAgents(); u != nil {
		if out.UserAgents, err = buildUserAgents(u); err != nil {
			return nil, err
		}
	}
	if c := a.GetCors(); c != nil {
		if out.CORS, err = buildCORS(c); err != nil {
			return nil, err
		}
	}
	if g := a.GetGeo(); g != nil {
		if out.Geo, err = buildGeo(g, features); err != nil {
			return nil, err
		}
	}
	if w := a.GetWebsocket(); w != nil {
		if out.WebSocket, err = buildWebSocketAccess(w); err != nil {
			return nil, err
		}
	}
	if h := a.GetSecurityHeaders(); h != nil {
		if out.SecurityHeaders, err = buildSecurityHeaders(h); err != nil {
			return nil, err
		}
	}
	if len(out.BlockListIDs) == 0 && len(out.AllowListIDs) == 0 && out.Hotlink == nil && out.UserAgents == nil &&
		out.CORS == nil && out.Geo == nil && out.WebSocket == nil && out.SecurityHeaders == nil {
		return nil, nil
	}
	return out, nil
}

// siteLists checks the ids of a site's block or allow lists: at most 16
// ids of NodeConfig.ip_lists.
func siteLists(kind string, ids []string, lists map[string]bool) ([]string, error) {
	if len(ids) > maxSiteLists {
		return nil, fmt.Errorf("%w: more than %d site %s lists", ErrRejected, maxSiteLists, kind)
	}
	for _, id := range ids {
		if !lists[id] {
			return nil, fmt.Errorf("%w: unknown site %s list %q", ErrRejected, kind, id)
		}
	}
	return slices.Clone(ids), nil
}

func accessPrefixes(list []string) ([]string, error) {
	if len(list) > maxAccessPrefixes {
		return nil, fmt.Errorf("%w: too many path prefixes", ErrRejected)
	}
	return authPrefixes(list)
}

func buildHotlink(h *nodev1.Hotlink) (*HotlinkAccess, error) {
	out := &HotlinkAccess{AllowEmpty: h.GetAllowEmpty(), AllowSiteDomains: h.GetAllowSiteDomains(), CheckOrigin: h.GetCheckOrigin()}
	if len(h.GetAllowed()) > maxHotlinkSources || len(h.GetDenied()) > maxHotlinkSources {
		return nil, fmt.Errorf("%w: too many hotlink sources", ErrRejected)
	}
	for _, list := range [][]string{h.GetAllowed(), h.GetDenied()} {
		for _, f := range list {
			if !ValidHostForm(f) {
				return nil, fmt.Errorf("%w: invalid hotlink source %q", ErrRejected, f)
			}
		}
	}
	out.Allowed, out.Denied = slices.Clone(h.GetAllowed()), slices.Clone(h.GetDenied())
	if len(h.GetExtensions()) > maxHotlinkExtensions {
		return nil, fmt.Errorf("%w: too many hotlink extensions", ErrRejected)
	}
	for _, e := range h.GetExtensions() {
		if !authExtensionRE.MatchString(e) {
			return nil, fmt.Errorf("%w: invalid hotlink extension %q", ErrRejected, e)
		}
	}
	out.Extensions = slices.Clone(h.GetExtensions())
	var err error
	if out.PathPrefixes, err = accessPrefixes(h.GetPathPrefixes()); err != nil {
		return nil, err
	}
	if out.ExcludePathPrefixes, err = accessPrefixes(h.GetExcludePathPrefixes()); err != nil {
		return nil, err
	}
	if r := h.GetRedirectUrl(); r != "" {
		if !validHotlinkRedirect(r) {
			return nil, fmt.Errorf("%w: invalid hotlink redirect URL", ErrRejected)
		}
		out.RedirectURL = r
	}
	return out, nil
}

// validHotlinkRedirect reports whether v is a hotlink redirect target as
// the console checks static redirect targets: a site path ("/..." not
// "//...") or an http(s) URL with a host and without credentials or
// whitespace; never control characters or backslashes; at most 2048
// characters.
func validHotlinkRedirect(v string) bool {
	if !utf8.ValidString(v) || utf8.RuneCountInString(v) > maxHotlinkRedirect || hasControl(v) || strings.Contains(v, `\`) {
		return false
	}
	if !strings.HasPrefix(v, "/") && strings.ContainsFunc(v, unicode.IsSpace) {
		return false
	}
	return validRedirectLocation(v)
}

func buildUserAgents(u *nodev1.UserAgentRules) (*UserAgentAccess, error) {
	if len(u.GetRules()) < 1 || len(u.GetRules()) > maxUserAgentRules {
		return nil, fmt.Errorf("%w: 1 to %d user agent rules", ErrRejected, maxUserAgentRules)
	}
	out := &UserAgentAccess{}
	for _, r := range u.GetRules() {
		if !ValidUserAgentPattern(r.GetPattern()) {
			return nil, fmt.Errorf("%w: invalid user agent pattern %q", ErrRejected, r.GetPattern())
		}
		out.Rules = append(out.Rules, UserAgentRule{Pattern: r.GetPattern(), Allow: r.GetAllow()})
	}
	var err error
	if out.PathPrefixes, err = accessPrefixes(u.GetPathPrefixes()); err != nil {
		return nil, err
	}
	if out.ExcludePathPrefixes, err = accessPrefixes(u.GetExcludePathPrefixes()); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidUserAgentPattern reports whether p is a user agent pattern: "" or
// 1-512 printable ASCII bytes forming a wildcard of the rule engine (a
// backslash only in "\*" or "\\", at most 8 "*").
func ValidUserAgentPattern(p string) bool {
	if p == "" {
		return true
	}
	return len(p) <= maxUserAgentPattern && printableRE.MatchString(p) && wildcardStars(p) >= 0
}

func buildCORS(c *nodev1.Cors) (*CORSAccess, error) {
	origins := c.GetAllowedOrigins()
	if len(origins) < 1 || len(origins) > maxCORSOrigins {
		return nil, fmt.Errorf("%w: 1 to %d CORS origins", ErrRejected, maxCORSOrigins)
	}
	for _, o := range origins {
		if o == accessOriginWildcard {
			if c.GetAllowCredentials() {
				return nil, fmt.Errorf("%w: CORS origin \"*\" with credentials", ErrRejected)
			}
			continue
		}
		if !ValidOriginForm(o) {
			return nil, fmt.Errorf("%w: invalid CORS origin %q", ErrRejected, o)
		}
	}
	methods := c.GetAllowedMethods()
	if len(methods) < 1 || len(methods) > maxCORSMethods {
		return nil, fmt.Errorf("%w: 1 to %d CORS methods", ErrRejected, maxCORSMethods)
	}
	for _, m := range methods {
		if !tokenRE.MatchString(m) || m != strings.ToUpper(m) {
			return nil, fmt.Errorf("%w: invalid CORS method %q", ErrRejected, m)
		}
	}
	if len(c.GetAllowedHeaders()) > maxCORSHeaders || len(c.GetExposedHeaders()) > maxCORSHeaders {
		return nil, fmt.Errorf("%w: too many CORS headers", ErrRejected)
	}
	for _, h := range c.GetAllowedHeaders() {
		if !lowerTokenRE.MatchString(h) {
			return nil, fmt.Errorf("%w: invalid CORS request header %q", ErrRejected, h)
		}
	}
	for _, h := range c.GetExposedHeaders() {
		if !tokenRE.MatchString(h) {
			return nil, fmt.Errorf("%w: invalid CORS exposed header %q", ErrRejected, h)
		}
	}
	if c.GetMaxAgeSeconds() > maxCORSMaxAge {
		return nil, fmt.Errorf("%w: CORS max age out of range", ErrRejected)
	}
	prefixes, err := accessPrefixes(c.GetPathPrefixes())
	if err != nil {
		return nil, err
	}
	return &CORSAccess{
		AllowedOrigins: slices.Clone(origins), AllowCredentials: c.GetAllowCredentials(),
		AllowedMethods: slices.Clone(methods), AllowedHeaders: slices.Clone(c.GetAllowedHeaders()),
		EchoRequestHeaders: c.GetEchoRequestHeaders(), ExposedHeaders: slices.Clone(c.GetExposedHeaders()),
		MaxAgeSeconds: c.GetMaxAgeSeconds(), PreflightToOrigin: c.GetPreflightToOrigin(),
		KeepOriginHeaders: c.GetKeepOriginHeaders(), PathPrefixes: prefixes,
	}, nil
}

// buildGeo checks geo access; its lists need the node's GeoIP databases
// like rules reading the same fields (countries: ip.geoip.country,
// subdivisions: ip.geoip.subdivision, ASNs: ip.geoip.asnum).
func buildGeo(g *nodev1.GeoAccess, features []string) (*GeoAccess, error) {
	if len(g.GetCountries()) > maxGeoEntries || len(g.GetSubdivisions()) > maxGeoEntries || len(g.GetAsns()) > maxGeoEntries {
		return nil, fmt.Errorf("%w: too many geo entries", ErrRejected)
	}
	for _, c := range g.GetCountries() {
		if !countryRE.MatchString(c) {
			return nil, fmt.Errorf("%w: invalid country %q", ErrRejected, c)
		}
	}
	for _, s := range g.GetSubdivisions() {
		if !validSubdivision(s) {
			return nil, fmt.Errorf("%w: invalid subdivision %q", ErrRejected, s)
		}
	}
	for _, n := range g.GetAsns() {
		if n == 0 {
			return nil, fmt.Errorf("%w: ASN 0", ErrRejected)
		}
	}
	for _, use := range []struct {
		field string
		used  bool
	}{
		{"ip.geoip.country", len(g.GetCountries()) > 0},
		{"ip.geoip.subdivision", len(g.GetSubdivisions()) > 0},
		{"ip.geoip.asnum", len(g.GetAsns()) > 0},
	} {
		if feature := geoFeatures[use.field]; use.used && !slices.Contains(features, feature) {
			return nil, fmt.Errorf("%w: geo access needs %s, GeoIP database unavailable", ErrRejected, feature)
		}
	}
	out := &GeoAccess{AllowOnly: g.GetAllowOnly(), Countries: slices.Clone(g.GetCountries()),
		Subdivisions: slices.Clone(g.GetSubdivisions()), ASNs: slices.Clone(g.GetAsns())}
	var err error
	if out.PathPrefixes, err = accessPrefixes(g.GetPathPrefixes()); err != nil {
		return nil, err
	}
	if out.ExceptPathPrefixes, err = accessPrefixes(g.GetExceptPathPrefixes()); err != nil {
		return nil, err
	}
	return out, nil
}

// validSubdivision reports whether s is "CC-subdivision": an uppercase
// country code, "-" and 1-64 bytes of UTF-8 without control characters
// (ip.geoip.subdivision, a code or a name).
func validSubdivision(s string) bool {
	if len(s) < 4 || !countryRE.MatchString(s[:2]) || s[2] != '-' {
		return false
	}
	rest := s[3:]
	return len(rest) <= maxSubdivisionName && utf8.ValidString(rest) && !hasControl(rest)
}

func buildWebSocketAccess(w *nodev1.WebSocketAccess) (*WebSocketAccess, error) {
	if len(w.GetOrigins()) > maxWebSocketOrigins {
		return nil, fmt.Errorf("%w: too many WebSocket origins", ErrRejected)
	}
	for _, o := range w.GetOrigins() {
		if !ValidOriginForm(o) {
			return nil, fmt.Errorf("%w: invalid WebSocket origin %q", ErrRejected, o)
		}
	}
	idle := w.GetIdleTimeoutSeconds()
	switch {
	case idle == 0:
		idle = DefaultWebSocketIdle
	case idle < minWebSocketIdle || idle > maxWebSocketIdle:
		return nil, fmt.Errorf("%w: WebSocket idle timeout out of range", ErrRejected)
	}
	return &WebSocketAccess{Origins: slices.Clone(w.GetOrigins()), IdleTimeoutSeconds: idle}, nil
}

func buildSecurityHeaders(h *nodev1.SecurityHeaders) (*SecurityHeadersAccess, error) {
	if !slices.Contains(frameOptions, h.GetFrameOptions()) || !slices.Contains(referrerPolicies, h.GetReferrerPolicy()) {
		return nil, fmt.Errorf("%w: invalid X-Frame-Options or Referrer-Policy", ErrRejected)
	}
	if p := h.GetPermissionsPolicy(); p != "" && (len(p) > maxPermissionsPolicy || !printableRE.MatchString(p)) {
		return nil, fmt.Errorf("%w: invalid Permissions-Policy", ErrRejected)
	}
	return &SecurityHeadersAccess{
		Nosniff: h.GetNosniff(), FrameOptions: h.GetFrameOptions(), ReferrerPolicy: h.GetReferrerPolicy(),
		PermissionsPolicy: h.GetPermissionsPolicy(), HideServer: h.GetHideServer(), RemovePoweredBy: h.GetRemovePoweredBy(),
	}, nil
}

// accessHostName reports whether host is a host name of the access control
// forms (the console's validHostName): an IPv4 address, or labels of
// [a-z0-9_-] (no "-" at either end, at most 63 bytes) of at most 253 bytes
// in all.
func accessHostName(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	if accessIPv4RE.MatchString(host) {
		return true
	}
	for label := range strings.SplitSeq(host, ".") {
		if !accessLabelRE.MatchString(label) {
			return false
		}
	}
	return true
}

// ValidHostForm reports whether f is a hotlink source as the console
// stores it (normalizeHostForm): "*", "a.com", "*.a.com" or ".a.com",
// lowercase, without a trailing dot; the wildcard forms never over an IPv4
// address.
func ValidHostForm(f string) bool {
	switch {
	case f == accessHostAnyWildcard:
		return true
	case strings.HasPrefix(f, "*."):
		return accessHostName(f[2:]) && !accessIPv4RE.MatchString(f[2:])
	case strings.HasPrefix(f, "."):
		return accessHostName(f[1:]) && !accessIPv4RE.MatchString(f[1:])
	}
	return accessHostName(f)
}

// NormalizeOriginForm returns a CORS or WebSocket origin as the console
// stores it (normalizeOriginForm without "*"): "scheme://host[:port]",
// http or https, lowercase, the default port left out, the host may start
// with "*.". ok is false when text is no such origin.
func NormalizeOriginForm(text string) (string, bool) {
	m := accessOriginRE.FindStringSubmatch(strings.TrimSpace(text))
	if m == nil {
		return "", false
	}
	scheme, authority := strings.ToLower(m[1]), m[2]
	host, port := authority, ""
	if i := strings.LastIndexByte(authority, ':'); i >= 0 {
		host, port = authority[:i], authority[i+1:]
	}
	host = strings.ToLower(host)
	if port != "" {
		n, err := strconv.Atoi(port)
		if !originPortRE.MatchString(port) || err != nil || n > 65535 {
			return "", false
		}
		if (scheme == SchemeHTTP && n == 80) || (scheme == SchemeHTTPS && n == 443) {
			port = ""
		}
	}
	if rest, wild := strings.CutPrefix(host, "*."); wild {
		if !accessHostName(rest) || accessIPv4RE.MatchString(rest) {
			return "", false
		}
	} else if !accessHostName(host) {
		return "", false
	}
	out := scheme + "://" + host
	if port != "" {
		out += ":" + port
	}
	return out, true
}

// ValidOriginForm reports whether o is an origin form as stored (its own
// normalized form).
func ValidOriginForm(o string) bool {
	n, ok := NormalizeOriginForm(o)
	return ok && n == o
}
