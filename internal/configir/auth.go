package configir

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// FeatureAccessAuth (proto v0.27.0, ADR-0038): Site.auth_rules, the
// access authentication of a site (Basic, forward authentication, signed
// URLs of kinds A-D) before its rule phases and cache lookup, and
// MinuteStats.auth_failures. The console requires it when a site has an
// enabled rule.
const FeatureAccessAuth = "access-auth-v1"

// Kinds of access authentication rules, as the site table names them.
const (
	AuthBasic   = "basic"
	AuthForward = "forward"
	AuthURLA    = "url_a"
	AuthURLB    = "url_b"
	AuthURLC    = "url_c"
	AuthURLD    = "url_d"
)

var authKinds = map[nodev1.AuthKind]string{
	nodev1.AuthKind_AUTH_KIND_BASIC:   AuthBasic,
	nodev1.AuthKind_AUTH_KIND_FORWARD: AuthForward,
	nodev1.AuthKind_AUTH_KIND_URL_A:   AuthURLA,
	nodev1.AuthKind_AUTH_KIND_URL_B:   AuthURLB,
	nodev1.AuthKind_AUTH_KIND_URL_C:   AuthURLC,
	nodev1.AuthKind_AUTH_KIND_URL_D:   AuthURLD,
}

// Limits of a site's access authentication (the console's).
const (
	maxAuthRules              = 16
	maxAuthDomains            = 50
	maxAuthPrefixes           = 32
	maxAuthExtensions         = 64
	maxForwardRequestHeaders  = 16
	maxForwardResponseHeaders = 8
	maxForwardURL             = 2048
	maxURLAuthValidity        = 31536000
	maxURLAuthSkew            = 600
	maxForwardCacheSeconds    = 300
	maxBasicUsers             = 100
	// Basic hashes: PBKDF2-HMAC-SHA256 iterations the node computes.
	minBasicIterations = 1000
	maxBasicIterations = 200000
)

// AuthRule is a site's access authentication rule. Users and Keys come from
// the rule's secret (the agent attaches them, AttachCredentials); a rule
// whose secret is unavailable keeps neither and refuses every request in its
// scope.
type AuthRule struct {
	ID                  string       `json:"id"`
	Kind                string       `json:"kind"`
	Domains             []string     `json:"domains,omitempty"`
	PathPrefixes        []string     `json:"path_prefixes,omitempty"`
	Extensions          []string     `json:"extensions,omitempty"`
	ExcludePathPrefixes []string     `json:"exclude_path_prefixes,omitempty"`
	Basic               *BasicAuth   `json:"basic,omitempty"`
	Forward             *ForwardAuth `json:"forward,omitempty"`
	URL                 *URLAuth     `json:"url,omitempty"`
	// Credential names the secret; SecretVersion is the attached one's
	// version (it keys the data plane's caches of results).
	Credential    *PurgeRef   `json:"-"`
	SecretVersion uint64      `json:"secret_version,omitempty"`
	Users         []BasicUser `json:"users,omitempty"`
	Keys          []string    `json:"keys,omitempty"`
}

// BasicAuth holds a Basic rule's settings.
type BasicAuth struct {
	Realm             string `json:"realm"`
	KeepAuthorization bool   `json:"keep_authorization,omitempty"`
	UserHeader        bool   `json:"user_header,omitempty"`
}

// BasicUser is a Basic user with the parts of its PBKDF2-HMAC-SHA256 hash
// (salt and hash in lowercase hex).
type BasicUser struct {
	Name       string `json:"name"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
}

// ForwardAuth holds a forward authentication rule's settings, with its URL
// split for the origin layer: Address is resolved (and checked against the
// origin address policy) like an origin's, HostHeader and URI make the
// request line, SNI is the name verified over TLS ("" for IP literals).
type ForwardAuth struct {
	URL              string   `json:"url"`
	Scheme           string   `json:"scheme"`
	Address          string   `json:"address"`
	Port             uint32   `json:"port"`
	HostHeader       string   `json:"host_header"`
	URI              string   `json:"uri"`
	SNI              string   `json:"sni,omitempty"`
	Forbidden        bool     `json:"forbidden,omitempty"`
	Head             bool     `json:"head,omitempty"`
	TimeoutMS        uint32   `json:"timeout_ms"`
	RequestHeaders   []string `json:"request_headers,omitempty"`
	ResponseHeaders  []string `json:"response_headers,omitempty"`
	CacheSeconds     uint32   `json:"cache_seconds,omitempty"`
	PassRedirects    bool     `json:"pass_redirects,omitempty"`
	AllowUnavailable bool     `json:"allow_unavailable,omitempty"`
}

// URLAuth holds a signed URL rule's settings.
type URLAuth struct {
	ValiditySeconds uint32 `json:"validity_seconds"`
	SkewSeconds     uint32 `json:"skew_seconds"`
	SignParam       string `json:"sign_param"`
	TimeParam       string `json:"time_param"`
}

var (
	authParamRE     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	authExtensionRE = regexp.MustCompile(`^[a-z0-9]{1,16}$`)
	authKeyRE       = regexp.MustCompile(`^[\x21-\x7e]{16,128}$`)
	basicNameRE     = regexp.MustCompile(`^[\x21-\x39\x3b-\x7e]{1,64}$`)
	basicHashRE     = regexp.MustCompile(`^pbkdf2-sha256\$([0-9]{4,6})\$([0-9a-f]{32})\$([0-9a-f]{64})$`)
	lowerTokenRE    = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9a-z-]{1,64}$")
)

// Request headers forward authentication never forwards from the visitor:
// hop-by-hop ones, Host and the ones the node sets itself.
var forwardUnforwardable = map[string]bool{
	"host": true, "connection": true, "upgrade": true, "te": true, "trailer": true,
	"transfer-encoding": true, "content-length": true, "keep-alive": true, "proxy-connection": true,
	"x-original-uri": true, "x-original-method": true, "x-original-host": true, "x-real-ip": true,
	"x-forwarded-for": true,
}

// Headers a forward authentication answer cannot set on the request
// towards the origin (the rules' protected headers).
var forwardProtected = map[string]bool{
	"host": true, "authorization": true, "proxy-authorization": true, "cookie": true, "set-cookie": true,
	"content-length": true, "transfer-encoding": true, "connection": true, "upgrade": true, "te": true,
	"trailer": true, "cdn-loop": true,
}

// buildAuthRules validates a site's access authentication rules; any
// invalid rule rejects the configuration (the console never sends one).
// The forward authentication URL's IP literal outside the origin allow list
// is marked Forbidden (its requests fail as unavailable), as origins are.
func buildAuthRules(s *nodev1.Site, policy AddressPolicy) ([]AuthRule, error) {
	if len(s.GetAuthRules()) > maxAuthRules {
		return nil, fmt.Errorf("more than %d access authentication rules", maxAuthRules)
	}
	var out []AuthRule
	seen := map[string]bool{}
	for _, r := range s.GetAuthRules() {
		rule, err := buildAuthRule(r, policy)
		if err != nil {
			return nil, fmt.Errorf("access authentication rule %q: %w", r.GetId(), err)
		}
		if seen[rule.ID] {
			return nil, fmt.Errorf("access authentication rule %q twice", rule.ID)
		}
		seen[rule.ID] = true
		out = append(out, rule)
	}
	return out, nil
}

func buildAuthRule(r *nodev1.AuthRule, policy AddressPolicy) (AuthRule, error) {
	kind, ok := authKinds[r.GetKind()]
	if !ok || !idRE.MatchString(r.GetId()) {
		return AuthRule{}, fmt.Errorf("%w: invalid id or kind", ErrRejected)
	}
	out := AuthRule{ID: r.GetId(), Kind: kind}
	if len(r.GetDomains()) > maxAuthDomains {
		return AuthRule{}, fmt.Errorf("%w: too many domains", ErrRejected)
	}
	for _, d := range r.GetDomains() {
		if !validScopeDomain(d) {
			return AuthRule{}, fmt.Errorf("%w: invalid domain %q", ErrRejected, d)
		}
		out.Domains = append(out.Domains, d)
	}
	var err error
	if out.PathPrefixes, err = authPrefixes(r.GetPathPrefixes()); err != nil {
		return AuthRule{}, err
	}
	if out.ExcludePathPrefixes, err = authPrefixes(r.GetExcludePathPrefixes()); err != nil {
		return AuthRule{}, err
	}
	if len(r.GetExtensions()) > maxAuthExtensions {
		return AuthRule{}, fmt.Errorf("%w: too many extensions", ErrRejected)
	}
	for _, e := range r.GetExtensions() {
		if !authExtensionRE.MatchString(e) {
			return AuthRule{}, fmt.Errorf("%w: invalid extension %q", ErrRejected, e)
		}
		out.Extensions = append(out.Extensions, e)
	}
	hasSecret := r.GetCredentialId() != ""
	if hasSecret {
		if !idRE.MatchString(r.GetCredentialId()) {
			return AuthRule{}, fmt.Errorf("%w: invalid credential id", ErrRejected)
		}
		out.Credential = &PurgeRef{CredentialID: r.GetCredentialId(), CredentialVersion: r.GetCredentialVersion()}
	}
	parts := 0
	for _, set := range []bool{r.GetBasic() != nil, r.GetForward() != nil, r.GetUrl() != nil} {
		if set {
			parts++
		}
	}
	if parts != 1 {
		return AuthRule{}, fmt.Errorf("%w: exactly one of basic, forward and url", ErrRejected)
	}
	switch kind {
	case AuthBasic:
		b := r.GetBasic()
		if b == nil || !hasSecret {
			return AuthRule{}, fmt.Errorf("%w: basic settings and credential required", ErrRejected)
		}
		realm := b.GetRealm()
		if n := utf8.RuneCountInString(realm); !utf8.ValidString(realm) || n < 1 || n > 64 || hasControl(realm) || strings.ContainsAny(realm, "\"\\") {
			return AuthRule{}, fmt.Errorf("%w: invalid realm", ErrRejected)
		}
		out.Basic = &BasicAuth{Realm: realm, KeepAuthorization: b.GetKeepAuthorization(), UserHeader: b.GetUserHeader()}
	case AuthForward:
		f := r.GetForward()
		if f == nil || hasSecret {
			return AuthRule{}, fmt.Errorf("%w: forward settings without a credential required", ErrRejected)
		}
		if out.Forward, err = buildForwardAuth(f, policy); err != nil {
			return AuthRule{}, err
		}
	default:
		u := r.GetUrl()
		if u == nil || !hasSecret {
			return AuthRule{}, fmt.Errorf("%w: url settings and credential required", ErrRejected)
		}
		if u.GetValiditySeconds() < 1 || u.GetValiditySeconds() > maxURLAuthValidity || u.GetSkewSeconds() > maxURLAuthSkew ||
			!authParamRE.MatchString(u.GetSignParam()) || !authParamRE.MatchString(u.GetTimeParam()) ||
			(kind == AuthURLD && u.GetSignParam() == u.GetTimeParam()) {
			return AuthRule{}, fmt.Errorf("%w: invalid url settings", ErrRejected)
		}
		out.URL = &URLAuth{ValiditySeconds: u.GetValiditySeconds(), SkewSeconds: u.GetSkewSeconds(), SignParam: u.GetSignParam(), TimeParam: u.GetTimeParam()}
	}
	return out, nil
}

// validScopeDomain reports whether a scope domain is a site domain in its
// written form: a host name, *.host, .host or ~pattern.
func validScopeDomain(d string) bool {
	switch {
	case strings.HasPrefix(d, "~"):
		return domainProblem(d[1:], false, MatchRegex, true) == ""
	case strings.HasPrefix(d, "*."):
		return domainProblem(d[2:], true, "", true) == ""
	case strings.HasPrefix(d, "."):
		return domainProblem(d[1:], false, MatchSuffix, true) == ""
	}
	return domainProblem(d, false, "", true) == ""
}

func authPrefixes(list []string) ([]string, error) {
	if len(list) > maxAuthPrefixes {
		return nil, fmt.Errorf("%w: too many path prefixes", ErrRejected)
	}
	var out []string
	for _, p := range list {
		if !strings.HasPrefix(p, "/") || len(p) > 1024 || !utf8.ValidString(p) || hasControl(p) || strings.ContainsAny(p, " ?#") {
			return nil, fmt.Errorf("%w: invalid path prefix %q", ErrRejected, p)
		}
		out = append(out, p)
	}
	return out, nil
}

// buildForwardAuth validates a forward authentication rule and splits its URL.
func buildForwardAuth(f *nodev1.ForwardAuth, policy AddressPolicy) (*ForwardAuth, error) {
	raw := f.GetUrl()
	u, err := url.Parse(raw)
	if err != nil || len(raw) > maxForwardURL || (u.Scheme != SchemeHTTP && u.Scheme != SchemeHTTPS) || u.User != nil ||
		u.Fragment != "" || strings.Contains(raw, "#") || u.Opaque != "" || u.Host == "" || strings.ContainsAny(raw, " \t\\") || hasControl(raw) {
		return nil, fmt.Errorf("%w: invalid forward authentication URL", ErrRejected)
	}
	host := strings.ToLower(u.Hostname())
	out := &ForwardAuth{URL: raw, Scheme: u.Scheme, Address: host}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return nil, fmt.Errorf("%w: zoned forward authentication address", ErrRejected)
		}
		out.Address = ip.String()
		out.Forbidden = policy.Forbidden(ip)
	} else if !ValidHostname(host) {
		return nil, fmt.Errorf("%w: invalid forward authentication host", ErrRejected)
	} else {
		out.SNI = host
	}
	out.Port = 80
	if u.Scheme == SchemeHTTPS {
		out.Port = 443
	}
	authority := u.Host
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%w: invalid forward authentication port", ErrRejected)
		}
		if uint32(n) == out.Port {
			authority = strings.TrimSuffix(u.Host, ":"+p)
		}
		out.Port = uint32(n)
	}
	out.HostHeader = strings.ToLower(authority)
	// The request URI exactly as written after the authority.
	rest := raw[len(u.Scheme)+3+len(u.Host):]
	if rest == "" {
		rest = "/"
	} else if rest[0] == '?' {
		rest = "/" + rest
	}
	out.URI = rest
	if f.GetTimeoutMs() < 100 || f.GetTimeoutMs() > 10000 || f.GetCacheSeconds() > maxForwardCacheSeconds ||
		len(f.GetRequestHeaders()) > maxForwardRequestHeaders || len(f.GetResponseHeaders()) > maxForwardResponseHeaders {
		return nil, fmt.Errorf("%w: invalid forward authentication settings", ErrRejected)
	}
	for _, h := range f.GetRequestHeaders() {
		if !lowerTokenRE.MatchString(h) || forwardUnforwardable[h] || strings.HasPrefix(h, "x-edgeweir-") {
			return nil, fmt.Errorf("%w: header %q cannot be forwarded", ErrRejected, h)
		}
		out.RequestHeaders = append(out.RequestHeaders, h)
	}
	for _, h := range f.GetResponseHeaders() {
		if !lowerTokenRE.MatchString(h) || forwardProtected[h] || strings.HasPrefix(h, "x-edgeweir-") {
			return nil, fmt.Errorf("%w: header %q cannot be copied", ErrRejected, h)
		}
		out.ResponseHeaders = append(out.ResponseHeaders, h)
	}
	out.Head, out.TimeoutMS, out.CacheSeconds = f.GetHead(), f.GetTimeoutMs(), f.GetCacheSeconds()
	out.PassRedirects, out.AllowUnavailable = f.GetPassRedirects(), f.GetAllowUnavailable()
	return out, nil
}

// attachAuthSecret fills a rule's users or keys from its secret (the JSON
// document of GetOriginCredentials). It returns why the secret cannot be
// used ("" when it can): the rule then keeps no users or keys. Invalid
// entries are left out.
func (r *AuthRule) attachAuthSecret(c Credential, ok bool) string {
	r.Users, r.Keys, r.SecretVersion = nil, nil, 0
	if r.Credential == nil {
		return ""
	}
	if !ok || c.Version < r.Credential.CredentialVersion || c.SecretKey == "" {
		return fmt.Sprintf("secret %s (version %d) unavailable", r.Credential.CredentialID, r.Credential.CredentialVersion)
	}
	var doc struct {
		Users []struct {
			Name string `json:"name"`
			Hash string `json:"hash"`
		} `json:"users"`
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal([]byte(c.SecretKey), &doc); err != nil {
		return "unreadable secret"
	}
	r.SecretVersion = c.Version
	if r.Kind == AuthBasic {
		for _, u := range doc.Users {
			m := basicHashRE.FindStringSubmatch(u.Hash)
			if !basicNameRE.MatchString(u.Name) || m == nil || len(r.Users) >= maxBasicUsers {
				continue
			}
			n, _ := strconv.Atoi(m[1])
			if n < minBasicIterations || n > maxBasicIterations {
				continue
			}
			r.Users = append(r.Users, BasicUser{Name: u.Name, Iterations: n, Salt: m[2], Hash: m[3]})
		}
		if len(r.Users) == 0 {
			return "secret without usable users"
		}
		return ""
	}
	for _, k := range doc.Keys {
		if authKeyRE.MatchString(k) && len(r.Keys) < 2 {
			r.Keys = append(r.Keys, k)
		}
	}
	if len(r.Keys) == 0 {
		return "secret without usable keys"
	}
	return ""
}
