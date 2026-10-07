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

// Features of proto v0.24.0. FeatureSiteContent covers the site settings
// of that version: cache keys that drop parameters, caching responses with
// Set-Cookie, the PURGE method, hiding X-Cache, error pages for more
// statuses, classes and redirects, maintenance mode, charsets, the gzip
// level and the largest compressed response, request body limits and
// origin retries. FeatureCacheZone covers per-node cache zone sizes and
// the cache usage in ReportStatus.
const (
	FeatureSiteContent = "site-content-v1"
	FeatureCacheZone   = "cache-zone-v1"
)

// Bounds of the proto v0.24.0 settings.
const (
	// DefaultRequestBodyLimit is a site's body limit when it sets none (and
	// the data plane's when no site is published): nginx's former global
	// client_max_body_size.
	DefaultRequestBodyLimit uint64 = 100 << 20
	MaxRequestBodyLimit     uint64 = 10 << 30
	// MinCacheZoneMB and MaxCacheZoneMB bound per-node cache sizes (1 GiB to
	// 64 TiB), MinKeysZoneMB and MaxKeysZoneMB their key zones.
	MinCacheZoneMB = 1024
	MaxCacheZoneMB = 64 << 20
	MinKeysZoneMB  = 16
	MaxKeysZoneMB  = 512
	// DefaultOriginTries is how many origins a request tries without
	// OriginPool.tries; MaxOriginTries bounds it (and the origin layer's
	// proxy_next_upstream_tries).
	DefaultOriginTries     = 3
	MaxOriginTries         = 5
	maxMaintenanceCIDRs    = 64
	maxMaintenancePrefixes = 32
	maxRetryAfterSeconds   = 86400
	maxErrorRedirectURL    = 2048
)

// Charsets a site may add to its text responses (Site.charset).
var Charsets = []string{"utf-8", "gbk", "gb18030", "gb2312", "big5", "iso-8859-1", "shift_jis", "euc-kr"}

// Maintenance is a site's maintenance mode (site table field
// "maintenance"; lua/edgeweir/maintenance.lua).
type Maintenance struct {
	Template      string   `json:"template,omitempty"`
	RetryAfter    uint32   `json:"retry_after,omitempty"`
	AllowCIDRs    []string `json:"allow_cidrs,omitempty"`
	AllowPrefixes []string `json:"allow_prefixes,omitempty"`
}

// Charset is a site's charset setting (site table field "charset").
type Charset struct {
	Name      string `json:"name"`
	Force     bool   `json:"force,omitempty"`
	Uppercase bool   `json:"uppercase,omitempty"`
}

// PurgeRef names the key of a site's PURGE method (fetched like S3
// credentials, never pushed to the data plane).
type PurgeRef struct {
	CredentialID      string
	CredentialVersion uint64
}

// buildMaintenance validates a site's maintenance mode (nil: off).
func buildMaintenance(m *nodev1.Maintenance) (*Maintenance, error) {
	if m == nil {
		return nil, nil
	}
	if len(m.GetTemplate()) > MaxErrorPageBytes {
		return nil, fmt.Errorf("%w: maintenance page exceeds %d bytes", ErrRejected, MaxErrorPageBytes)
	}
	if m.GetRetryAfterSeconds() > maxRetryAfterSeconds {
		return nil, fmt.Errorf("%w: maintenance Retry-After out of range", ErrRejected)
	}
	if len(m.GetAllowedCidrs()) > maxMaintenanceCIDRs || len(m.GetAllowedPathPrefixes()) > maxMaintenancePrefixes {
		return nil, fmt.Errorf("%w: too many maintenance exceptions", ErrRejected)
	}
	out := &Maintenance{Template: m.GetTemplate(), RetryAfter: m.GetRetryAfterSeconds()}
	for _, c := range m.GetAllowedCidrs() {
		// Host bits zero, as the console normalizes them (its text of an
		// IPv4-mapped address may differ from Go's, so no string compare).
		prefix, err := netip.ParsePrefix(c)
		if err != nil || prefix.Masked() != prefix {
			return nil, fmt.Errorf("%w: invalid maintenance CIDR %q", ErrRejected, c)
		}
		// The data plane looks IPv4 clients up as IPv4 (a mapped client
		// address is unmapped first), so an IPv4-mapped prefix becomes the
		// IPv4 prefix it covers; a shorter one covers no mapped address only.
		if a := prefix.Addr(); a.Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(a.Unmap(), prefix.Bits()-96)
		}
		out.AllowCIDRs = append(out.AllowCIDRs, prefix.String())
	}
	for _, p := range m.GetAllowedPathPrefixes() {
		if !strings.HasPrefix(p, "/") || len(p) > 1024 || hasControl(p) || strings.ContainsAny(p, " ?#") {
			return nil, fmt.Errorf("%w: invalid maintenance path prefix %q", ErrRejected, p)
		}
		out.AllowPrefixes = append(out.AllowPrefixes, p)
	}
	return out, nil
}

// buildCharset validates a site's charset setting (nil: off).
func buildCharset(c *nodev1.Charset) (*Charset, error) {
	if c == nil {
		return nil, nil
	}
	if !slices.Contains(Charsets, c.GetName()) {
		return nil, fmt.Errorf("%w: unsupported charset %q", ErrRejected, c.GetName())
	}
	return &Charset{Name: c.GetName(), Force: c.GetForce(), Uppercase: c.GetUppercase()}, nil
}

// buildPurge validates a site's PURGE method (nil: off).
func buildPurge(p *nodev1.PurgeMethod) (*PurgeRef, error) {
	if p == nil {
		return nil, nil
	}
	if !idRE.MatchString(p.GetCredentialId()) {
		return nil, fmt.Errorf("%w: invalid PURGE key reference", ErrRejected)
	}
	return &PurgeRef{CredentialID: p.GetCredentialId(), CredentialVersion: p.GetCredentialVersion()}, nil
}

// buildRequestBodyLimit returns a site's body limit in bytes (0: none).
func buildRequestBodyLimit(s *nodev1.Site) (uint64, error) {
	if s.RequestBodyLimit == nil {
		return DefaultRequestBodyLimit, nil
	}
	if s.GetRequestBodyLimit() > MaxRequestBodyLimit {
		return 0, fmt.Errorf("%w: request body limit out of range", ErrRejected)
	}
	return s.GetRequestBodyLimit(), nil
}

// buildRetries returns how many origins a request of pool tries and
// whether 502, 503 and 504 responses are retried.
func buildRetries(pool *nodev1.OriginPool) (uint32, bool, error) {
	tries := pool.GetTries()
	if tries == 0 {
		tries = DefaultOriginTries
	}
	if tries > MaxOriginTries {
		return 0, false, fmt.Errorf("%w: origin tries out of range", ErrRejected)
	}
	return tries, !pool.GetStatusRetryDisabled(), nil
}

// keysZoneMB is the key zone size the console derives from a cache size.
func keysZoneMB(maxSizeMB uint64) uint32 {
	return uint32(min(max((maxSizeMB+159)/160, MinKeysZoneMB), MaxKeysZoneMB))
}

// nodeZoneSize returns the sizes of zone z on node nodeID: its entry in
// node_sizes, else the zone's own (ok false). Entries must be sorted by
// node id, unique and within bounds.
func nodeZoneSize(z *nodev1.CacheZone, nodeID string) (uint64, uint32, bool, error) {
	var found *nodev1.CacheZoneNodeSize
	for i, n := range z.GetNodeSizes() {
		if !idRE.MatchString(n.GetNodeId()) || (i > 0 && z.GetNodeSizes()[i-1].GetNodeId() >= n.GetNodeId()) {
			return 0, 0, false, fmt.Errorf("%w: cache zone %q: node sizes must name valid nodes in order", ErrRejected, z.GetName())
		}
		if n.GetMaxSizeMb() < MinCacheZoneMB || n.GetMaxSizeMb() > MaxCacheZoneMB || n.GetKeysZoneMb() < MinKeysZoneMB || n.GetKeysZoneMb() > MaxKeysZoneMB {
			return 0, 0, false, fmt.Errorf("%w: cache zone %q: node size out of range", ErrRejected, z.GetName())
		}
		if nodeID != "" && n.GetNodeId() == nodeID {
			found = n
		}
	}
	if found == nil {
		return z.GetMaxSizeMb(), z.GetKeysZoneMb(), false, nil
	}
	return found.GetMaxSizeMb(), found.GetKeysZoneMb(), true, nil
}

// MaxRequestBody is the data plane's client_max_body_size in bytes (0: no
// limit): the largest body limit of a published site or of a config rule
// (site or platform), so that nginx admits every request some site
// accepts; the sites check their own limits by Content-Length. Without
// sites it is DefaultRequestBodyLimit.
func (p *Plan) MaxRequestBody() uint64 {
	if len(p.Sites) == 0 {
		return DefaultRequestBodyLimit
	}
	var largest uint64
	consider := func(limit uint64) bool {
		if limit == 0 {
			return true
		}
		largest = max(largest, limit)
		return false
	}
	ruleLimits := func(rules []*nodev1.EdgeRule) bool {
		for _, r := range rules {
			if a := r.GetAction(); a.GetKind() == "config" && a.RequestBodyLimit != nil && consider(a.GetRequestBodyLimit()) {
				return true
			}
		}
		return false
	}
	if ruleLimits(p.PlatformRules) {
		return 0
	}
	for _, s := range p.Sites {
		if consider(s.BodyLimit) || ruleLimits(s.Rules) {
			return 0
		}
	}
	return largest
}

// errorRedirectRE matches an error page's redirect URL before its
// placeholders are replaced: printable ASCII without spaces.
var errorRedirectRE = regexp.MustCompile(`^[\x21-\x7e]+$`)

// errorRedirectAbsRE matches an absolute redirect URL as the console takes
// it too: http(s), "//", a host that is a dotted-quad IPv4 address, a DNS
// name whose last label starts with a letter or a bracketed IPv6 literal
// (no user information, no escapes), an optional port, then a path, query
// or fragment. URL parsers repair other shapes differently (WHATWG reads
// "https:example.com" as https://example.com/ and "1.08" as an invalid
// IPv4 address, Go as an opaque URL and a host name).
var errorRedirectAbsRE = regexp.MustCompile(`^https?://(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}|(?:[A-Za-z0-9-]+\.)*[A-Za-z][A-Za-z0-9-]*|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?(?:[/?#][\x21-\x7e]*)?$`)

// validEscapes reports whether every "%" of s starts an escape of two hex
// digits.
func validEscapes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && (i+2 >= len(s) || !isHexDigit(s[i+1]) || !isHexDigit(s[i+2])) {
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// validErrorRedirect reports whether u is a valid redirect URL of an error
// page: an absolute http(s) URL or a local path, whose only placeholders
// are {{status}} and {{request_id}} and whose "%" each start an escape.
// The console applies the same rule (@edgeweir/contract validErrorRedirect);
// shared vectors: testdata/error_redirect_vectors.json.
func validErrorRedirect(u string) bool {
	if len(u) > maxErrorRedirectURL || !errorRedirectRE.MatchString(u) {
		return false
	}
	bare := strings.NewReplacer("{{status}}", "0", "{{request_id}}", "0").Replace(u)
	if strings.Contains(bare, "{{") || strings.Contains(bare, "}}") || strings.Contains(bare, "\\") || !validEscapes(bare) {
		return false
	}
	if strings.HasPrefix(bare, "/") {
		return !strings.HasPrefix(bare, "//")
	}
	if !errorRedirectAbsRE.MatchString(bare) || !validRedirectLocation(bare) {
		return false
	}
	parsed, err := url.Parse(bare)
	if err != nil {
		return false
	}
	// As strict as the WHATWG parser: ports up to 65535, IPv6 literals that parse.
	if p := parsed.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n > 65535 {
			return false
		}
	}
	if strings.HasPrefix(parsed.Host, "[") {
		if a, err := netip.ParseAddr(parsed.Hostname()); err != nil || !a.Is6() || a.Zone() != "" {
			return false
		}
	}
	return true
}

// content holds a site's validated proto v0.24.0 settings until the site
// is built.
type content struct {
	tries       uint32
	statusRetry bool
	purge       *PurgeRef
	maintenance *Maintenance
	charset     *Charset
	bodyLimit   uint64
	hideXCache  bool
}

// buildContent validates the proto v0.24.0 settings of a site (disabled
// sites included: invalid values reject the configuration).
func buildContent(s *nodev1.Site) (content, error) {
	var c content
	var err error
	if c.tries, c.statusRetry, err = buildRetries(s.GetOriginPool()); err != nil {
		return c, err
	}
	if c.purge, err = buildPurge(s.GetPurge()); err != nil {
		return c, err
	}
	if c.maintenance, err = buildMaintenance(s.GetMaintenance()); err != nil {
		return c, err
	}
	if c.charset, err = buildCharset(s.GetCharset()); err != nil {
		return c, err
	}
	if c.bodyLimit, err = buildRequestBodyLimit(s); err != nil {
		return c, err
	}
	if s.GetTls().GetGzipLevel() > 9 {
		return c, fmt.Errorf("%w: gzip level out of range", ErrRejected)
	}
	c.hideXCache = s.GetHideXCache()
	return c, nil
}

// apply copies the settings onto the site.
func (c content) apply(site *Site) {
	site.Tries, site.NoStatusRetry = c.tries, !c.statusRetry
	site.Purge, site.PurgeKey = c.purge != nil, c.purge
	site.Maintenance, site.Charset = c.maintenance, c.charset
	site.BodyLimit, site.HideXCache = c.bodyLimit, c.hideXCache
}
