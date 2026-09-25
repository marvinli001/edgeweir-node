package configir

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	nodev1 "github.com/edgeweir/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// DefaultCacheZone is created when a configuration defines no cache zone,
// so that every site always has somewhere to cache.
const DefaultCacheZone = "edgeweir_default"

// Default sizes for cache zones whose fields are zero.
const (
	defaultZoneMaxSizeMB  = 1024
	defaultZoneKeysZoneMB = 16
	defaultZoneInactive   = 3600
)

// reservedZoneNames collide with the data plane's own shared memory zones.
var reservedZoneNames = map[string]bool{
	"edgeweir_sites": true,
	"edgeweir_meta":  true,
	"edgeweir_stats": true,
}

var zoneNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

var extensionRE = regexp.MustCompile(`^[a-z0-9]{1,16}$`)

// tokenRE matches RFC 7230 tokens (header and cookie names in cache keys).
var tokenRE = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")

var regionRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// idRE matches site, origin and rule ids. The data plane joins them with
// "|", ":", "," and other separators (cache keys, purge and health keys,
// X-Edgeweir-Rules), so nothing else is accepted. The console uses UUIDs.
var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

var bucketRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// Defaults for zero values in OriginPool.health_check and .connection.
const (
	DefaultMaxFails          = 3
	DefaultRecoverySeconds   = 30
	DefaultConnectTimeoutMS  = 10_000
	DefaultSendTimeoutMS     = 60_000
	DefaultReadTimeoutMS     = 60_000
	DefaultKeepaliveIdle     = 60
	DefaultKeepaliveRequests = 1000
)

// ErrRejected wraps validation failures that reject a whole configuration.
var ErrRejected = errors.New("configuration rejected")

// Plan is a validated, engine-agnostic view of a NodeConfig: everything
// the data plane needs, with defaults resolved and invalid parts removed.
// JSON tags define the site table pushed to the Lua data plane.
type Plan struct {
	Revision    uint64
	ContentHash string
	ClusterID   string
	Listeners   []Listener
	CacheZones  []CacheZone
	Sites       []Site
	// OriginAllowedCIDRs are the normalized entries of the platform's
	// origin allow list (special-purpose ranges origins may use anyway).
	OriginAllowedCIDRs []string
	// Warnings lists parts of the configuration that were skipped or
	// adjusted; they are reported to the console with the apply result.
	Warnings []string
}

// Listener is a plain-HTTP port served by the edge layer.
type Listener struct {
	Port          uint32
	HTTP2         bool
	ProxyProtocol bool
}

// CacheZone is a cache storage zone with defaults applied.
type CacheZone struct {
	Name            string
	MaxSizeMB       uint64
	KeysZoneMB      uint32
	InactiveSeconds uint32
}

// Site is a routable site.
type Site struct {
	ID              string      `json:"id"`
	Name            string      `json:"name,omitempty"`
	Domains         []Domain    `json:"domains"`
	CacheZone       string      `json:"cache_zone"`
	CacheGeneration uint64      `json:"cache_generation,string"`
	LoadBalance     string      `json:"load_balance"`
	Origins         []Origin    `json:"origins"`
	CacheRules      []CacheRule `json:"cache_rules,omitempty"`
	// TLSVerify verifies HTTPS origin certificates (default true).
	TLSVerify bool `json:"tls_verify"`
	// Health is the passive health check of the origin pool.
	Health HealthCheck `json:"health"`
	// Conn holds upstream connection settings.
	Conn Connection `json:"conn"`
	// CacheKey is the cache key policy of every request of the site.
	CacheKey CacheKey `json:"cache_key"`
	// Slice fetches and caches cacheable GET/HEAD requests in 1 MiB slices.
	Slice bool `json:"slice,omitempty"`
	// WebSocket proxies WebSocket upgrades (default true).
	WebSocket bool `json:"websocket"`
}

// HealthCheck marks an origin down after MaxFails consecutive failures for
// RecoverySeconds.
type HealthCheck struct {
	MaxFails        uint32 `json:"max_fails"`
	RecoverySeconds uint32 `json:"recovery_seconds"`
}

// Connection holds timeouts (milliseconds) and keep-alive settings.
type Connection struct {
	ConnectTimeoutMS  uint32 `json:"connect_timeout_ms"`
	SendTimeoutMS     uint32 `json:"send_timeout_ms"`
	ReadTimeoutMS     uint32 `json:"read_timeout_ms"`
	Keepalive         bool   `json:"keepalive"`
	KeepaliveIdle     uint32 `json:"keepalive_idle"`
	KeepaliveRequests uint32 `json:"keepalive_requests"`
}

// CacheKey query modes.
const (
	QueryAll     = "all"
	QueryIgnore  = "ignore"
	QueryInclude = "include"
)

// CacheKey is the site's cache key policy.
type CacheKey struct {
	Query       string   `json:"query"`
	QueryParams []string `json:"query_params,omitempty"`
	SortQuery   bool     `json:"sort_query,omitempty"`
	Headers     []string `json:"headers,omitempty"`
	Cookies     []string `json:"cookies,omitempty"`
	Device      bool     `json:"device,omitempty"`
	ExcludeHost bool     `json:"exclude_host,omitempty"`
}

// Domain is a host name (exact) or a single-label wildcard suffix.
type Domain struct {
	Name     string `json:"name"`
	Wildcard bool   `json:"wildcard,omitempty"`
}

// Origin is an upstream server.
type Origin struct {
	ID         string `json:"id"`
	Scheme     string `json:"scheme"`
	Address    string `json:"address"`
	Port       uint32 `json:"port"`
	Weight     uint32 `json:"weight"`
	Backup     bool   `json:"backup,omitempty"`
	HostHeader string `json:"host_header,omitempty"`
	SNI        string `json:"sni,omitempty"`
	// S3 signs requests with AWS Signature V4; the keys are filled in by
	// the agent from GetOriginCredentials, never from the configuration.
	S3 *S3Auth `json:"s3,omitempty"`
	// Forbidden marks an origin whose IP literal is a special-purpose
	// address outside the origin allow list: the data plane never connects
	// to it (requests that only have such origins fail with 502).
	Forbidden bool `json:"forbidden,omitempty"`
}

// S3Auth is the signing configuration of an S3-compatible origin.
type S3Auth struct {
	Region            string `json:"region"`
	Bucket            string `json:"bucket,omitempty"`
	CredentialID      string `json:"credential_id"`
	CredentialVersion uint64 `json:"-"`
	AccessKey         string `json:"access_key,omitempty"`
	SecretKey         string `json:"secret_key,omitempty"`
}

// CacheRule actions and origin cache-control modes as used in the site table.
const (
	ActionCache   = "cache"
	ActionBypass  = "bypass"
	ModeOverride  = "override"
	ModeRespect   = "respect"
	LBWeighted    = "weighted_random"
	LBRoundRobin  = "round_robin"
	LBConsistent  = "consistent_hash"
	SchemeHTTP    = "http"
	SchemeHTTPS   = "https"
	maxHostLength = 253
)

// CacheRule is an evaluated-in-order cache rule (first match wins).
// Paths, prefixes and extensions are checked on the request; status codes
// and size bounds on the response.
type CacheRule struct {
	ID           string   `json:"id"`
	Action       string   `json:"action"`
	TTL          uint32   `json:"ttl"`
	Mode         string   `json:"mode"`
	PathPrefixes []string `json:"path_prefixes,omitempty"`
	Paths        []string `json:"paths,omitempty"`
	Extensions   []string `json:"extensions,omitempty"`
	StatusCodes  []uint32 `json:"status_codes,omitempty"`
	MinSize      uint64   `json:"min_size,omitempty"`
	MaxSize      uint64   `json:"max_size,omitempty"`
	// StaleWhileRevalidate and StaleIfError are seconds (RFC 5861).
	StaleWhileRevalidate uint32 `json:"swr,omitempty"`
	StaleIfError         uint32 `json:"sie,omitempty"`
	// CacheAuthorized lets the rule cache requests that carry
	// Authorization; otherwise they bypass the cache (RFC 9111, 3.5).
	CacheAuthorized bool `json:"cache_authorized,omitempty"`
}

// CredentialRefs returns the S3 credentials the plan needs, id -> version.
func (p *Plan) CredentialRefs() map[string]uint64 {
	refs := map[string]uint64{}
	for _, s := range p.Sites {
		for _, o := range s.Origins {
			if o.S3 != nil {
				refs[o.S3.CredentialID] = o.S3.CredentialVersion
			}
		}
	}
	return refs
}

// Options control plan building.
type Options struct {
	// DefaultPort is served when the configuration has no usable listener.
	DefaultPort uint32
	// ClusterID, when set, must equal the config's cluster_id.
	ClusterID string
}

// Bootstrap returns the plan used before any configuration exists: a
// single HTTP listener that answers 404 unknown-host for every request.
func Bootstrap(defaultPort uint32) *Plan {
	return &Plan{
		Listeners:  []Listener{{Port: defaultPort}},
		CacheZones: []CacheZone{defaultZone()},
	}
}

func defaultZone() CacheZone {
	return CacheZone{
		Name:            DefaultCacheZone,
		MaxSizeMB:       defaultZoneMaxSizeMB,
		KeysZoneMB:      defaultZoneKeysZoneMB,
		InactiveSeconds: defaultZoneInactive,
	}
}

// Build validates a canonical, hash-verified NodeConfig and produces a Plan.
//
// Whole-config rejections (returned as errors wrapping ErrRejected):
//   - cluster_id differs from the node's cluster;
//   - a site, origin or cache rule id contains anything but letters,
//     digits, "_" and "-" (they are used as separators in the data plane);
//   - any cache rule uses the rule-engine expression (not supported by
//     Phase 0 nodes, per the proto contract).
//
// Everything else is handled per item with a warning, so that one bad site
// cannot take down the rest of the cluster:
//   - listeners with invalid ports, duplicates, or HTTPS (certificate
//     delivery is not part of proto v0.1.0) are skipped; http3 is ignored;
//     without any usable listener the default port is served;
//   - invalid cache zones are skipped; sites referencing an unknown or
//     empty zone use the first zone;
//   - invalid domains are dropped, domains claimed by an earlier site (by
//     id order) are dropped, sites left without domains are skipped;
//   - invalid origins are dropped, sites left without origins are skipped;
//   - origins whose IP literal is a special-purpose address (see
//     address.go) outside origin_allowed_cidrs stay in the site but are
//     marked forbidden, so the data plane answers 502 instead of
//     connecting;
//   - cache rules with an unknown action or with a condition list that
//     becomes empty after dropping invalid entries are skipped (never
//     widened to "match everything");
//   - disabled sites are not served.
func Build(c *nodev1.NodeConfig, opts Options) (*Plan, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: empty configuration", ErrRejected)
	}
	if opts.ClusterID != "" && c.GetClusterId() != "" && c.GetClusterId() != opts.ClusterID {
		return nil, fmt.Errorf("%w: configuration is for cluster %q but this node belongs to %q",
			ErrRejected, c.GetClusterId(), opts.ClusterID)
	}
	if err := validateIDs(c); err != nil {
		return nil, err
	}
	for _, s := range c.GetSites() {
		for _, r := range s.GetCacheRules() {
			if strings.TrimSpace(r.GetMatch().GetExpression()) != "" {
				return nil, fmt.Errorf("%w: site %q cache rule %q uses a rule expression, which this node version does not support",
					ErrRejected, s.GetId(), r.GetId())
			}
		}
	}
	defaultPort := opts.DefaultPort
	if defaultPort == 0 {
		defaultPort = 80
	}

	p := &Plan{Revision: c.GetRevision(), ContentHash: c.GetContentHash(), ClusterID: c.GetClusterId()}
	warn := func(format string, args ...any) { p.Warnings = append(p.Warnings, fmt.Sprintf(format, args...)) }

	policy, allowed, policyWarnings := NewAddressPolicy(c.GetOriginAllowedCidrs())
	p.OriginAllowedCIDRs = allowed
	p.Warnings = append(p.Warnings, policyWarnings...)

	// Listeners.
	seenPorts := map[uint32]bool{}
	for _, l := range c.GetListeners() {
		port := l.GetPort()
		switch {
		case port == 0 || port > 65535:
			warn("listener with invalid port %d skipped", port)
			continue
		case seenPorts[port]:
			warn("duplicate listener on port %d skipped", port)
			continue
		case l.GetProtocol() == nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTPS:
			warn("HTTPS listener on port %d skipped: certificate delivery is not supported yet", port)
			continue
		}
		if l.GetHttp3() {
			warn("listener %d: http3 ignored (requires TLS)", port)
		}
		seenPorts[port] = true
		p.Listeners = append(p.Listeners, Listener{Port: port, HTTP2: l.GetHttp2(), ProxyProtocol: l.GetProxyProtocol()})
	}
	if len(p.Listeners) == 0 {
		if len(c.GetListeners()) > 0 {
			warn("no usable listener; serving HTTP on default port %d", defaultPort)
		}
		p.Listeners = []Listener{{Port: defaultPort}}
	}

	// Cache zones.
	zones := map[string]bool{}
	for _, z := range c.GetCacheZones() {
		name := z.GetName()
		if !zoneNameRE.MatchString(name) || reservedZoneNames[name] {
			warn("cache zone %q skipped: invalid or reserved name", name)
			continue
		}
		if zones[name] {
			warn("duplicate cache zone %q skipped", name)
			continue
		}
		zones[name] = true
		cz := CacheZone{Name: name, MaxSizeMB: z.GetMaxSizeMb(), KeysZoneMB: z.GetKeysZoneMb(), InactiveSeconds: z.GetInactiveSeconds()}
		if cz.MaxSizeMB == 0 {
			cz.MaxSizeMB = defaultZoneMaxSizeMB
		}
		if cz.KeysZoneMB == 0 {
			cz.KeysZoneMB = defaultZoneKeysZoneMB
		}
		if cz.InactiveSeconds == 0 {
			cz.InactiveSeconds = defaultZoneInactive
		}
		p.CacheZones = append(p.CacheZones, cz)
	}
	if len(p.CacheZones) == 0 {
		p.CacheZones = []CacheZone{defaultZone()}
		zones[DefaultCacheZone] = true
	}
	fallbackZone := p.CacheZones[0].Name

	// Sites (already in id order).
	claimed := map[string]string{} // "exact:name" / "wild:name" -> site id
	for _, s := range c.GetSites() {
		if !s.GetEnabled() {
			continue
		}
		id := s.GetId()
		if id == "" {
			warn("site without id skipped")
			continue
		}
		pool := s.GetOriginPool()
		site := Site{
			ID:              id,
			Name:            s.GetName(),
			CacheGeneration: s.GetCacheGeneration(),
			CacheZone:       s.GetCacheZone(),
			LoadBalance:     loadBalance(pool.GetPolicy()),
			TLSVerify:       !pool.GetSkipTlsVerify(),
			Health:          buildHealth(pool.GetHealthCheck()),
			Conn:            buildConnection(pool.GetConnection()),
			Slice:           s.GetRangeSlice(),
			WebSocket:       !s.GetWebsocketDisabled(),
		}
		key, keyWarnings := buildCacheKey(s.GetCacheKey())
		site.CacheKey = key
		for _, w := range keyWarnings {
			warn("site %s: %s", id, w)
		}
		if site.CacheZone == "" || !zones[site.CacheZone] {
			if site.CacheZone != "" {
				warn("site %s: unknown cache zone %q, using %q", id, site.CacheZone, fallbackZone)
			}
			site.CacheZone = fallbackZone
		}

		// Origins are checked before domains so that a site skipped for
		// lack of origins never claims domains.
		for _, o := range s.GetOriginPool().GetOrigins() {
			origin, err := buildOrigin(o)
			if err != nil {
				warn("site %s: origin %q skipped: %v", id, o.GetId(), err)
				continue
			}
			if ip, err := netip.ParseAddr(origin.Address); err == nil && policy.Forbidden(ip) {
				origin.Forbidden = true
				warn("site %s: origin %q refused: %s is a special-purpose address outside the origin allow list", id, o.GetId(), origin.Address)
			}
			site.Origins = append(site.Origins, origin)
		}
		if len(site.Origins) == 0 {
			warn("site %s skipped: no valid origin", id)
			continue
		}

		for _, d := range s.GetDomains() {
			name := strings.ToLower(d.GetName())
			if !ValidHostname(name) {
				warn("site %s: invalid domain %q skipped", id, d.GetName())
				continue
			}
			if d.GetWildcard() && !strings.Contains(name, ".") {
				warn("site %s: wildcard over a top-level label %q skipped", id, name)
				continue
			}
			key := "exact:" + name
			if d.GetWildcard() {
				key = "wild:" + name
			}
			if owner, dup := claimed[key]; dup {
				if owner != id {
					warn("site %s: domain %q already served by site %s, skipped", id, displayDomain(name, d.GetWildcard()), owner)
				}
				continue
			}
			claimed[key] = id
			site.Domains = append(site.Domains, Domain{Name: name, Wildcard: d.GetWildcard()})
		}
		if len(site.Domains) == 0 {
			warn("site %s skipped: no valid domain", id)
			continue
		}

		for _, r := range s.GetCacheRules() {
			rule, ok, why := buildRule(r)
			if !ok {
				warn("site %s: cache rule %q skipped: %s", id, r.GetId(), why)
				continue
			}
			site.CacheRules = append(site.CacheRules, rule)
		}
		p.Sites = append(p.Sites, site)
	}
	return p, nil
}

// validateIDs rejects configurations whose site, origin or rule ids
// contain anything but letters, digits, "_" and "-" (see idRE). Empty ids
// are handled per item by Build.
func validateIDs(c *nodev1.NodeConfig) error {
	check := func(kind, id, site string) error {
		if id == "" || idRE.MatchString(id) {
			return nil
		}
		where := ""
		if site != "" {
			where = fmt.Sprintf(" in site %q", site)
		}
		return fmt.Errorf("%w: %s id %q%s may only contain letters, digits, \"_\" and \"-\" (at most 128)", ErrRejected, kind, id, where)
	}
	for _, s := range c.GetSites() {
		if err := check("site", s.GetId(), ""); err != nil {
			return err
		}
		for _, o := range s.GetOriginPool().GetOrigins() {
			if err := check("origin", o.GetId(), s.GetId()); err != nil {
				return err
			}
		}
		for _, r := range s.GetCacheRules() {
			if err := check("cache rule", r.GetId(), s.GetId()); err != nil {
				return err
			}
		}
	}
	return nil
}

func displayDomain(name string, wildcard bool) string {
	if wildcard {
		return "*." + name
	}
	return name
}

func buildHealth(h *nodev1.PassiveHealthCheck) HealthCheck {
	out := HealthCheck{MaxFails: h.GetMaxFails(), RecoverySeconds: h.GetRecoverySeconds()}
	if out.MaxFails == 0 {
		out.MaxFails = DefaultMaxFails
	}
	if out.RecoverySeconds == 0 {
		out.RecoverySeconds = DefaultRecoverySeconds
	}
	return out
}

func orDefault(v, def uint32) uint32 {
	if v == 0 {
		return def
	}
	return v
}

func buildConnection(c *nodev1.OriginConnection) Connection {
	return Connection{
		ConnectTimeoutMS:  orDefault(c.GetConnectTimeoutMs(), DefaultConnectTimeoutMS),
		SendTimeoutMS:     orDefault(c.GetSendTimeoutMs(), DefaultSendTimeoutMS),
		ReadTimeoutMS:     orDefault(c.GetReadTimeoutMs(), DefaultReadTimeoutMS),
		Keepalive:         !c.GetKeepaliveDisabled(),
		KeepaliveIdle:     orDefault(c.GetKeepaliveIdleSeconds(), DefaultKeepaliveIdle),
		KeepaliveRequests: orDefault(c.GetKeepaliveMaxRequests(), DefaultKeepaliveRequests),
	}
}

// buildCacheKey validates a cache key policy. Invalid names are dropped
// with a warning; an INCLUDE policy that loses all its parameters keys on
// no parameter at all (never widened to the full query string).
func buildCacheKey(k *nodev1.CacheKeyPolicy) (CacheKey, []string) {
	var warnings []string
	out := CacheKey{Query: QueryAll, SortQuery: k.GetSortQuery(), Device: k.GetDeviceType(), ExcludeHost: k.GetExcludeHost()}
	switch k.GetQuery() {
	case nodev1.CacheKeyQuery_CACHE_KEY_QUERY_IGNORE:
		out.Query = QueryIgnore
	case nodev1.CacheKeyQuery_CACHE_KEY_QUERY_INCLUDE:
		out.Query = QueryInclude
	}
	if out.Query == QueryInclude {
		for _, q := range k.GetQueryParams() {
			if q == "" || len(q) > 128 || strings.ContainsAny(q, "&=# \t\r\n") {
				warnings = append(warnings, fmt.Sprintf("cache key query parameter %q ignored", q))
				continue
			}
			out.QueryParams = append(out.QueryParams, q)
		}
	}
	for _, h := range k.GetHeaders() {
		h = strings.ToLower(h)
		// Internal headers are stripped before the key is built.
		if !tokenRE.MatchString(h) || h == "cookie" || h == "host" || strings.HasPrefix(h, "x-edgeweir-") {
			warnings = append(warnings, fmt.Sprintf("cache key header %q ignored", h))
			continue
		}
		out.Headers = append(out.Headers, h)
	}
	for _, c := range k.GetCookies() {
		if !tokenRE.MatchString(c) {
			warnings = append(warnings, fmt.Sprintf("cache key cookie %q ignored", c))
			continue
		}
		out.Cookies = append(out.Cookies, c)
	}
	return out, warnings
}

func loadBalance(p nodev1.LoadBalancePolicy) string {
	switch p {
	case nodev1.LoadBalancePolicy_LOAD_BALANCE_POLICY_ROUND_ROBIN:
		return LBRoundRobin
	case nodev1.LoadBalancePolicy_LOAD_BALANCE_POLICY_CONSISTENT_HASH:
		return LBConsistent
	default:
		return LBWeighted
	}
}

func buildOrigin(o *nodev1.Origin) (Origin, error) {
	if o.GetId() == "" {
		return Origin{}, errors.New("origin without id")
	}
	addr := strings.ToLower(strings.TrimSpace(o.GetAddress()))
	if addr == "" {
		return Origin{}, errors.New("empty address")
	}
	if ip, err := netip.ParseAddr(addr); err == nil {
		if ip.Zone() != "" {
			return Origin{}, fmt.Errorf("address %q: zoned IPv6 addresses are not supported", addr)
		}
		addr = ip.String()
	} else if !ValidHostname(addr) {
		return Origin{}, fmt.Errorf("invalid address %q", o.GetAddress())
	}
	scheme := SchemeHTTP
	if o.GetScheme() == nodev1.OriginScheme_ORIGIN_SCHEME_HTTPS {
		scheme = SchemeHTTPS
	}
	port := o.GetPort()
	if port == 0 {
		port = 80
		if scheme == SchemeHTTPS {
			port = 443
		}
	}
	if port > 65535 {
		return Origin{}, fmt.Errorf("port %d out of range", port)
	}
	host := strings.TrimSpace(o.GetHostHeader())
	if host != "" && !validHostHeader(host) {
		return Origin{}, fmt.Errorf("invalid host_header %q", host)
	}
	sni := strings.ToLower(strings.TrimSpace(o.GetSni()))
	if sni != "" && !ValidHostname(sni) {
		return Origin{}, fmt.Errorf("invalid sni %q", sni)
	}
	weight := o.GetWeight()
	if weight == 0 {
		weight = 1
	}
	var s3 *S3Auth
	if a := o.GetS3(); a != nil {
		switch {
		case !regionRE.MatchString(a.GetRegion()):
			return Origin{}, fmt.Errorf("invalid S3 region %q", a.GetRegion())
		case a.GetBucket() != "" && !bucketRE.MatchString(a.GetBucket()):
			return Origin{}, fmt.Errorf("invalid S3 bucket %q", a.GetBucket())
		case a.GetCredentialId() == "":
			return Origin{}, errors.New("S3 origin without credential")
		}
		s3 = &S3Auth{Region: a.GetRegion(), Bucket: a.GetBucket(), CredentialID: a.GetCredentialId(), CredentialVersion: a.GetCredentialVersion()}
	}
	return Origin{
		ID:         o.GetId(),
		Scheme:     scheme,
		Address:    addr,
		Port:       port,
		Weight:     weight,
		Backup:     o.GetBackup(),
		HostHeader: host,
		SNI:        sni,
		S3:         s3,
	}, nil
}

func buildRule(r *nodev1.CacheRule) (CacheRule, bool, string) {
	if r.GetId() == "" {
		return CacheRule{}, false, "rule without id"
	}
	rule := CacheRule{
		ID:                   r.GetId(),
		TTL:                  r.GetEdgeTtlSeconds(),
		StaleWhileRevalidate: r.GetStaleWhileRevalidateSeconds(),
		StaleIfError:         r.GetStaleIfErrorSeconds(),
		CacheAuthorized:      r.GetCacheAuthorized(),
	}
	switch r.GetAction() {
	case nodev1.CacheAction_CACHE_ACTION_CACHE:
		rule.Action = ActionCache
	case nodev1.CacheAction_CACHE_ACTION_BYPASS:
		rule.Action = ActionBypass
	default:
		return rule, false, "unspecified action"
	}
	switch r.GetOriginCacheControl() {
	case nodev1.OriginCacheControl_ORIGIN_CACHE_CONTROL_RESPECT:
		rule.Mode = ModeRespect
	default:
		rule.Mode = ModeOverride
	}
	m := r.GetMatch()
	for _, pfx := range m.GetPathPrefixes() {
		if pfx == "" || strings.ContainsAny(pfx, "\x00\r\n") {
			continue
		}
		if !strings.HasPrefix(pfx, "/") {
			pfx = "/" + pfx
		}
		rule.PathPrefixes = append(rule.PathPrefixes, pfx)
	}
	if len(m.GetPathPrefixes()) > 0 && len(rule.PathPrefixes) == 0 {
		return rule, false, "no valid path prefix"
	}
	for _, ext := range m.GetExtensions() {
		e := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(ext), "."))
		if extensionRE.MatchString(e) {
			rule.Extensions = append(rule.Extensions, e)
		}
	}
	if len(m.GetExtensions()) > 0 && len(rule.Extensions) == 0 {
		return rule, false, "no valid extension"
	}
	for _, path := range m.GetPaths() {
		if strings.HasPrefix(path, "/") && !strings.ContainsAny(path, "\x00\r\n ") {
			rule.Paths = append(rule.Paths, path)
		}
	}
	if len(m.GetPaths()) > 0 && len(rule.Paths) == 0 {
		return rule, false, "no valid path"
	}
	for _, code := range m.GetStatusCodes() {
		if code >= 100 && code <= 599 {
			rule.StatusCodes = append(rule.StatusCodes, code)
		}
	}
	if len(m.GetStatusCodes()) > 0 && len(rule.StatusCodes) == 0 {
		return rule, false, "no valid status code"
	}
	rule.MinSize, rule.MaxSize = m.GetMinSizeBytes(), m.GetMaxSizeBytes()
	if rule.MaxSize != 0 && rule.MaxSize < rule.MinSize {
		return rule, false, "maximum size below minimum size"
	}
	return rule, true, ""
}

// ValidHostname reports whether name is a lowercase DNS host name made of
// LDH labels (letters, digits, hyphen; no leading/trailing hyphen), without
// a trailing dot. Internationalized names must be in punycode. Underscores
// are rejected, which also keeps origin addresses from ever matching the
// data plane's internal upstream names.
func ValidHostname(name string) bool {
	if name == "" || len(name) > maxHostLength {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}

// validHostHeader accepts a host name or IP literal with an optional port.
func validHostHeader(h string) bool {
	if len(h) > maxHostLength+6 || strings.ContainsAny(h, " \t\r\n\"'\\/") {
		return false
	}
	if ap, err := netip.ParseAddrPort(h); err == nil {
		return ap.Addr().Zone() == ""
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	host := strings.ToLower(h)
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		port := host[i+1:]
		if port == "" || len(port) > 5 || strings.Trim(port, "0123456789") != "" {
			return false
		}
		host = host[:i]
	}
	return ValidHostname(host)
}

// Credential is an S3 access key pair fetched from the console.
type Credential struct {
	Version   uint64
	AccessKey string
	SecretKey string
}

// AttachCredentials fills the S3 keys of every S3 origin from creds (keyed
// by credential id). Origins whose credential is missing or older than the
// configuration asks for are dropped with a warning, and sites left without
// origins are skipped: an unsigned request would only collect 403s.
func (p *Plan) AttachCredentials(creds map[string]Credential) {
	sites := p.Sites[:0]
	for _, s := range p.Sites {
		origins := s.Origins[:0]
		for _, o := range s.Origins {
			if o.S3 != nil {
				c, ok := creds[o.S3.CredentialID]
				if !ok || c.Version < o.S3.CredentialVersion || c.AccessKey == "" || c.SecretKey == "" {
					p.Warnings = append(p.Warnings, fmt.Sprintf("site %s: origin %q skipped: S3 credential %s (version %d) unavailable",
						s.ID, o.ID, o.S3.CredentialID, o.S3.CredentialVersion))
					continue
				}
				auth := *o.S3
				auth.AccessKey, auth.SecretKey = c.AccessKey, c.SecretKey
				o.S3 = &auth
			}
			origins = append(origins, o)
		}
		if len(origins) == 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf("site %s skipped: no origin with a usable credential", s.ID))
			continue
		}
		s.Origins = origins
		sites = append(sites, s)
	}
	p.Sites = sites
}
