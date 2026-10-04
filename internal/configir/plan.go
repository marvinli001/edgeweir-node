package configir

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
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

// The data plane's shared memory zones (lua_shared_dict). The Lua modules
// use them by name (ngx.shared.<name>). internal/render also declares
// one rate-limit partition per site under RateLimitDictPrefix.
const (
	DictSites      = "edgeweir_sites"
	DictMeta       = "edgeweir_meta"
	DictStats      = "edgeweir_stats"
	DictPurge      = "edgeweir_purge"
	DictHealth     = "edgeweir_health"
	DictLimits     = "edgeweir_limits" // Reserved legacy global counter dictionary.
	DictPolicyLogs = "edgeweir_policy_logs"
	DictTopStats   = "edgeweir_topstats"
	DictLogs       = "edgeweir_logs"
	DictBans       = "edgeweir_bans"
	// DictChallenge holds the challenge keys, the captcha pool and used
	// challenge nonces; DictCC the CC mitigation counters, levels and
	// events.
	DictChallenge = "edgeweir_challenge"
	DictCC        = "edgeweir_cc"
	// DictTags is the Cache-Tag index (lua/edgeweir/cachetags.lua): the
	// tags and key epoch of cached objects, for purges by tag.
	DictTags = "edgeweir_tags"
)

// SharedDicts lists the static lua_shared_dicts in declaration order.
// nginx keeps all shared memory zones in one
// namespace, so a cache zone (proxy_cache_path keys_zone) named like one
// of them would fail `nginx -t`: Build skips such zones.
var SharedDicts = []string{DictSites, DictMeta, DictStats, DictPurge, DictHealth, DictPolicyLogs, DictTopStats, DictLogs, DictBans, DictChallenge, DictCC, DictTags}

// reservedZoneName reports whether a cache zone name collides with one of
// the data plane's shared dicts.
func reservedZoneName(name string) bool {
	return slices.Contains(SharedDicts, name) || name == DictLimits || strings.HasPrefix(name, RateLimitDictPrefix)
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

// ValidID reports whether s is a valid id (see idRE).
func ValidID(s string) bool { return idRE.MatchString(s) }

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
	Warnings       []string
	Certificates   map[string]string
	HTTPChallenges []HTTPChallenge
	IPLists        []*nodev1.IpList
	PlatformRules  []*nodev1.EdgeRule
	// PlatformProtection is the platform-wide Under Attack (nil: off).
	PlatformProtection *PlatformProtection
	// ChallengeKeys name the cluster's challenge pass keys; the secrets
	// come from GetChallengeKeys.
	ChallengeKeys []ChallengeKeyRef
	// PlatformErrorPages are the platform's pages for unknown and offline
	// hosts (nil: built-in pages); OfflineHosts the domains of disabled
	// sites, answered with those pages.
	PlatformErrorPages *PlatformErrorPages
	OfflineHosts       []OfflineHost
	// L4Apps are the layer-4 (TCP / UDP) applications, sorted by id
	// (feature l4-v1).
	L4Apps []L4App
}

// Listener is an HTTP or HTTPS port served by the edge layer.
type Listener struct {
	Port          uint32
	TLS           bool
	HTTP2         bool
	HTTP3         bool
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
	LogSampleRate   uint32      `json:"log_sample_rate"`
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
	// OriginHTTP2 sends the requests to the origins over HTTP/2 (feature
	// origin-http2-v1); WebSocket upgrades keep HTTP/1.1.
	OriginHTTP2 bool `json:"origin_http2,omitempty"`
	// GRPC proxies gRPC requests over HTTP/2 end to end, unbuffered and
	// never cached, without the CRS (requires OriginHTTP2).
	GRPC          bool               `json:"grpc,omitempty"`
	CertificateID string             `json:"certificate_id,omitempty"`
	TLS           *TLSOptions        `json:"tls,omitempty"`
	Certificate   *Certificate       `json:"certificate,omitempty"`
	Rules         []*nodev1.EdgeRule `json:"rules,omitempty"`
	// Protection holds Under Attack, challenge and CC settings.
	Protection *Protection `json:"protection,omitempty"`
	// WAF runs the OWASP CRS on the site's requests (nil: off).
	WAF *WAF `json:"waf,omitempty"`
	// KeepCacheTag forwards the origin's Cache-Tag header to clients.
	KeepCacheTag bool `json:"keep_cache_tag,omitempty"`
	// ErrorPages replace the built-in error pages of the site (nil: none).
	ErrorPages *ErrorPages `json:"error_pages,omitempty"`
	// ActiveHealthCheck is the pool's active health check (nil: passive
	// checks only); the agent runs it. ActiveHealth tells the data plane
	// that the agent's marks count for the site.
	ActiveHealthCheck *ActiveHealthCheck `json:"-"`
	ActiveHealth      bool               `json:"active_health,omitempty"`
	// Affinity is the pool's cookie-based session affinity (nil: none).
	Affinity *Affinity `json:"affinity,omitempty"`
	// BulkRedirects is the site's exact-match redirect table, sorted by
	// source (feature rules-v2).
	BulkRedirects []BulkRedirect `json:"bulk_redirects,omitempty"`
}

// BulkRedirect is an entry of a site's exact-match redirect table: Source
// is "/path" (every domain) or "host/path".
type BulkRedirect struct {
	Source        string `json:"source"`
	Target        string `json:"target"`
	Status        uint32 `json:"status"`
	PreserveQuery bool   `json:"preserve_query,omitempty"`
}

type TLSOptions struct {
	ForceHTTPS            bool     `json:"force_https"`
	HSTSMaxAge            uint32   `json:"hsts_max_age"`
	HSTSIncludeSubdomains bool     `json:"hsts_include_subdomains"`
	HSTSPreload           bool     `json:"hsts_preload"`
	MinimumVersion        string   `json:"minimum_version"`
	CipherProfile         string   `json:"cipher_profile"`
	HTTP2                 bool     `json:"http2"`
	HTTP3                 bool     `json:"http3"`
	Gzip                  bool     `json:"gzip"`
	GzipMinLength         uint32   `json:"gzip_min_length"`
	GzipTypes             []string `json:"gzip_types"`
	OCSPStapling          bool     `json:"ocsp_stapling"`
	// Brotli and Zstandard (features brotli-v1, zstd-v1): levels have their
	// defaults applied; unset while the algorithm is off.
	Brotli          bool     `json:"brotli,omitempty"`
	BrotliLevel     uint32   `json:"brotli_level,omitempty"`
	BrotliMinLength uint32   `json:"brotli_min_length,omitempty"`
	BrotliTypes     []string `json:"brotli_types,omitempty"`
	Zstd            bool     `json:"zstd,omitempty"`
	ZstdLevel       uint32   `json:"zstd_level,omitempty"`
	ZstdMinLength   uint32   `json:"zstd_min_length,omitempty"`
	ZstdTypes       []string `json:"zstd_types,omitempty"`
}

type Certificate struct {
	ChainPEM      string `json:"chain_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
	Fingerprint   string `json:"fingerprint"`
	OCSP          string `json:"ocsp,omitempty"`
	OCSPUntil     int64  `json:"ocsp_until,omitempty"`
}

type HTTPChallenge struct {
	Domain           string `json:"domain"`
	Token            string `json:"token"`
	KeyAuthorization string `json:"key_authorization"`
	ExpiresAt        int64  `json:"expires_at"`
}

// SupportedFeatures are the features of this agent version, announced in
// NodeInfo.supported_features (the node's files add Options.ExtraFeatures).
var SupportedFeatures = []string{"tls-v1", "http01-v1", "http3-v1", "rules-v1", "stats-sequence-v1", "stats-watermark-v1", "access-logs-v1", "bans-v1", "challenge-v1", "ja4-v1", FeatureErrorPages, FeatureSessionAffinity, FeatureActiveHealth, FeaturePurgeTag, FeaturePrefetch, FeatureRulesV2, FeatureProbeHealth, FeatureL4, FeatureRuleLog, FeatureTLSPendingDomains, FeatureOriginHTTP2}

// Features of the proto v0.12.0 site settings: the console requires them
// (required_features) when a served site uses the setting.
const (
	FeatureErrorPages      = "error-pages-v1"
	FeatureSessionAffinity = "session-affinity-v1"
	FeatureActiveHealth    = "active-health-v1"
)

// Features of the proto v0.12.0 tasks: purges by Host and Cache-Tag
// (PURGE_TYPE_HOST, PURGE_TYPE_TAG), and prefetches of device variants,
// https URLs and sitemaps (PrefetchTarget.variant, SitemapPrefetchTask).
// The console sends such tasks only to nodes that announce them.
const (
	FeaturePurgeTag = "purge-tag-v1"
	FeaturePrefetch = "prefetch-v2"
)

// FeatureRulesV2 covers the rule engine extensions of proto v0.13.0:
// functions and the new fields in expressions, value expressions in
// redirects and rewrites, query edits, origin, compression and extended
// config actions, the compression phase, cache rule conditions and
// browser TTLs, bulk redirects and origin groups. The console requires it
// when a configuration uses any of them.
const FeatureRulesV2 = "rules-v2"

// Features of proto v0.14.0. FeatureProbeHealth: every edge listener
// answers GET /.edgeweir/health before any site logic, TLS listeners with
// the node's health certificate for SNI health.edgeweir.invalid (the
// console probes nodes over HTTP(S) only when all of a cluster's nodes
// have it, TCP otherwise). FeatureMetrics: ReportStatus carries host
// metrics (Linux builds; announced at runtime).
const (
	FeatureProbeHealth = "probe-health-v1"
	FeatureMetrics     = "metrics-v1"
)

// FeatureRuleLog (proto v0.18.0): the matches of rules with the log action
// are counted per rule and minute and reported in MinuteStats.logged_rules.
// The console only reads the counts; no configuration requires it.
const FeatureRuleLog = "rule-log-v1"

// FeatureTLSPendingDomains (proto v0.19.0): a domain with tls_pending is
// one the site's certificate does not cover yet. It is served over HTTP
// only: the TLS handshake for it is refused, and requests for it are
// neither redirected to HTTPS nor answered with HSTS. The console sends
// such domains (and requires the feature) only to clusters whose active
// nodes all announce it.
const FeatureTLSPendingDomains = "tls-pending-domains-v1"

// FeatureOriginHTTP2 (proto v0.21.0): OriginPool.protocol HTTP/2 towards
// the origins (h2 over TLS, h2c to HTTP origins) and OriginPool.grpc, gRPC
// requests proxied over HTTP/2 end to end; the active health checks of
// such pools probe over HTTP/2. The console requires it when a served site
// uses either.
const FeatureOriginHTTP2 = "origin-http2-v1"

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
	// TLSPending: not covered by the site's certificate yet, served over
	// HTTP only (FeatureTLSPendingDomains). Never set without a certificate.
	TLSPending bool `json:"tls_pending,omitempty"`
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
	// Group is the origin group inside the site ("" is the default group);
	// origin rules send requests to the other groups (feature rules-v2).
	Group string `json:"group,omitempty"`
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
	// Condition is the request condition as a typed expression (phase
	// cache), evaluated on the client's original request; rules with a
	// condition have no path lists (feature rules-v2).
	Condition *nodev1.RuleExpression `json:"condition,omitempty"`
	// BrowserTTL replaces the client's Cache-Control with max-age=N on
	// responses the rule caches; 0 keeps the origin's (feature rules-v2).
	BrowserTTL uint32 `json:"browser_ttl,omitempty"`
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
	ClusterID     string
	ExtraFeatures []string
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
// Whole-config rejections include unsupported capabilities/enums, invalid IDs,
// invalid typed rules/list references, missing certificate references, invalid
// TLS policy, invalid error pages, offline host reasons, active health checks
// or session affinity (also without challenge keys), and the legacy
// CacheRuleMatch.expression placeholder. M4 rules
// use Site.rules instead. Invalid listeners/empty sites/cache conditions are
// handled conservatively without widening a condition to match everything.
// Special-purpose origins outside the platform allow list remain marked
// forbidden and return 502. Disabled sites are not served.
func Build(c *nodev1.NodeConfig, opts Options) (*Plan, error) {
	if c == nil {
		return nil, fmt.Errorf("%w: empty configuration", ErrRejected)
	}
	if len(c.GetSites()) > MaxPublishedSites {
		return nil, fmt.Errorf("%w: configuration exceeds %d published sites", ErrRejected, MaxPublishedSites)
	}
	if err := validateEnums(c.ProtoReflect()); err != nil {
		return nil, err
	}
	for _, feature := range c.GetRequiredFeatures() {
		if !slices.Contains(SupportedFeatures, feature) && !slices.Contains(opts.ExtraFeatures, feature) {
			return nil, fmt.Errorf("%w: unsupported required feature %q", ErrRejected, feature)
		}
	}
	if opts.ClusterID != "" && c.GetClusterId() != "" && c.GetClusterId() != opts.ClusterID {
		return nil, fmt.Errorf("%w: configuration is for cluster %q but this node belongs to %q",
			ErrRejected, c.GetClusterId(), opts.ClusterID)
	}
	if err := validateRules(c, opts.ExtraFeatures); err != nil {
		return nil, err
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
	p.Certificates = map[string]string{}
	for _, cert := range c.GetCertificates() {
		if !idRE.MatchString(cert.GetId()) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(cert.GetSha256Fingerprint()) {
			return nil, fmt.Errorf("%w: invalid certificate reference", ErrRejected)
		}
		p.Certificates[cert.GetId()] = cert.GetSha256Fingerprint()
	}
	p.IPLists = c.GetIpLists()
	p.PlatformRules = c.GetPlatformRules()
	var err error
	if p.PlatformProtection, err = buildPlatformProtection(c.GetPlatformProtection()); err != nil {
		return nil, err
	}
	if p.ChallengeKeys, err = buildChallengeKeys(c.GetChallengeKeys()); err != nil {
		return nil, err
	}
	// Every site's protection, CRS setting, error pages, active health
	// check, session affinity and origin protocol are checked, disabled
	// sites included: an unknown challenge type, CRS mode or error page
	// status, or gRPC without HTTP/2, rejects the whole configuration.
	protections := map[string]*Protection{}
	wafs := map[string]*WAF{}
	pages := map[string]*ErrorPages{}
	checks := map[string]*ActiveHealthCheck{}
	affinities := map[string]*Affinity{}
	protocols := map[string]originProtocol{}
	for _, s := range c.GetSites() {
		id := s.GetId()
		if protections[id], err = buildProtection(s.GetProtection()); err != nil {
			return nil, fmt.Errorf("site %q: %w", id, err)
		}
		if wafs[id], err = buildWAF(s.GetWaf()); err != nil {
			return nil, fmt.Errorf("site %q: %w", id, err)
		}
		if pages[id], err = buildErrorPages(s.GetErrorPages()); err != nil {
			return nil, fmt.Errorf("site %q: %w", id, err)
		}
		if checks[id], err = buildActiveHealthCheck(s.GetOriginPool().GetActiveHealthCheck()); err != nil {
			return nil, fmt.Errorf("site %q: %w", id, err)
		}
		if affinities[id], err = buildAffinity(s.GetOriginPool().GetSessionAffinity()); err != nil {
			return nil, fmt.Errorf("site %q: %w", id, err)
		}
		if protocols[id], err = buildOriginProtocol(s.GetOriginPool()); err != nil {
			return nil, fmt.Errorf("site %q: %w", id, err)
		}
	}
	if p.PlatformErrorPages, err = buildPlatformErrorPages(c.GetPlatformErrorPages()); err != nil {
		return nil, err
	}
	var offlineWarnings []string
	if p.OfflineHosts, offlineWarnings, err = buildOfflineHosts(c.GetOfflineHosts()); err != nil {
		return nil, err
	}
	p.Warnings = append(p.Warnings, offlineWarnings...)
	for _, ch := range c.GetHttpChallenges() {
		if !idRE.MatchString(ch.GetToken()) || len(ch.GetKeyAuthorization()) > 512 || ch.GetExpiresAt() == nil {
			return nil, fmt.Errorf("%w: invalid HTTP challenge", ErrRejected)
		}
		p.HTTPChallenges = append(p.HTTPChallenges, HTTPChallenge{Domain: ch.GetDomain(), Token: ch.GetToken(), KeyAuthorization: ch.GetKeyAuthorization(), ExpiresAt: ch.GetExpiresAt().GetSeconds()})
	}
	warn := func(format string, args ...any) { p.Warnings = append(p.Warnings, fmt.Sprintf(format, args...)) }

	policy, allowed, policyWarnings := NewAddressPolicy(c.GetOriginAllowedCidrs())
	p.OriginAllowedCIDRs = allowed
	p.Warnings = append(p.Warnings, policyWarnings...)
	var l4Warnings []string
	if p.L4Apps, l4Warnings, err = buildL4Apps(c, policy); err != nil {
		return nil, err
	}
	p.Warnings = append(p.Warnings, l4Warnings...)

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
		}
		if l.GetHttp3() && l.GetProtocol() != nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTPS {
			return nil, fmt.Errorf("%w: HTTP/3 requires TLS", ErrRejected)
		}
		seenPorts[port] = true
		p.Listeners = append(p.Listeners, Listener{Port: port, TLS: l.GetProtocol() == nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTPS, HTTP2: l.GetHttp2(), HTTP3: l.GetHttp3(), ProxyProtocol: l.GetProxyProtocol()})
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
		if !zoneNameRE.MatchString(name) || reservedZoneName(name) {
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
		if s.GetLogSampleRate() > 10000 {
			return nil, fmt.Errorf("%w: invalid log sample rate", ErrRejected)
		}
		pool := s.GetOriginPool()
		site := Site{
			LogSampleRate:   s.GetLogSampleRate(),
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
			CertificateID:   s.GetCertificateId(),
			Rules:           s.GetRules(),
		}
		site.Protection = protections[id]
		site.WAF = wafs[id]
		site.KeepCacheTag = s.GetKeepCacheTag()
		site.ErrorPages = pages[id]
		site.ActiveHealthCheck = checks[id]
		site.ActiveHealth = site.ActiveHealthCheck != nil
		site.Affinity = affinities[id]
		site.OriginHTTP2, site.GRPC = protocols[id].http2, protocols[id].grpc
		// Affinity cookies are signed with the cluster's challenge keys.
		if site.Affinity != nil && len(p.ChallengeKeys) == 0 {
			return nil, fmt.Errorf("%w: site %q uses session affinity, but the configuration carries no challenge keys to sign its cookies", ErrRejected, id)
		}
		if site.CertificateID != "" && p.Certificates[site.CertificateID] == "" {
			return nil, fmt.Errorf("%w: missing certificate reference", ErrRejected)
		}
		if tls := s.GetTls(); tls != nil {
			if (tls.GetMinimumVersion() != "1.2" && tls.GetMinimumVersion() != "1.3") || (tls.GetCipherProfile() != "modern" && tls.GetCipherProfile() != "compatible") {
				return nil, fmt.Errorf("%w: unsupported TLS policy", ErrRejected)
			}
			if site.CertificateID == "" && (tls.GetForceHttps() || tls.GetHstsMaxAge() > 0) {
				return nil, fmt.Errorf("%w: HTTPS policy without a certificate", ErrRejected)
			}
			site.TLS = &TLSOptions{ForceHTTPS: tls.GetForceHttps(), HSTSMaxAge: tls.GetHstsMaxAge(), HSTSIncludeSubdomains: tls.GetHstsIncludeSubdomains(), HSTSPreload: tls.GetHstsPreload(), MinimumVersion: tls.GetMinimumVersion(), CipherProfile: tls.GetCipherProfile(), HTTP2: tls.GetHttp2(), HTTP3: tls.GetHttp3(), Gzip: tls.GetGzip(), GzipMinLength: tls.GetGzipMinLength(), GzipTypes: tls.GetGzipTypes(), OCSPStapling: tls.GetOcspStapling()}
			if err := buildCompression(tls, site.TLS); err != nil {
				return nil, err
			}
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
			site.Domains = append(site.Domains, Domain{Name: name, Wildcard: d.GetWildcard(), TLSPending: d.GetTlsPending() && site.CertificateID != ""})
		}
		if len(site.Domains) == 0 {
			warn("site %s skipped: no valid domain", id)
			continue
		}

		for _, b := range s.GetBulkRedirects() {
			site.BulkRedirects = append(site.BulkRedirects, BulkRedirect{Source: b.GetSource(), Target: b.GetTarget(), Status: b.GetStatusCode(), PreserveQuery: b.GetPreserveQuery()})
		}
		for _, r := range s.GetCacheRules() {
			rule, ok, why := buildRule(r)
			if !ok {
				warn("site %s: cache rule %q skipped: %s", id, r.GetId(), why)
				continue
			}
			site.CacheRules = append(site.CacheRules, rule)
		}
		if err := requireModules(&site, opts.ExtraFeatures); err != nil {
			return nil, err
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
		Group:      o.GetGroup(),
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
		Condition:            r.GetMatch().GetCondition(),
		BrowserTTL:           r.GetBrowserTtlSeconds(),
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
