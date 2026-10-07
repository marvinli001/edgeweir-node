// Package render produces the OpenResty nginx.conf from a validated plan.
//
// The rendered file depends on structural settings and the set of site IDs,
// which determines reserved rate-limit partitions. Ordinary site rules and
// lists remain hot updates through the control socket.
package render

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

//go:embed nginx.conf.tmpl
var confTemplate string

var tmpl = template.Must(template.New("nginx.conf").
	Funcs(template.FuncMap{"join": strings.Join, "originProxy": newOriginProxy}).
	Option("missingkey=error").
	Parse(confTemplate))

// safePath matches absolute paths that are safe to embed in nginx.conf
// without quoting (no whitespace, quotes, semicolons, braces or $).
var safePath = regexp.MustCompile(`^/[A-Za-z0-9._/@+-]*$`)

var safeWord = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Params are the node-local settings of the rendered configuration.
type Params struct {
	// Prefix is the nginx prefix directory (-p); holds logs/ and tmp/.
	Prefix string
	// LuaDir contains the edgeweir/*.lua modules.
	LuaDir string
	// CacheDir is the parent directory of all proxy_cache_path zones.
	CacheDir string
	// ControlSocket is the unix socket of the control API.
	ControlSocket string
	// EdgeSocket and EdgeTLSSocket are the local edge listeners (plain
	// and TLS) of the agent's prefetch requests (default: edge.sock next
	// to ControlSocket, edge-tls.sock next to EdgeSocket). Requests there
	// skip bans, CC, challenges, access-denying rules and statistics
	// (edgeweir.router).
	EdgeSocket    string
	EdgeTLSSocket string
	GeoIPSocket   string
	// AgentSocket is the agent's unix socket for the data plane's requests
	// (PURGE method; default: agent.sock next to ControlSocket).
	AgentSocket string
	// OriginSocket is the unix socket of the internal origin layer.
	OriginSocket string
	// OriginSocketNoVerify is the unix socket of the origin layer for sites
	// that skip TLS verification (default: origin-noverify.sock next to
	// OriginSocket).
	OriginSocketNoVerify string
	// OriginSocketH2 and OriginSocketNoVerifyH2 are the origin layers of
	// sites that send their requests to the origins over HTTP/2 (default:
	// origin-h2.sock and origin-noverify-h2.sock next to OriginSocket).
	OriginSocketH2         string
	OriginSocketNoVerifyH2 string
	// OriginSocketGRPC and OriginSocketNoVerifyGRPC are the origin layers
	// of gRPC requests, which the edge reaches over HTTP/2 (default:
	// origin-grpc.sock and origin-noverify-grpc.sock next to OriginSocket).
	OriginSocketGRPC         string
	OriginSocketNoVerifyGRPC string
	// TrustedCA is the CA bundle used to verify HTTPS origins. Empty means
	// none was found: origins that must be verified then fail closed.
	TrustedCA string
	// ResolvConf is the file the resolvers were read from (comment only).
	ResolvConf string
	// Resolvers are nginx resolver addresses (IPv6 bracketed).
	Resolvers []string
	// ResolverIPv6 enables AAAA lookups for origins.
	ResolverIPv6 bool
	// ListenIPv6 adds `listen [::]:port` for every listener.
	ListenIPv6 bool
	// User is rendered as the `user` directive when the master runs as
	// root; empty keeps nginx's default.
	User            string
	WorkerProcesses string
	// WorkerRlimitNofile raises the workers' open file limit (0: unset).
	WorkerRlimitNofile uint64
	WorkerConnections  int
	ErrorLogLevel      string
	SitesDictMB        int
	StatsDictMB        int
	PurgeDictMB        int
	// BanDictMB sizes lua_shared_dict edgeweir_bans; BanCapacity is the
	// number of bans it may hold (edgeweir.bans).
	BanDictMB   int
	BanCapacity int
	// CCDictMB sizes lua_shared_dict edgeweir_cc (CC counters, levels and
	// events), ChallengeDictMB edgeweir_challenge (keys, captcha pool and
	// used challenge nonces).
	CCDictMB        int
	ChallengeDictMB int
	// TagDictMB sizes lua_shared_dict edgeweir_tags, the Cache-Tag index
	// (tags and key epoch of cached objects, for purges by tag).
	TagDictMB int
	// RateLimitDictKB sizes the rate-limit partition (lua_shared_dict
	// edgeweir_rate_<hex site id>) of every published site, in KiB.
	RateLimitDictKB int
	// ModSecurityModule is the ModSecurity-nginx dynamic module; nginx.conf
	// loads it only while a site runs the OWASP CRS. Empty: the node has
	// none (such configurations are rejected earlier, see configir).
	ModSecurityModule string
	// CRSDir holds crs-setup.conf and rules/ of the OWASP CRS.
	CRSDir string
	// ModSecurityUnicodeMap is ModSecurity's unicode.mapping (optional).
	ModSecurityUnicodeMap string
	// L4Socket is the unix socket of the stream subsystem's control relay
	// (default: l4.sock next to ControlSocket); the control API forwards
	// /v1/l4 requests to it. L4DictMB sizes lua_shared_dict edgeweir_l4
	// (the current and the previous layer-4 table with their IP lists).
	L4Socket string
	L4DictMB int
	// WorkerShutdownTimeout bounds the graceful shutdown of the workers a
	// reload replaces (worker_shutdown_timeout, every connection they still
	// serve); 0 leaves it unset: old workers serve their connections until
	// these end.
	WorkerShutdownTimeout time.Duration
}

// Default locations of the edgeweir-openresty packages.
const (
	DefaultCRSDir     = "/usr/share/edgeweir-openresty/crs"
	DefaultUnicodeMap = "/usr/share/edgeweir-openresty/modsecurity/unicode.mapping"
)

// Ban store defaults (--ban-dict-mb, --ban-capacity) and the capacity
// bounds.
const (
	DefaultBanDictMB   = 32
	DefaultBanCapacity = 100000
	MaxBanCapacity     = 10000000
	// CC and challenge store defaults (--cc-dict-mb, --challenge-dict-mb).
	DefaultCCDictMB        = 32
	DefaultChallengeDictMB = 8
	// DefaultTagDictMB sizes the Cache-Tag index (--tag-dict-mb).
	DefaultTagDictMB = 64
	// DefaultSitesDictMB sizes the site table store (--sites-dict-mb): the
	// current and the previous table, error page templates included.
	DefaultSitesDictMB = 64
	// DefaultStatsDictMB sizes the statistics counters (--stats-dict-mb):
	// per site and minute until the agent drains them.
	DefaultStatsDictMB = 16
	// DefaultL4DictMB sizes the layer-4 table store (--l4-dict-mb): the
	// current and the previous layer-4 table with their IP lists.
	DefaultL4DictMB = 32
	// Rate-limit partition size of each published site (--rate-limit-dict-kb)
	// and its bounds.
	DefaultRateLimitDictKB = 256
	MinRateLimitDictKB     = 64
	MaxRateLimitDictKB     = 65536
)

// WithDefaults fills zero values with production defaults.
func (p Params) WithDefaults() Params {
	if p.WorkerProcesses == "" {
		p.WorkerProcesses = "auto"
	}
	if p.WorkerConnections == 0 {
		p.WorkerConnections = 4096
	}
	if p.ErrorLogLevel == "" {
		p.ErrorLogLevel = "notice"
	}
	if p.SitesDictMB == 0 {
		p.SitesDictMB = DefaultSitesDictMB
	}
	if p.StatsDictMB == 0 {
		p.StatsDictMB = DefaultStatsDictMB
	}
	if p.PurgeDictMB == 0 {
		p.PurgeDictMB = 32
	}
	if p.BanDictMB == 0 {
		p.BanDictMB = DefaultBanDictMB
	}
	if p.BanCapacity == 0 {
		p.BanCapacity = DefaultBanCapacity
	}
	if p.CCDictMB == 0 {
		p.CCDictMB = DefaultCCDictMB
	}
	if p.ChallengeDictMB == 0 {
		p.ChallengeDictMB = DefaultChallengeDictMB
	}
	if p.TagDictMB == 0 {
		p.TagDictMB = DefaultTagDictMB
	}
	if p.RateLimitDictKB == 0 {
		p.RateLimitDictKB = DefaultRateLimitDictKB
	}
	if p.GeoIPSocket == "" && p.ControlSocket != "" {
		p.GeoIPSocket = p.ControlSocket + ".geo"
	}
	if p.AgentSocket == "" && p.ControlSocket != "" {
		p.AgentSocket = filepath.Join(filepath.Dir(p.ControlSocket), "agent.sock")
	}
	if p.EdgeSocket == "" && p.ControlSocket != "" {
		p.EdgeSocket = filepath.Join(filepath.Dir(p.ControlSocket), "edge.sock")
	}
	if p.EdgeTLSSocket == "" && p.EdgeSocket != "" {
		p.EdgeTLSSocket = filepath.Join(filepath.Dir(p.EdgeSocket), "edge-tls.sock")
	}
	if p.L4Socket == "" && p.ControlSocket != "" {
		p.L4Socket = filepath.Join(filepath.Dir(p.ControlSocket), "l4.sock")
	}
	if p.L4DictMB == 0 {
		p.L4DictMB = DefaultL4DictMB
	}
	if p.OriginSocket != "" {
		dir := filepath.Dir(p.OriginSocket)
		for _, s := range []struct {
			path *string
			name string
		}{
			{&p.OriginSocketNoVerify, "origin-noverify.sock"},
			{&p.OriginSocketH2, "origin-h2.sock"},
			{&p.OriginSocketNoVerifyH2, "origin-noverify-h2.sock"},
			{&p.OriginSocketGRPC, "origin-grpc.sock"},
			{&p.OriginSocketNoVerifyGRPC, "origin-noverify-grpc.sock"},
		} {
			if *s.path == "" {
				*s.path = filepath.Join(dir, s.name)
			}
		}
	}
	if len(p.Resolvers) == 0 {
		p.Resolvers = []string{"127.0.0.1"}
	}
	if p.ResolvConf == "" {
		p.ResolvConf = "/etc/resolv.conf"
	}
	if p.CRSDir == "" {
		p.CRSDir = DefaultCRSDir
	}
	return p
}

// Validate checks the settings Render needs (after WithDefaults): paths,
// names, sizes and resolvers.
func (p Params) Validate() error {
	for name, v := range map[string]string{
		"nginx prefix": p.Prefix, "lua dir": p.LuaDir, "cache dir": p.CacheDir,
		"control socket": p.ControlSocket, "origin socket": p.OriginSocket, "resolv.conf": p.ResolvConf,
		"origin socket without verification":        p.OriginSocketNoVerify,
		"HTTP/2 origin socket":                      p.OriginSocketH2,
		"HTTP/2 origin socket without verification": p.OriginSocketNoVerifyH2,
		"gRPC origin socket":                        p.OriginSocketGRPC,
		"gRPC origin socket without verification":   p.OriginSocketNoVerifyGRPC,
		"edge socket":                               p.EdgeSocket,
		"TLS edge socket":                           p.EdgeTLSSocket,
		"GeoIP socket":                              p.GeoIPSocket,
		"agent socket":                              p.AgentSocket,
		"layer-4 control socket":                    p.L4Socket,
	} {
		if !safePath.MatchString(v) {
			return fmt.Errorf("%s %q must be an absolute path without spaces or special characters", name, v)
		}
	}
	if p.TrustedCA != "" && !safePath.MatchString(p.TrustedCA) {
		return fmt.Errorf("trusted CA bundle %q must be an absolute path without spaces or special characters", p.TrustedCA)
	}
	seen := map[string]bool{}
	for _, l := range originLayers(p) {
		if seen[l.Socket] {
			return errors.New("the origin layer sockets (with and without TLS verification, HTTP/1.1, HTTP/2 and gRPC) must differ")
		}
		seen[l.Socket] = true
	}
	if p.EdgeSocket == p.EdgeTLSSocket {
		return errors.New("the plain and the TLS edge sockets must differ")
	}
	for name, v := range map[string]string{"worker_processes": p.WorkerProcesses, "error log level": p.ErrorLogLevel} {
		if !safeWord.MatchString(v) {
			return fmt.Errorf("invalid %s %q", name, v)
		}
	}
	if p.User != "" && !regexp.MustCompile(`^[a-z_][a-z0-9_-]*( [a-z_][a-z0-9_-]*)?$`).MatchString(p.User) {
		return fmt.Errorf("invalid nginx user %q", p.User)
	}
	if p.BanCapacity < 1 || p.BanCapacity > MaxBanCapacity {
		return fmt.Errorf("ban capacity %d out of range (1-%d)", p.BanCapacity, MaxBanCapacity)
	}
	if p.WorkerShutdownTimeout < 0 {
		return fmt.Errorf("negative worker shutdown timeout %s", p.WorkerShutdownTimeout)
	}
	for name, v := range map[string]int{"sites dict": p.SitesDictMB, "stats dict": p.StatsDictMB, "purge dict": p.PurgeDictMB, "ban dict": p.BanDictMB, "CC dict": p.CCDictMB, "challenge dict": p.ChallengeDictMB, "tag dict": p.TagDictMB, "layer-4 dict": p.L4DictMB} {
		if v < 1 || v > 65536 {
			return fmt.Errorf("%s size %d MiB out of range (1-65536)", name, v)
		}
	}
	for _, r := range p.Resolvers {
		if !validResolver(r) {
			return fmt.Errorf("invalid resolver address %q", r)
		}
	}
	return nil
}

type data struct {
	Params
	ConfID       string
	SharedDicts  []sharedDict
	EdgeServers  []edgeServer
	CacheZones   []configir.CacheZone
	DefaultZone  string
	OriginLayers []originLayer
	Balancers    []string
	// ModSecurityConf is the CRS configuration (ModSecurityConf) when a
	// site runs the CRS; WAFBodyLimits are the request body limits of the
	// edge layer's CRS locations.
	ModSecurityConf string
	WAFBodyLimits   []uint32
	WAFHeader       string
	// L4Servers are the stream servers of the layer-4 applications (none:
	// no stream block); ShutdownTimeoutMS is worker_shutdown_timeout (0:
	// unset).
	L4Servers         []l4Server
	ShutdownTimeoutMS int64
	// ClientMaxBodySize is client_max_body_size of the http block
	// (configir.Plan.MaxRequestBody).
	ClientMaxBodySize string
}

// originProxy is the data of one origin layer location (template
// "origin_proxy"): P is the directive prefix (proxy or grpc), StatusRetry
// whether 502, 503 and 504 responses are retried.
type originProxy struct {
	Root        data
	Layer       originLayer
	P           string
	StatusRetry bool
}

func newOriginProxy(root data, layer originLayer, statusRetry bool) originProxy {
	p := "proxy"
	if layer.Protocol == protocolGRPC {
		p = "grpc"
	}
	return originProxy{Root: root, Layer: layer, P: p, StatusRetry: statusRetry}
}

// clientMaxBodySize renders a body limit in bytes (0: none) for nginx,
// keeping the former "100m" for the default.
func clientMaxBodySize(limit uint64) string {
	if limit == configir.DefaultRequestBodyLimit {
		return "100m"
	}
	return fmt.Sprint(limit)
}

// sharedDict is one lua_shared_dict of the data plane.
type sharedDict struct {
	Name   string
	SizeMB int
	SizeKB int
}

// sharedDicts sizes static dictionaries and the reserved site partitions.
func sharedDicts(p Params, sites []configir.Site) ([]sharedDict, error) {
	sizes := map[string]int{
		configir.DictSites:      p.SitesDictMB,
		configir.DictMeta:       1,
		configir.DictStats:      p.StatsDictMB,
		configir.DictPurge:      p.PurgeDictMB,
		configir.DictHealth:     4,
		configir.DictPolicyLogs: 1,
		configir.DictTopStats:   8,
		configir.DictLogs:       8,
		configir.DictBans:       p.BanDictMB,
		configir.DictChallenge:  p.ChallengeDictMB,
		configir.DictCC:         p.CCDictMB,
		configir.DictTags:       p.TagDictMB,
		configir.DictPurgeRate:  1,
	}
	out := make([]sharedDict, 0, len(configir.SharedDicts))
	for _, name := range configir.SharedDicts {
		mb, ok := sizes[name]
		if !ok {
			return nil, fmt.Errorf("no size for shared dict %s", name)
		}
		out = append(out, sharedDict{Name: name, SizeMB: mb})
	}
	if len(sites) > configir.MaxPublishedSites {
		return nil, fmt.Errorf("configuration exceeds %d published sites", configir.MaxPublishedSites)
	}
	if len(sites) == 0 {
		return out, nil
	}
	names := make([]string, 0, len(sites))
	seen := make(map[string]bool, len(sites))
	for _, site := range sites {
		name, err := configir.RateLimitDictName(site.ID)
		if err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate rate-limit site ID %q", site.ID)
		}
		seen[name] = true
		names = append(names, name)
	}
	slices.Sort(names)
	// Fixed names and sizes let nginx reuse existing counters when another
	// site is added or removed. The admission limit bounds total allocation.
	for _, name := range names {
		out = append(out, sharedDict{Name: name, SizeKB: p.RateLimitDictKB})
	}
	return out, nil
}

// edgeServer is one server block of the edge layer.
type edgeServer struct {
	Listen        []string // listen directive arguments
	QUICListen    []string
	HTTP3         bool
	HTTP2         bool
	ProxyProtocol bool
	Local         bool // the agent's unix socket listeners
	TLS           bool
	ServerName    string
	Gzip          bool
	GzipMinLength uint32
	GzipTypes     string
	CipherProfile string
	// Brotli and Zstandard follow gzip: levels, minimum lengths and types
	// are static directives of the site's server block.
	Brotli          bool
	BrotliLevel     uint32
	BrotliMinLength uint32
	BrotliTypes     string
	Zstd            bool
	ZstdLevel       uint32
	ZstdMinLength   uint32
	ZstdTypes       string
	// GzipLevel is gzip_comp_level (0: nginx's default).
	GzipLevel uint32
}

// edgeServers returns the edge layer's servers. gRPC clients speak HTTP/2
// only: while a site proxies gRPC, plain listeners also take HTTP/2 with
// prior knowledge (h2c; nginx tells it from HTTP/1.1 by the connection
// preface), and that site's servers enable HTTP/2 on every listener
// (nginx answers 421 to HTTP/2 requests for a server without it).
func edgeServers(p Params, plan *configir.Plan) []edgeServer {
	var out []edgeServer
	hasTLS := false
	grpc := slices.ContainsFunc(plan.Sites, func(s configir.Site) bool { return s.GRPC })
	for _, l := range plan.Listeners {
		hasTLS = hasTLS || l.TLS
		suffix := " default_server"
		if l.TLS {
			suffix += " ssl"
		}
		if l.ProxyProtocol {
			suffix += " proxy_protocol"
		}
		s := edgeServer{Listen: []string{fmt.Sprintf("%d%s", l.Port, suffix)}, HTTP2: l.HTTP2 || (grpc && !l.TLS), ProxyProtocol: l.ProxyProtocol, TLS: l.TLS, ServerName: "_"}
		if p.ListenIPv6 {
			s.Listen = append(s.Listen, fmt.Sprintf("[::]:%d%s", l.Port, suffix))
		}
		if l.HTTP3 {
			s.HTTP3 = true
			s.QUICListen = []string{fmt.Sprintf("%d quic reuseport default_server", l.Port)}
			if p.ListenIPv6 {
				s.QUICListen = append(s.QUICListen, fmt.Sprintf("[::]:%d quic reuseport default_server", l.Port))
			}
		}
		out = append(out, s)
		for _, site := range plan.Sites {
			if site.TLS == nil || (l.TLS && site.CertificateID == "") {
				continue
			}
			var names []string
			for _, domain := range site.Domains {
				// No HTTPS for a domain the certificate does not cover yet.
				if l.TLS && domain.TLSPending {
					continue
				}
				name := domain.Name
				if domain.Wildcard {
					name = "*." + name
				}
				names = append(names, name)
			}
			if len(names) == 0 {
				continue
			}
			custom := s
			custom.Listen = make([]string, len(s.Listen))
			for i, listen := range s.Listen {
				custom.Listen[i] = strings.ReplaceAll(listen, " default_server", "")
			}
			custom.ServerName = strings.Join(names, " ")
			custom.HTTP2 = (l.TLS && site.TLS.HTTP2) || site.GRPC
			custom.HTTP3 = l.TLS && site.TLS.HTTP3
			custom.QUICListen = make([]string, len(s.QUICListen))
			for i, listen := range s.QUICListen {
				custom.QUICListen[i] = strings.ReplaceAll(strings.ReplaceAll(listen, " default_server", ""), " reuseport", "")
			}
			custom.Gzip, custom.GzipMinLength = site.TLS.Gzip, max(site.TLS.GzipMinLength, 1)
			custom.GzipLevel = site.TLS.GzipLevel
			custom.GzipTypes = strings.Join(site.TLS.GzipTypes, " ")
			custom.Brotli, custom.BrotliLevel = site.TLS.Brotli, site.TLS.BrotliLevel
			custom.BrotliMinLength, custom.BrotliTypes = max(site.TLS.BrotliMinLength, 1), strings.Join(site.TLS.BrotliTypes, " ")
			custom.Zstd, custom.ZstdLevel = site.TLS.Zstd, site.TLS.ZstdLevel
			custom.ZstdMinLength, custom.ZstdTypes = max(site.TLS.ZstdMinLength, 1), strings.Join(site.TLS.ZstdTypes, " ")
			custom.CipherProfile = site.TLS.CipherProfile
			out = append(out, custom)
		}
	}
	out = append(out, edgeServer{Listen: []string{"unix:" + p.EdgeSocket + " default_server"}, Local: true, ServerName: "_"})
	if hasTLS {
		// https URLs: the certificate of the site that serves the host (SNI),
		// as on the public HTTPS listeners.
		out = append(out, edgeServer{Listen: []string{"unix:" + p.EdgeTLSSocket + " default_server ssl"}, Local: true, TLS: true, ServerName: "_"})
	}
	return out
}

// Protocols of the origin layers towards the origins.
const (
	protocolHTTP1 = "http1"
	protocolHTTP2 = "http2"
	protocolGRPC  = "grpc"
)

// originLayer is one origin layer server: Name is the edge layer's
// upstream of it (the value edgeweir.router puts in
// $edgeweir_origin_layer), Verify whether it verifies HTTPS origins and
// Protocol how it talks to the origins (and, for gRPC, how the edge
// reaches it).
type originLayer struct {
	Name     string
	Socket   string
	Verify   bool
	Protocol string
	// Balancer is the upstream (balancer_by_lua) of its requests to the
	// origins: one per protocol.
	Balancer string
}

// originLayers are the origin layer servers: with and without TLS
// verification, for HTTP/1.1, HTTP/2 and gRPC towards the origins.
func originLayers(p Params) []originLayer {
	return []originLayer{
		{Name: "edgeweir_origin_verify", Socket: p.OriginSocket, Verify: true, Protocol: protocolHTTP1, Balancer: balancers[0]},
		{Name: "edgeweir_origin_noverify", Socket: p.OriginSocketNoVerify, Protocol: protocolHTTP1, Balancer: balancers[0]},
		{Name: "edgeweir_origin_verify_h2", Socket: p.OriginSocketH2, Verify: true, Protocol: protocolHTTP2, Balancer: balancers[1]},
		{Name: "edgeweir_origin_noverify_h2", Socket: p.OriginSocketNoVerifyH2, Protocol: protocolHTTP2, Balancer: balancers[1]},
		{Name: "edgeweir_origin_verify_grpc", Socket: p.OriginSocketGRPC, Verify: true, Protocol: protocolGRPC, Balancer: balancers[2]},
		{Name: "edgeweir_origin_noverify_grpc", Socket: p.OriginSocketNoVerifyGRPC, Protocol: protocolGRPC, Balancer: balancers[2]},
	}
}

// balancers are the upstreams of the origin layers' requests to the
// origins (HTTP/1.1, HTTP/2, gRPC).
var balancers = []string{"edgeweir_balancer", "edgeweir_balancer_h2", "edgeweir_balancer_grpc"}

// OriginLayerSockets are the unix sockets of the origin layer servers
// (with defaults applied).
func (p Params) OriginLayerSockets() []string {
	var out []string
	for _, l := range originLayers(p.WithDefaults()) {
		out = append(out, l.Socket)
	}
	return out
}

// Render returns nginx.conf for plan.
func Render(p Params, plan *configir.Plan) ([]byte, error) {
	p = p.WithDefaults()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if plan == nil || len(plan.Listeners) == 0 || len(plan.CacheZones) == 0 {
		return nil, errors.New("plan needs at least one listener and one cache zone")
	}
	for _, l := range plan.Listeners {
		if l.Port == 0 || l.Port > 65535 {
			return nil, fmt.Errorf("invalid listener port %d", l.Port)
		}
	}
	for _, z := range plan.CacheZones {
		if !safeWord.MatchString(z.Name) || strings.HasPrefix(z.Name, configir.RateLimitDictPrefix) {
			return nil, fmt.Errorf("invalid cache zone name %q", z.Name)
		}
	}
	dicts, err := sharedDicts(p, plan.Sites)
	if err != nil {
		return nil, err
	}
	if err := validateCompression(plan); err != nil {
		return nil, err
	}
	modsecConf, _, err := ModSecurityConf(p, plan)
	if err != nil {
		return nil, err
	}
	l4, err := l4Servers(p, plan)
	if err != nil {
		return nil, err
	}
	d := data{
		Params:    p,
		L4Servers: l4,
		// Whole milliseconds, at least one (nginx's time syntax).
		ShutdownTimeoutMS: (p.WorkerShutdownTimeout + time.Millisecond - 1).Milliseconds(),
		SharedDicts:       dicts,
		EdgeServers:       edgeServers(p, plan),
		CacheZones:        plan.CacheZones,
		DefaultZone:       plan.CacheZones[0].Name,
		OriginLayers:      originLayers(p),
		Balancers:         balancers,
		ModSecurityConf:   modsecConf,
		WAFHeader:         WAFHeader,
		ClientMaxBodySize: clientMaxBodySize(plan.MaxRequestBody()),
	}
	if modsecConf != "" {
		d.WAFBodyLimits = plan.WAFBodyLimits()
	}
	// The configuration id is the hash of the file rendered without it:
	// equal settings give equal files, and the data plane reports the id
	// of the file its workers loaded.
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, d); err != nil {
		return nil, fmt.Errorf("render nginx.conf: %w", err)
	}
	sum := sha256.Sum256(buf.Bytes())
	d.ConfID = hex.EncodeToString(sum[:])[:16]
	buf.Reset()
	if err := tmpl.Execute(&buf, d); err != nil {
		return nil, fmt.Errorf("render nginx.conf: %w", err)
	}
	return buf.Bytes(), nil
}

var mimeTypeRE = regexp.MustCompile(`^[a-z0-9.+-]+/[a-z0-9.+-]+$`)

// validateCompression checks what the site server blocks render unquoted
// (configir validates the same; nginx.conf never trusts its input).
func validateCompression(plan *configir.Plan) error {
	for _, s := range plan.Sites {
		if s.TLS == nil {
			continue
		}
		if s.TLS.BrotliLevel > configir.MaxBrotliLevel || s.TLS.ZstdLevel > configir.MaxZstdLevel || s.TLS.GzipLevel > 9 ||
			(s.TLS.Brotli && s.TLS.BrotliLevel == 0) || (s.TLS.Zstd && s.TLS.ZstdLevel == 0) {
			return fmt.Errorf("site %q: invalid compression level", s.ID)
		}
		for _, list := range [][]string{s.TLS.GzipTypes, s.TLS.BrotliTypes, s.TLS.ZstdTypes} {
			for _, mime := range list {
				if !mimeTypeRE.MatchString(mime) {
					return fmt.Errorf("site %q: invalid compression type %q", s.ID, mime)
				}
			}
		}
	}
	return nil
}

var confIDRE = regexp.MustCompile(`(?m)^\s*conf_id = "([0-9a-f]{16})",$`)

// ConfID returns the configuration id of a rendered nginx.conf ("" when it
// has none).
func ConfID(conf []byte) string {
	m := confIDRE.FindSubmatch(conf)
	if m == nil {
		return ""
	}
	return string(m[1])
}
