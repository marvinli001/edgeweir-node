// Package render produces the OpenResty nginx.conf from a validated plan.
//
// The rendered file only depends on structural settings (listeners, cache
// zones, resolver, paths), never on sites, so comparing the rendered bytes
// is exactly the "structural change" test that decides between a reload and
// a hot update through the control socket.
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
	"strings"
	"text/template"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

//go:embed nginx.conf.tmpl
var confTemplate string

var tmpl = template.Must(template.New("nginx.conf").
	Funcs(template.FuncMap{"join": strings.Join}).
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
	// EdgeSocket is the local edge listener for the agent's prefetch
	// requests (default: edge.sock next to ControlSocket).
	EdgeSocket  string
	GeoIPSocket string
	// OriginSocket is the unix socket of the internal origin layer.
	OriginSocket string
	// OriginSocketNoVerify is the unix socket of the origin layer for sites
	// that skip TLS verification (default: origin-noverify.sock next to
	// OriginSocket).
	OriginSocketNoVerify string
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
}

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
		p.SitesDictMB = 64
	}
	if p.StatsDictMB == 0 {
		p.StatsDictMB = 16
	}
	if p.PurgeDictMB == 0 {
		p.PurgeDictMB = 32
	}
	if p.GeoIPSocket == "" && p.ControlSocket != "" {
		p.GeoIPSocket = p.ControlSocket + ".geo"
	}
	if p.EdgeSocket == "" && p.ControlSocket != "" {
		p.EdgeSocket = filepath.Join(filepath.Dir(p.ControlSocket), "edge.sock")
	}
	if p.OriginSocketNoVerify == "" && p.OriginSocket != "" {
		p.OriginSocketNoVerify = filepath.Join(filepath.Dir(p.OriginSocket), "origin-noverify.sock")
	}
	if len(p.Resolvers) == 0 {
		p.Resolvers = []string{"127.0.0.1"}
	}
	if p.ResolvConf == "" {
		p.ResolvConf = "/etc/resolv.conf"
	}
	return p
}

func (p Params) validate() error {
	for name, v := range map[string]string{
		"nginx prefix": p.Prefix, "lua dir": p.LuaDir, "cache dir": p.CacheDir,
		"control socket": p.ControlSocket, "origin socket": p.OriginSocket, "resolv.conf": p.ResolvConf,
		"origin socket without verification": p.OriginSocketNoVerify,
		"edge socket":                        p.EdgeSocket,
		"GeoIP socket":                       p.GeoIPSocket,
	} {
		if !safePath.MatchString(v) {
			return fmt.Errorf("%s %q must be an absolute path without spaces or special characters", name, v)
		}
	}
	if p.TrustedCA != "" && !safePath.MatchString(p.TrustedCA) {
		return fmt.Errorf("trusted CA bundle %q must be an absolute path without spaces or special characters", p.TrustedCA)
	}
	if p.OriginSocket == p.OriginSocketNoVerify {
		return errors.New("the origin sockets with and without TLS verification must differ")
	}
	for name, v := range map[string]string{"worker_processes": p.WorkerProcesses, "error log level": p.ErrorLogLevel} {
		if !safeWord.MatchString(v) {
			return fmt.Errorf("invalid %s %q", name, v)
		}
	}
	if p.User != "" && !regexp.MustCompile(`^[a-z_][a-z0-9_-]*( [a-z_][a-z0-9_-]*)?$`).MatchString(p.User) {
		return fmt.Errorf("invalid nginx user %q", p.User)
	}
	for name, v := range map[string]int{"sites dict": p.SitesDictMB, "stats dict": p.StatsDictMB, "purge dict": p.PurgeDictMB} {
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
}

// sharedDict is one lua_shared_dict of the data plane.
type sharedDict struct {
	Name   string
	SizeMB int
}

// sharedDicts sizes every dict of configir.SharedDicts, the single list
// that also keeps cache zones from reusing these names.
func sharedDicts(p Params) ([]sharedDict, error) {
	sizes := map[string]int{
		configir.DictSites:  p.SitesDictMB,
		configir.DictMeta:   1,
		configir.DictStats:  p.StatsDictMB,
		configir.DictPurge:  p.PurgeDictMB,
		configir.DictHealth: 4,
		configir.DictLimits: 16,
	}
	out := make([]sharedDict, 0, len(configir.SharedDicts))
	for _, name := range configir.SharedDicts {
		mb, ok := sizes[name]
		if !ok {
			return nil, fmt.Errorf("no size for shared dict %s", name)
		}
		out = append(out, sharedDict{Name: name, SizeMB: mb})
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
	Local         bool // the agent's unix socket listener
	TLS           bool
	ServerName    string
	Gzip          bool
	GzipMinLength uint32
	GzipTypes     string
	CipherProfile string
}

func edgeServers(p Params, plan *configir.Plan) []edgeServer {
	var out []edgeServer
	for _, l := range plan.Listeners {
		suffix := " default_server"
		if l.TLS {
			suffix += " ssl"
		}
		if l.ProxyProtocol {
			suffix += " proxy_protocol"
		}
		s := edgeServer{Listen: []string{fmt.Sprintf("%d%s", l.Port, suffix)}, HTTP2: l.HTTP2, ProxyProtocol: l.ProxyProtocol, TLS: l.TLS, ServerName: "_"}
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
				name := domain.Name
				if domain.Wildcard {
					name = "*." + name
				}
				names = append(names, name)
			}
			custom := s
			custom.Listen = make([]string, len(s.Listen))
			for i, listen := range s.Listen {
				custom.Listen[i] = strings.ReplaceAll(listen, " default_server", "")
			}
			custom.ServerName = strings.Join(names, " ")
			custom.HTTP2 = l.TLS && site.TLS.HTTP2
			custom.HTTP3 = l.TLS && site.TLS.HTTP3
			custom.QUICListen = make([]string, len(s.QUICListen))
			for i, listen := range s.QUICListen {
				custom.QUICListen[i] = strings.ReplaceAll(strings.ReplaceAll(listen, " default_server", ""), " reuseport", "")
			}
			custom.Gzip, custom.GzipMinLength = site.TLS.Gzip, max(site.TLS.GzipMinLength, 1)
			custom.GzipTypes = strings.Join(site.TLS.GzipTypes, " ")
			custom.CipherProfile = site.TLS.CipherProfile
			out = append(out, custom)
		}
	}
	return append(out, edgeServer{Listen: []string{"unix:" + p.EdgeSocket + " default_server"}, Local: true, ServerName: "_"})
}

type originLayer struct {
	Socket string
	Verify bool
}

// Render returns nginx.conf for plan.
func Render(p Params, plan *configir.Plan) ([]byte, error) {
	p = p.WithDefaults()
	if err := p.validate(); err != nil {
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
		if !safeWord.MatchString(z.Name) {
			return nil, fmt.Errorf("invalid cache zone name %q", z.Name)
		}
	}
	dicts, err := sharedDicts(p)
	if err != nil {
		return nil, err
	}
	d := data{
		Params:      p,
		SharedDicts: dicts,
		EdgeServers: edgeServers(p, plan),
		CacheZones:  plan.CacheZones,
		DefaultZone: plan.CacheZones[0].Name,
		OriginLayers: []originLayer{
			{Socket: p.OriginSocket, Verify: true},
			{Socket: p.OriginSocketNoVerify, Verify: false},
		},
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
