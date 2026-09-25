// Package render produces the OpenResty nginx.conf from a validated plan.
//
// The rendered file only depends on structural settings (listeners, cache
// zones, resolver, paths), never on sites, so comparing the rendered bytes
// is exactly the "structural change" test that decides between a reload and
// a hot update through the control socket.
package render

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/edgeweir/edgeweir-node/internal/configir"
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
	EdgeSocket string
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
	EdgeServers  []edgeServer
	CacheZones   []configir.CacheZone
	DefaultZone  string
	OriginLayers []originLayer
}

// edgeServer is one server block of the edge layer.
type edgeServer struct {
	Listen        []string // listen directive arguments
	HTTP2         bool
	ProxyProtocol bool
	Local         bool // the agent's unix socket listener
}

func edgeServers(p Params, listeners []configir.Listener) []edgeServer {
	var out []edgeServer
	for _, l := range listeners {
		suffix := " default_server"
		if l.ProxyProtocol {
			suffix += " proxy_protocol"
		}
		s := edgeServer{Listen: []string{fmt.Sprintf("%d%s", l.Port, suffix)}, HTTP2: l.HTTP2, ProxyProtocol: l.ProxyProtocol}
		if p.ListenIPv6 {
			s.Listen = append(s.Listen, fmt.Sprintf("[::]:%d%s", l.Port, suffix))
		}
		out = append(out, s)
	}
	return append(out, edgeServer{Listen: []string{"unix:" + p.EdgeSocket + " default_server"}, Local: true})
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
	var buf bytes.Buffer
	err := tmpl.Execute(&buf, data{
		Params:      p,
		EdgeServers: edgeServers(p, plan.Listeners),
		CacheZones:  plan.CacheZones,
		DefaultZone: plan.CacheZones[0].Name,
		OriginLayers: []originLayer{
			{Socket: p.OriginSocket, Verify: true},
			{Socket: p.OriginSocketNoVerify, Verify: false},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("render nginx.conf: %w", err)
	}
	return buf.Bytes(), nil
}
