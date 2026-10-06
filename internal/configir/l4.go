package configir

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// FeatureL4 covers layer-4 (TCP / UDP) applications (proto v0.15.0,
// NodeConfig.l4_apps and ReportStatsV2Request.l4_stats): the console
// requires it when a configuration carries applications.
const FeatureL4 = "l4-v1"

// Transports of layer-4 applications as the data plane names them.
const (
	L4TCP = "tcp"
	L4UDP = "udp"
)

// Bounds of a layer-4 application (config.proto L4App).
const (
	MinL4Port           = 1024
	MaxL4Apps           = 1024
	MaxL4Origins        = 32
	MaxL4Weight         = 100
	MaxL4MaxFails       = 100
	MaxL4FailTimeout    = 3600
	MinL4ConnectTimeout = 100
	MaxL4ConnectTimeout = 60000
	MaxL4IdleTimeout    = 86400
	// MaxL4RangePorts bounds the ports of one application's range
	// (feature l4-v2).
	MaxL4RangePorts = 1000
)

// L4App is a validated layer-4 application. Port, Protocol,
// AcceptProxyProtocol and ProxyProtocolVersion shape the stream server
// that nginx.conf renders for the port (internal/render); everything else
// reaches the data plane through the control socket (hot update). JSON
// tags define the application in the data plane's layer-4 table.
type L4App struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	Port     uint32 `json:"port"`
	// AcceptProxyProtocol: the listener expects a PROXY protocol header
	// (TCP only).
	AcceptProxyProtocol bool `json:"accept_proxy_protocol,omitempty"`
	// ProxyProtocolVersion is the PROXY protocol header sent to the
	// origins: 0 none, 1 or 2 (TCP only).
	ProxyProtocolVersion uint32     `json:"proxy_protocol_version,omitempty"`
	Origins              []L4Origin `json:"origins"`
	// MaxFails consecutive connection failures within FailTimeout seconds
	// take an origin out for FailTimeout seconds.
	MaxFails    uint32 `json:"max_fails"`
	FailTimeout uint32 `json:"fail_timeout"`
	// ConnectTimeoutMS bounds a connection attempt towards an origin;
	// IdleTimeout ends a connection or UDP session without traffic.
	ConnectTimeoutMS uint32 `json:"connect_timeout_ms"`
	IdleTimeout      uint32 `json:"idle_timeout"`
	// AllowLists and BlockLists are ids of Plan.IPLists.
	AllowLists []string `json:"allow_lists,omitempty"`
	BlockLists []string `json:"block_lists,omitempty"`
	// Per node: concurrent connections or sessions and new ones per
	// second (0: no limit).
	MaxConnections          uint32 `json:"max_connections,omitempty"`
	NewConnectionsPerSecond uint32 `json:"new_connections_per_second,omitempty"`
	// PortEnd is the last port of the range Port..PortEnd (0: Port alone;
	// feature l4-v2).
	PortEnd uint32 `json:"port_end,omitempty"`
	// CertificateID: TCP applications that terminate TLS (feature l4-v2)
	// with this certificate and TLSMinimumVersion ("1.2" or "1.3"); the
	// agent attaches the material (Certificate) like for sites.
	CertificateID     string       `json:"certificate_id,omitempty"`
	TLSMinimumVersion string       `json:"tls_minimum_version,omitempty"`
	Certificate       *Certificate `json:"certificate,omitempty"`
	// CertificateNames are the DNS names of the certificate (lowercase):
	// the SNI of a handshake must be one of them.
	CertificateNames []string `json:"certificate_names,omitempty"`
}

// LastPort is the last port of the application's range (Port for a
// single port).
func (a L4App) LastPort() uint32 {
	return max(a.Port, a.PortEnd)
}

// TLS reports whether the node terminates TLS for the application.
func (a L4App) TLS() bool {
	return a.CertificateID != ""
}

// L4Origin is an upstream of a layer-4 application.
type L4Origin struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	// Port 0: the port the connection or session arrived on (l4-v2).
	Port   uint32 `json:"port"`
	Weight uint32 `json:"weight"`
	Backup bool   `json:"backup,omitempty"`
	// Forbidden marks an IP literal in a special-purpose range outside the
	// origin allow list: the data plane never connects to it.
	Forbidden bool `json:"forbidden,omitempty"`
}

// Relay reports whether the application's TCP connections go through the
// data plane's Lua relay instead of nginx's own proxy: nginx sends PROXY
// protocol headers with the TCP peer's address, so an application that
// both accepts and sends the PROXY protocol needs the relay to pass on
// the client's address from the header it received.
func (a L4App) Relay() bool {
	return a.Protocol == L4TCP && a.AcceptProxyProtocol && a.ProxyProtocolVersion > 0
}

// buildL4Apps validates NodeConfig.l4_apps. Any invalid application
// rejects the whole configuration (the console validates the same
// bounds); origins with special-purpose IP literals outside the allow list
// stay, marked forbidden, with a warning (like site origins).
func buildL4Apps(c *nodev1.NodeConfig, policy AddressPolicy) ([]L4App, []string, error) {
	apps := c.GetL4Apps()
	if len(apps) == 0 {
		return nil, nil, nil
	}
	if len(apps) > MaxL4Apps {
		return nil, nil, fmt.Errorf("%w: more than %d layer-4 applications", ErrRejected, MaxL4Apps)
	}
	// Every port a listener names counts, including skipped listeners and
	// the UDP port of HTTP/3.
	listeners := map[uint32]bool{}
	for _, l := range c.GetListeners() {
		listeners[l.GetPort()] = true
	}
	certificates := map[string]bool{}
	for _, cert := range c.GetCertificates() {
		certificates[cert.GetId()] = true
	}
	lists := map[string]bool{}
	for _, l := range c.GetIpLists() {
		lists[l.GetId()] = true
	}
	var out []L4App
	var warnings []string
	previous := ""
	for i, a := range apps {
		id := a.GetId()
		if !idRE.MatchString(id) {
			return nil, nil, fmt.Errorf("%w: layer-4 application id %q may only contain letters, digits, \"_\" and \"-\" (at most 128)", ErrRejected, id)
		}
		if i > 0 && id <= previous {
			return nil, nil, fmt.Errorf("%w: layer-4 applications are not sorted by id or %q is repeated", ErrRejected, id)
		}
		previous = id
		app, err := buildL4App(a, listeners, lists, certificates)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: layer-4 application %q: %w", ErrRejected, id, err)
		}
		for _, other := range out {
			if other.Protocol == app.Protocol && other.Port <= app.LastPort() && app.Port <= other.LastPort() {
				return nil, nil, fmt.Errorf("%w: layer-4 applications %q and %q both use %s port %d", ErrRejected, other.ID, id, strings.ToUpper(app.Protocol), max(app.Port, other.Port))
			}
		}
		for i, o := range app.Origins {
			if ip, err := netip.ParseAddr(o.Address); err == nil && policy.Forbidden(ip) {
				app.Origins[i].Forbidden = true
				warnings = append(warnings, fmt.Sprintf("layer-4 application %s: origin %q refused: %s is a special-purpose address outside the origin allow list", id, o.ID, o.Address))
			}
		}
		out = append(out, app)
	}
	return out, warnings, nil
}

func buildL4App(a *nodev1.L4App, listeners map[uint32]bool, lists, certificates map[string]bool) (L4App, error) {
	app := L4App{
		ID:                      a.GetId(),
		Port:                    a.GetPort(),
		AcceptProxyProtocol:     a.GetAcceptProxyProtocol(),
		ProxyProtocolVersion:    a.GetProxyProtocolVersion(),
		MaxFails:                a.GetMaxFails(),
		FailTimeout:             a.GetFailTimeoutSeconds(),
		ConnectTimeoutMS:        a.GetConnectTimeoutMs(),
		IdleTimeout:             a.GetIdleTimeoutSeconds(),
		MaxConnections:          a.GetMaxConnections(),
		NewConnectionsPerSecond: a.GetNewConnectionsPerSecond(),
		PortEnd:                 a.GetPortEnd(),
		CertificateID:           a.GetCertificateId(),
		TLSMinimumVersion:       a.GetTlsMinimumVersion(),
	}
	switch a.GetProtocol() {
	case nodev1.L4Protocol_L4_PROTOCOL_TCP:
		app.Protocol = L4TCP
	case nodev1.L4Protocol_L4_PROTOCOL_UDP:
		app.Protocol = L4UDP
	default:
		return app, errors.New("protocol must be TCP or UDP")
	}
	switch {
	case app.Port < MinL4Port || app.Port > 65535:
		return app, fmt.Errorf("port %d out of range (%d-65535)", app.Port, MinL4Port)
	case app.PortEnd != 0 && (app.PortEnd <= app.Port || app.PortEnd > 65535 || app.PortEnd-app.Port >= MaxL4RangePorts):
		return app, fmt.Errorf("port range %d-%d (the last port above the first, at most %d ports)", app.Port, app.PortEnd, MaxL4RangePorts)
	case app.CertificateID != "" && app.Protocol != L4TCP:
		return app, errors.New("TLS is for TCP only")
	case app.CertificateID != "" && !certificates[app.CertificateID]:
		return app, fmt.Errorf("missing certificate reference %q", app.CertificateID)
	case app.CertificateID != "" && app.TLSMinimumVersion != "1.2" && app.TLSMinimumVersion != "1.3":
		return app, fmt.Errorf("minimum TLS version %q (1.2 or 1.3)", app.TLSMinimumVersion)
	case app.CertificateID == "" && app.TLSMinimumVersion != "":
		return app, errors.New("a minimum TLS version without a certificate")
	case l4RangeHitsListener(app, listeners):
		return app, fmt.Errorf("port range %d-%d holds a listener of the node", app.Port, app.LastPort())
	case app.ProxyProtocolVersion > 2:
		return app, fmt.Errorf("PROXY protocol version %d (0, 1 or 2)", app.ProxyProtocolVersion)
	case app.Protocol == L4UDP && (app.AcceptProxyProtocol || app.ProxyProtocolVersion != 0):
		return app, errors.New("the PROXY protocol is for TCP only")
	case app.MaxFails < 1 || app.MaxFails > MaxL4MaxFails:
		return app, fmt.Errorf("max_fails %d out of range (1-%d)", app.MaxFails, MaxL4MaxFails)
	case app.FailTimeout < 1 || app.FailTimeout > MaxL4FailTimeout:
		return app, fmt.Errorf("fail timeout %d s out of range (1-%d)", app.FailTimeout, MaxL4FailTimeout)
	case app.ConnectTimeoutMS < MinL4ConnectTimeout || app.ConnectTimeoutMS > MaxL4ConnectTimeout:
		return app, fmt.Errorf("connect timeout %d ms out of range (%d-%d)", app.ConnectTimeoutMS, MinL4ConnectTimeout, MaxL4ConnectTimeout)
	case app.IdleTimeout < 1 || app.IdleTimeout > MaxL4IdleTimeout:
		return app, fmt.Errorf("idle timeout %d s out of range (1-%d)", app.IdleTimeout, MaxL4IdleTimeout)
	}
	var err error
	if app.AllowLists, err = l4Lists("allow", a.GetAllowListIds(), lists); err != nil {
		return app, err
	}
	if app.BlockLists, err = l4Lists("block", a.GetBlockListIds(), lists); err != nil {
		return app, err
	}
	origins := a.GetOrigins()
	if len(origins) == 0 || len(origins) > MaxL4Origins {
		return app, fmt.Errorf("%d origins (1-%d)", len(origins), MaxL4Origins)
	}
	seen := map[string]bool{}
	for _, o := range origins {
		origin, err := buildL4Origin(o)
		if err != nil {
			return app, err
		}
		if seen[origin.ID] {
			return app, fmt.Errorf("origin %q is repeated", origin.ID)
		}
		seen[origin.ID] = true
		app.Origins = append(app.Origins, origin)
	}
	return app, nil
}

func l4RangeHitsListener(app L4App, listeners map[uint32]bool) bool {
	for port := range listeners {
		if app.Port <= port && port <= app.LastPort() {
			return true
		}
	}
	return false
}

// l4Lists checks the IP list ids of an application: ids of
// NodeConfig.ip_lists, sorted without duplicates (canonical form).
func l4Lists(kind string, ids []string, lists map[string]bool) ([]string, error) {
	for i, id := range ids {
		if !lists[id] {
			return nil, fmt.Errorf("unknown %s list %q", kind, id)
		}
		if i > 0 && id <= ids[i-1] {
			return nil, fmt.Errorf("%s list ids are not sorted or %q is repeated", kind, id)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	return append([]string(nil), ids...), nil
}

func buildL4Origin(o *nodev1.L4Origin) (L4Origin, error) {
	id := o.GetId()
	if !idRE.MatchString(id) {
		return L4Origin{}, fmt.Errorf("origin id %q may only contain letters, digits, \"_\" and \"-\" (at most 128)", id)
	}
	addr := strings.ToLower(strings.TrimSpace(o.GetAddress()))
	if ip, err := netip.ParseAddr(addr); err == nil {
		if ip.Zone() != "" {
			return L4Origin{}, fmt.Errorf("origin %q: zoned IPv6 addresses are not supported", id)
		}
		addr = ip.String()
	} else if !ValidHostname(addr) {
		return L4Origin{}, fmt.Errorf("origin %q: invalid address %q", id, o.GetAddress())
	}
	switch {
	case o.GetPort() > 65535:
		return L4Origin{}, fmt.Errorf("origin %q: port %d out of range (0-65535)", id, o.GetPort())
	case o.GetWeight() < 1 || o.GetWeight() > MaxL4Weight:
		return L4Origin{}, fmt.Errorf("origin %q: weight %d out of range (1-%d)", id, o.GetWeight(), MaxL4Weight)
	}
	return L4Origin{ID: id, Address: addr, Port: o.GetPort(), Weight: o.GetWeight(), Backup: o.GetBackup()}, nil
}

// L4Lists returns the IP lists the layer-4 applications use, in plan
// order.
func (p *Plan) L4Lists() []*nodev1.IpList {
	used := map[string]bool{}
	for _, a := range p.L4Apps {
		for _, id := range a.AllowLists {
			used[id] = true
		}
		for _, id := range a.BlockLists {
			used[id] = true
		}
	}
	var out []*nodev1.IpList
	for _, l := range p.IPLists {
		if used[l.GetId()] {
			out = append(out, l)
		}
	}
	return out
}
