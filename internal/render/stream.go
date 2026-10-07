package render

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

// l4Server is the stream server of one (port, protocol) of the layer-4
// applications. Only what nginx fixes per server lives here: the listen
// sockets (port, protocol, PROXY protocol on the listener) and how the
// connection reaches the origin (nginx's proxy with or without a PROXY
// protocol header, or the Lua relay). Which application the port belongs
// to, its origins, timeouts, IP lists and limits come from the layer-4
// table in lua_shared_dict edgeweir_l4 (hot update, edgeweir.l4).
type l4Server struct {
	Protocol string
	Port     uint32
	// PortEnd is the last port of a range (0: Port alone); Ports counts
	// them and ReusePort tells whether every worker has its own sockets.
	PortEnd   uint32
	Ports     uint32
	ReusePort bool
	Listen    []string
	// Relay: content_by_lua relays the connection (TCP applications that
	// accept and send the PROXY protocol); ProxyProtocol is nginx's
	// proxy_protocol towards the origin otherwise ("on" for version 1,
	// "v2", "" for none).
	Relay         bool
	ProxyProtocol string
	// Accept: the listener expects a PROXY protocol header.
	Accept bool
	// TLS: the server terminates TLS (TCP applications with a
	// certificate, chosen in Lua by edgeweir.l4).
	TLS bool
}

// l4Servers returns the stream servers of plan's layer-4 applications. It
// checks again what nginx.conf takes from them (configir validated the
// same): nginx.conf never trusts its input.
func l4Servers(p Params, plan *configir.Plan) ([]l4Server, error) {
	var out []l4Server
	for _, a := range plan.L4Apps {
		overlaps := slices.ContainsFunc(out, func(s l4Server) bool {
			return s.Protocol == a.Protocol && s.Port <= a.LastPort() && a.Port <= max(s.Port, s.PortEnd)
		})
		listener := slices.ContainsFunc(plan.Listeners, func(l configir.Listener) bool {
			return a.Port <= l.Port && l.Port <= a.LastPort()
		})
		switch {
		case a.Protocol != configir.L4TCP && a.Protocol != configir.L4UDP:
			return nil, fmt.Errorf("layer-4 application %q: invalid protocol %q", a.ID, a.Protocol)
		case a.Port < configir.MinL4Port || a.Port > 65535:
			return nil, fmt.Errorf("layer-4 application %q: invalid port %d", a.ID, a.Port)
		case a.PortEnd != 0 && (a.PortEnd <= a.Port || a.PortEnd > 65535 || a.PortEnd-a.Port >= configir.MaxL4RangePorts):
			return nil, fmt.Errorf("layer-4 application %q: invalid port range %d-%d", a.ID, a.Port, a.PortEnd)
		case listener:
			return nil, fmt.Errorf("layer-4 application %q: port %d is a listener", a.ID, a.Port)
		case overlaps:
			return nil, fmt.Errorf("layer-4 application %q: %s port %d is used twice", a.ID, a.Protocol, a.Port)
		case a.TLS() && (a.Protocol != configir.L4TCP || (a.TLSMinimumVersion != "1.2" && a.TLSMinimumVersion != "1.3")):
			return nil, fmt.Errorf("layer-4 application %q: invalid TLS settings", a.ID)
		case a.ProxyProtocolVersion > 2 || (a.Protocol == configir.L4UDP && (a.AcceptProxyProtocol || a.ProxyProtocolVersion > 0)):
			return nil, fmt.Errorf("layer-4 application %q: invalid PROXY protocol settings", a.ID)
		}
		s := l4Server{Protocol: a.Protocol, Port: a.Port, PortEnd: a.PortEnd, Ports: a.LastPort() - a.Port + 1, Accept: a.AcceptProxyProtocol, Relay: a.Relay(), TLS: a.TLS()}
		// udp needs reuseport so that the datagrams of a client stay in one
		// session (one worker). TCP ranges share one socket per port among
		// the workers: with reuseport every worker would hold one per port.
		s.ReusePort = a.Protocol == configir.L4UDP || a.PortEnd == 0
		suffix := ""
		if a.Protocol == configir.L4UDP {
			suffix = " udp"
		}
		if s.ReusePort {
			suffix += " reuseport"
		}
		if s.TLS {
			suffix += " ssl"
		}
		if a.AcceptProxyProtocol {
			suffix += " proxy_protocol"
		}
		port := strconv.FormatUint(uint64(a.Port), 10)
		if a.PortEnd != 0 {
			port += "-" + strconv.FormatUint(uint64(a.PortEnd), 10)
		}
		s.Listen = []string{port + suffix}
		if p.ListenIPv6 {
			s.Listen = append(s.Listen, "[::]:"+port+suffix)
		}
		if !s.Relay {
			switch a.ProxyProtocolVersion {
			case 1:
				s.ProxyProtocol = "on"
			case 2:
				s.ProxyProtocol = "v2"
			}
		}
		out = append(out, s)
	}
	return out, nil
}
