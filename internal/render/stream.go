package render

import (
	"fmt"

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
	Listen   []string
	// Relay: content_by_lua relays the connection (TCP applications that
	// accept and send the PROXY protocol); ProxyProtocol is nginx's
	// proxy_protocol towards the origin otherwise ("on" for version 1,
	// "v2", "" for none).
	Relay         bool
	ProxyProtocol string
	// Accept: the listener expects a PROXY protocol header.
	Accept bool
}

// l4Servers returns the stream servers of plan's layer-4 applications. It
// checks again what nginx.conf takes from them (configir validated the
// same): nginx.conf never trusts its input.
func l4Servers(p Params, plan *configir.Plan) ([]l4Server, error) {
	listeners := map[uint32]bool{}
	for _, l := range plan.Listeners {
		listeners[l.Port] = true
	}
	seen := map[string]bool{}
	var out []l4Server
	for _, a := range plan.L4Apps {
		key := fmt.Sprintf("%s:%d", a.Protocol, a.Port)
		switch {
		case a.Protocol != configir.L4TCP && a.Protocol != configir.L4UDP:
			return nil, fmt.Errorf("layer-4 application %q: invalid protocol %q", a.ID, a.Protocol)
		case a.Port < configir.MinL4Port || a.Port > 65535:
			return nil, fmt.Errorf("layer-4 application %q: invalid port %d", a.ID, a.Port)
		case listeners[a.Port]:
			return nil, fmt.Errorf("layer-4 application %q: port %d is a listener", a.ID, a.Port)
		case seen[key]:
			return nil, fmt.Errorf("layer-4 application %q: %s port %d is used twice", a.ID, a.Protocol, a.Port)
		case a.ProxyProtocolVersion > 2 || (a.Protocol == configir.L4UDP && (a.AcceptProxyProtocol || a.ProxyProtocolVersion > 0)):
			return nil, fmt.Errorf("layer-4 application %q: invalid PROXY protocol settings", a.ID)
		}
		seen[key] = true
		suffix := " reuseport"
		if a.Protocol == configir.L4UDP {
			// udp needs reuseport so that the datagrams of a client stay in
			// one session (one worker).
			suffix = " udp reuseport"
		}
		if a.AcceptProxyProtocol {
			suffix += " proxy_protocol"
		}
		s := l4Server{Protocol: a.Protocol, Port: a.Port, Accept: a.AcceptProxyProtocol, Relay: a.Relay()}
		s.Listen = []string{fmt.Sprintf("%d%s", a.Port, suffix)}
		if p.ListenIPv6 {
			s.Listen = append(s.Listen, fmt.Sprintf("[::]:%d%s", a.Port, suffix))
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
