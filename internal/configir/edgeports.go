package configir

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// Features of proto v0.23.0. FeatureEdgePorts: listeners besides 80 and
// 443, the ports a site is served on (Site.ports) and the HTTPS redirect's
// status, port and excluded domains (TlsOptions.redirect_*).
// FeatureClientIP: the cluster's client address setting
// (NodeConfig.client_address: PROXY protocol on the HTTP(S) listeners or a
// header of trusted proxies) and the rule field ip.peer. FeatureL4V2:
// layer-4 port ranges, origins on the arriving port and TLS termination of
// TCP applications. The console requires each one when a configuration
// uses it.
const (
	FeatureEdgePorts = "edge-ports-v1"
	FeatureClientIP  = "client-ip-v1"
	FeatureL4V2      = "l4-v2"
)

// Client address modes (ClientAddress.mode).
const (
	ClientAddressDirect        = "direct"
	ClientAddressProxyProtocol = "proxy_protocol"
	ClientAddressHeader        = "header"
)

// Bounds of the client address setting and of the HTTPS redirect.
const (
	MaxTrustedCIDRs            = 64
	MaxRedirectExcludedDomains = 50
)

// ClientAddress is the validated client address setting of the cluster's
// HTTP(S) listeners. JSON tags define its form in the site table (Lua uses
// TrustedCIDRs: never banned, not counted per address by CC).
type ClientAddress struct {
	Mode             string   `json:"mode"`
	TrustedCIDRs     []string `json:"trusted_cidrs,omitempty"`
	Header           string   `json:"header,omitempty"`
	DropForwardedFor bool     `json:"drop_forwarded_for,omitempty"`
}

var clientHeaderRE = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// Headers that can never name the client: hop-by-hop and connection
// headers, and those the edge sets or reads itself.
var refusedClientHeaders = []string{"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "te", "trailer", "host", "content-length", "content-type", "cookie", "authorization", "cdn-loop", "x-request-id"}

// buildClientAddress validates NodeConfig.client_address against the
// listeners: mode proxy_protocol needs every listener to take the PROXY
// protocol, the other modes none of them. Without the setting listeners
// may still take it one by one (Listener.proxy_protocol predates it).
func buildClientAddress(c *nodev1.NodeConfig) (*ClientAddress, error) {
	ca := c.GetClientAddress()
	proxied := 0
	for _, l := range c.GetListeners() {
		if l.GetProxyProtocol() {
			proxied++
		}
	}
	if ca == nil {
		// Listeners may take the PROXY protocol on their own (Listener
		// field 5, older than the setting).
		return nil, nil
	}
	out := &ClientAddress{Mode: ca.GetMode(), DropForwardedFor: ca.GetDropForwardedFor()}
	switch out.Mode {
	case ClientAddressProxyProtocol:
		if proxied != len(c.GetListeners()) {
			return nil, fmt.Errorf("%w: client address mode proxy_protocol needs the PROXY protocol on every listener", ErrRejected)
		}
	case ClientAddressHeader, ClientAddressDirect:
		if proxied > 0 {
			return nil, fmt.Errorf("%w: listeners take the PROXY protocol, but the client address mode is %s", ErrRejected, out.Mode)
		}
	default:
		return nil, fmt.Errorf("%w: unknown client address mode %q", ErrRejected, out.Mode)
	}
	if out.DropForwardedFor && out.Mode != ClientAddressDirect {
		return nil, fmt.Errorf("%w: dropping X-Forwarded-For is for the direct mode only", ErrRejected)
	}
	if out.Mode == ClientAddressDirect && !out.DropForwardedFor {
		return nil, fmt.Errorf("%w: a direct client address setting must drop X-Forwarded-For (else it is left out)", ErrRejected)
	}
	if out.Mode != ClientAddressHeader {
		if len(ca.GetTrustedCidrs()) > 0 || ca.GetHeader() != "" {
			return nil, fmt.Errorf("%w: trusted CIDRs and the header are for the header mode only", ErrRejected)
		}
		return out, nil
	}
	cidrs := ca.GetTrustedCidrs()
	if len(cidrs) < 1 || len(cidrs) > MaxTrustedCIDRs {
		return nil, fmt.Errorf("%w: %d trusted CIDRs (1-%d)", ErrRejected, len(cidrs), MaxTrustedCIDRs)
	}
	for i, s := range cidrs {
		prefix, err := netip.ParsePrefix(s)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Masked() != prefix || prefix.String() != s {
			return nil, fmt.Errorf("%w: trusted CIDR %q is not in canonical form", ErrRejected, s)
		}
		if i > 0 && s <= cidrs[i-1] {
			return nil, fmt.Errorf("%w: trusted CIDRs are not sorted or %q is repeated", ErrRejected, s)
		}
	}
	out.TrustedCIDRs = append([]string(nil), cidrs...)
	header := ca.GetHeader()
	if !clientHeaderRE.MatchString(header) || strings.HasPrefix(header, "x-edgeweir-") || slices.Contains(refusedClientHeaders, header) {
		return nil, fmt.Errorf("%w: invalid client address header %q", ErrRejected, header)
	}
	out.Header = header
	return out, nil
}

// buildSitePorts validates Site.ports: listener ports, sorted and unique,
// HTTPS ones only for a site with a certificate. tls tells the listener
// ports that are HTTPS.
func buildSitePorts(s *nodev1.Site, listeners map[uint32]bool) ([]uint32, error) {
	ports := s.GetPorts()
	for i, port := range ports {
		tls, ok := listeners[port]
		switch {
		case !ok:
			return nil, fmt.Errorf("%w: site %q: port %d is not a listener", ErrRejected, s.GetId(), port)
		case i > 0 && port <= ports[i-1]:
			return nil, fmt.Errorf("%w: site %q: ports are not sorted or %d is repeated", ErrRejected, s.GetId(), port)
		case tls && s.GetCertificateId() == "":
			return nil, fmt.Errorf("%w: site %q: HTTPS port %d without a certificate", ErrRejected, s.GetId(), port)
		}
	}
	if len(ports) == 0 {
		return nil, nil
	}
	return append([]uint32(nil), ports...), nil
}

// buildRedirect validates the HTTPS redirect options of a site's TLS
// settings: the status, a target port among the site's HTTPS ports and
// excluded domains among the site's domains (as written in the config).
func buildRedirect(s *nodev1.Site, ports []uint32, listeners map[uint32]bool, out *TLSOptions) error {
	tls := s.GetTls()
	switch tls.GetRedirectStatus() {
	case 0, 301, 302, 303, 307, 308:
	default:
		return fmt.Errorf("%w: site %q: HTTPS redirect status %d (301, 302, 303, 307 or 308)", ErrRejected, s.GetId(), tls.GetRedirectStatus())
	}
	if port := tls.GetRedirectPort(); port != 0 {
		https, ok := listeners[port]
		if !ok || !https || (len(ports) > 0 && !slices.Contains(ports, port)) {
			return fmt.Errorf("%w: site %q: HTTPS redirect port %d is not an HTTPS port of the site", ErrRejected, s.GetId(), port)
		}
	}
	excluded := tls.GetRedirectExcludedDomains()
	if len(excluded) > MaxRedirectExcludedDomains {
		return fmt.Errorf("%w: site %q: more than %d domains excluded from the HTTPS redirect", ErrRejected, s.GetId(), MaxRedirectExcludedDomains)
	}
	names := map[string]bool{}
	for _, d := range s.GetDomains() {
		names[displayDomain(strings.ToLower(d.GetName()), d.GetWildcard())] = true
	}
	for i, name := range excluded {
		if !names[name] {
			return fmt.Errorf("%w: site %q: %q is excluded from the HTTPS redirect but is no domain of the site", ErrRejected, s.GetId(), name)
		}
		if i > 0 && name <= excluded[i-1] {
			return fmt.Errorf("%w: site %q: excluded domains are not sorted or %q is repeated", ErrRejected, s.GetId(), name)
		}
	}
	out.RedirectStatus = tls.GetRedirectStatus()
	if tls.GetRedirectPort() != 443 {
		out.RedirectPort = tls.GetRedirectPort()
	}
	if len(excluded) > 0 {
		out.RedirectExcluded = append([]string(nil), excluded...)
	}
	return nil
}

// ListenerTLS maps every listener port of a NodeConfig to whether it is
// HTTPS (skipped listeners included: their ports are still the listener's).
func ListenerTLS(c *nodev1.NodeConfig) map[uint32]bool {
	out := map[uint32]bool{}
	for _, l := range c.GetListeners() {
		out[l.GetPort()] = l.GetProtocol() == nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTPS
	}
	return out
}
