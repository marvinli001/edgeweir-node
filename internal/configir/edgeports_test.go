package configir

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// edgeConfig has HTTP listeners on 80 and 8081, HTTPS on 443 and 9443,
// and a site with a certificate on 80, 8081 and 9443.
func edgeConfig() *nodev1.NodeConfig {
	https := nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTPS
	return &nodev1.NodeConfig{
		Listeners: []*nodev1.Listener{{Port: 80}, {Port: 443, Protocol: https}, {Port: 8081}, {Port: 9443, Protocol: https, Http3: true}},
		Certificates: []*nodev1.CertificateRef{
			{Id: "cert", Sha256Fingerprint: "0000000000000000000000000000000000000000000000000000000000000000"},
		},
		Sites: []*nodev1.Site{{
			Id: "s1", Enabled: true, CertificateId: "cert",
			Domains:    []*nodev1.Domain{{Name: "a.test"}, {Name: "b.test"}, {Name: "w.test", Wildcard: true}},
			OriginPool: &nodev1.OriginPool{Origins: []*nodev1.Origin{{Id: "o1", Address: "origin.test", Port: 80}}},
			Ports:      []uint32{80, 8081, 9443},
			Tls: &nodev1.TlsOptions{
				ForceHttps: true, MinimumVersion: "1.2", CipherProfile: "modern",
				RedirectStatus: 308, RedirectPort: 9443, RedirectExcludedDomains: []string{"*.w.test", "b.test"},
			},
		}},
	}
}

func TestBuildEdgePorts(t *testing.T) {
	p, err := Build(edgeConfig(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Listeners) != 4 || !p.Listeners[3].TLS || !p.Listeners[3].HTTP3 {
		t.Fatalf("listeners = %+v", p.Listeners)
	}
	s := p.Sites[0]
	if !slices.Equal(s.Ports, []uint32{80, 8081, 9443}) {
		t.Fatalf("ports = %v", s.Ports)
	}
	if s.TLS.RedirectStatus != 308 || s.TLS.RedirectPort != 9443 || !slices.Equal(s.TLS.RedirectExcluded, []string{"*.w.test", "b.test"}) {
		t.Fatalf("redirect = %+v", s.TLS)
	}
	// Port 443 is the default target: the data plane leaves it out of the
	// URL either way.
	c := edgeConfig()
	c.Sites[0].Ports = nil
	c.Sites[0].Tls.RedirectPort, c.Sites[0].Tls.RedirectStatus, c.Sites[0].Tls.RedirectExcludedDomains = 443, 0, nil
	if p, err = Build(c, Options{}); err != nil {
		t.Fatal(err)
	}
	if p.Sites[0].Ports != nil || p.Sites[0].TLS.RedirectPort != 0 || p.Sites[0].TLS.RedirectStatus != 0 || p.Sites[0].TLS.RedirectExcluded != nil {
		t.Fatalf("defaults = %+v %+v", p.Sites[0].Ports, p.Sites[0].TLS)
	}
	// Without a certificate a site may use HTTP ports only.
	c = edgeConfig()
	c.Sites[0].CertificateId, c.Sites[0].Tls = "", nil
	c.Sites[0].Ports = []uint32{8081}
	if p, err = Build(c, Options{}); err != nil || !slices.Equal(p.Sites[0].Ports, []uint32{8081}) {
		t.Fatalf("HTTP only: %v %+v", err, p)
	}
}

func TestBuildEdgePortsRejects(t *testing.T) {
	for name, mutate := range map[string]func(c *nodev1.NodeConfig){
		"not a listener":       func(c *nodev1.NodeConfig) { c.Sites[0].Ports = []uint32{80, 8082} },
		"unsorted":             func(c *nodev1.NodeConfig) { c.Sites[0].Ports = []uint32{8081, 80} },
		"repeated":             func(c *nodev1.NodeConfig) { c.Sites[0].Ports = []uint32{80, 80} },
		"HTTPS without cert":   func(c *nodev1.NodeConfig) { c.Sites[0].CertificateId, c.Sites[0].Tls = "", nil },
		"status 304":           func(c *nodev1.NodeConfig) { c.Sites[0].Tls.RedirectStatus = 304 },
		"status 200":           func(c *nodev1.NodeConfig) { c.Sites[0].Tls.RedirectStatus = 200 },
		"redirect to HTTP":     func(c *nodev1.NodeConfig) { c.Sites[0].Tls.RedirectPort = 8081 },
		"redirect to 443":      func(c *nodev1.NodeConfig) { c.Sites[0].Tls.RedirectPort = 443 }, // not a port of the site
		"redirect to unknown":  func(c *nodev1.NodeConfig) { c.Sites[0].Tls.RedirectPort = 10443 },
		"excluded unknown":     func(c *nodev1.NodeConfig) { c.Sites[0].Tls.RedirectExcludedDomains = []string{"c.test"} },
		"excluded wildcard":    func(c *nodev1.NodeConfig) { c.Sites[0].Tls.RedirectExcludedDomains = []string{"w.test"} },
		"excluded unsorted":    func(c *nodev1.NodeConfig) { c.Sites[0].Tls.RedirectExcludedDomains = []string{"b.test", "a.test"} },
		"excluded repeated":    func(c *nodev1.NodeConfig) { c.Sites[0].Tls.RedirectExcludedDomains = []string{"a.test", "a.test"} },
		"too many excluded":    func(c *nodev1.NodeConfig) { c.Sites[0].Tls.RedirectExcludedDomains = make([]string, 51) },
		"excluded upper case":  func(c *nodev1.NodeConfig) { c.Sites[0].Tls.RedirectExcludedDomains = []string{"A.test"} },
		"disabled site's port": func(c *nodev1.NodeConfig) { c.Sites[0].Enabled = false; c.Sites[0].Ports = []uint32{1} },
	} {
		c := edgeConfig()
		mutate(c)
		if _, err := Build(c, Options{}); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: err = %v, want rejection", name, err)
		}
	}
}

func TestBuildClientAddress(t *testing.T) {
	c := edgeConfig()
	c.ClientAddress = &nodev1.ClientAddress{Mode: "header", Header: "x-forwarded-for", TrustedCidrs: []string{"10.0.0.0/8", "192.0.2.7/32", "2001:db8::/32"}}
	p, err := Build(c, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if want := (&ClientAddress{Mode: "header", Header: "x-forwarded-for", TrustedCIDRs: []string{"10.0.0.0/8", "192.0.2.7/32", "2001:db8::/32"}}); p.ClientAddress == nil || p.ClientAddress.Header != want.Header || !slices.Equal(p.ClientAddress.TrustedCIDRs, want.TrustedCIDRs) {
		t.Fatalf("client address = %+v", p.ClientAddress)
	}
	c = edgeConfig()
	for _, l := range c.Listeners {
		l.ProxyProtocol = true
	}
	c.ClientAddress = &nodev1.ClientAddress{Mode: "proxy_protocol"}
	if p, err = Build(c, Options{}); err != nil || !p.Listeners[0].ProxyProtocol || !p.Listeners[3].ProxyProtocol {
		t.Fatalf("proxy_protocol: %v %+v", err, p)
	}
	c = edgeConfig()
	c.ClientAddress = &nodev1.ClientAddress{Mode: "direct", DropForwardedFor: true}
	if p, err = Build(c, Options{}); err != nil || !p.ClientAddress.DropForwardedFor {
		t.Fatalf("direct: %v %+v", err, p)
	}
	if p, err = Build(edgeConfig(), Options{}); err != nil || p.ClientAddress != nil {
		t.Fatalf("none: %v %+v", err, p)
	}
	// A listener may take the PROXY protocol without the setting (older
	// configurations).
	c = edgeConfig()
	c.Listeners[2].ProxyProtocol = true
	if p, err = Build(c, Options{}); err != nil || p.ClientAddress != nil || !p.Listeners[2].ProxyProtocol {
		t.Fatalf("listener PROXY: %v %+v", err, p)
	}
}

func TestBuildClientAddressRejects(t *testing.T) {
	header := func(name string, cidrs ...string) func(c *nodev1.NodeConfig) {
		return func(c *nodev1.NodeConfig) {
			c.ClientAddress = &nodev1.ClientAddress{Mode: "header", Header: name, TrustedCidrs: cidrs}
		}
	}
	for name, mutate := range map[string]func(c *nodev1.NodeConfig){
		"unknown mode": func(c *nodev1.NodeConfig) { c.ClientAddress = &nodev1.ClientAddress{Mode: "auto"} },
		"PROXY on some listeners": func(c *nodev1.NodeConfig) {
			c.Listeners[0].ProxyProtocol = true
			c.ClientAddress = &nodev1.ClientAddress{Mode: "proxy_protocol"}
		},
		"PROXY listener in header mode": func(c *nodev1.NodeConfig) {
			header("x-real-ip", "10.0.0.0/8")(c)
			c.Listeners[0].ProxyProtocol = true
		},
		"direct keeping XFF": func(c *nodev1.NodeConfig) { c.ClientAddress = &nodev1.ClientAddress{Mode: "direct"} },
		"drop in header mode": func(c *nodev1.NodeConfig) {
			header("x-real-ip", "10.0.0.0/8")(c)
			c.ClientAddress.DropForwardedFor = true
		},
		"CIDRs in direct mode": func(c *nodev1.NodeConfig) {
			c.ClientAddress = &nodev1.ClientAddress{Mode: "direct", DropForwardedFor: true, TrustedCidrs: []string{"10.0.0.0/8"}}
		},
		"no CIDR": header("x-real-ip"),
		"65 CIDRs": func(c *nodev1.NodeConfig) {
			header("x-real-ip")(c)
			for i := range 65 {
				c.ClientAddress.TrustedCidrs = append(c.ClientAddress.TrustedCidrs, "10.0."+string(rune('0'+i/10))+string(rune('0'+i%10))+".0/24")
			}
		},
		"host bits":         header("x-real-ip", "10.0.0.1/8"),
		"not canonical v6":  header("x-real-ip", "2001:DB8::/32"),
		"no prefix":         header("x-real-ip", "10.0.0.1"),
		"unsorted CIDRs":    header("x-real-ip", "192.0.2.0/24", "10.0.0.0/8"),
		"repeated CIDRs":    header("x-real-ip", "10.0.0.0/8", "10.0.0.0/8"),
		"no header":         header("", "10.0.0.0/8"),
		"upper case header": header("X-Real-IP", "10.0.0.0/8"),
		"underscore header": header("x_real_ip", "10.0.0.0/8"),
		"internal header":   header("x-edgeweir-site", "10.0.0.0/8"),
		"hop-by-hop header": header("connection", "10.0.0.0/8"),
		"host header":       header("host", "10.0.0.0/8"),
		"long header":       header("x-"+strings.Repeat("a", 63), "10.0.0.0/8"),
	} {
		c := edgeConfig()
		mutate(c)
		if _, err := Build(c, Options{}); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: err = %v, want rejection", name, err)
		}
	}
}

func TestBuildL4RangesAndTLS(t *testing.T) {
	tcp := l4App("app-a", 9000)
	tcp.PortEnd = 9999
	tcp.Origins[0].Port = 0
	udp := l4App("app-b", 9000)
	udp.Protocol, udp.PortEnd = nodev1.L4Protocol_L4_PROTOCOL_UDP, 9001
	tls := l4App("app-c", 10000)
	tls.CertificateId, tls.TlsMinimumVersion, tls.AcceptProxyProtocol, tls.ProxyProtocolVersion = "cert", "1.3", true, 2
	c := l4Config(tcp, udp, tls)
	c.Certificates = []*nodev1.CertificateRef{{Id: "cert", Sha256Fingerprint: "0000000000000000000000000000000000000000000000000000000000000000"}}
	p, err := Build(c, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if a := p.L4Apps[0]; a.PortEnd != 9999 || a.LastPort() != 9999 || a.Origins[0].Port != 0 || a.TLS() {
		t.Fatalf("range = %+v", a)
	}
	if a := p.L4Apps[2]; !a.TLS() || a.TLSMinimumVersion != "1.3" || !a.Relay() || a.LastPort() != 10000 {
		t.Fatalf("TLS = %+v", a)
	}
	for name, mutate := range map[string]func(c *nodev1.NodeConfig){
		"range of 1001":      func(c *nodev1.NodeConfig) { c.L4Apps[0].PortEnd = 10000 },
		"range end below":    func(c *nodev1.NodeConfig) { c.L4Apps[0].PortEnd = 8999 },
		"range end equal":    func(c *nodev1.NodeConfig) { c.L4Apps[0].PortEnd = 9000 },
		"range end 65536":    func(c *nodev1.NodeConfig) { c.L4Apps[0].Port, c.L4Apps[0].PortEnd = 65000, 65536 },
		"range overlaps":     func(c *nodev1.NodeConfig) { c.L4Apps[2].Port = 9999 },
		"UDP ranges overlap": func(c *nodev1.NodeConfig) { c.L4Apps[1].PortEnd = 0; c.L4Apps[1].Port = 9001; c.L4Apps[0].Protocol = 2 },
		"range holds listener": func(c *nodev1.NodeConfig) {
			c.L4Apps[0].Port, c.L4Apps[0].PortEnd = 8000, 8999
		},
		"TLS for UDP":          func(c *nodev1.NodeConfig) { c.L4Apps[1].CertificateId, c.L4Apps[1].TlsMinimumVersion = "cert", "1.2" },
		"unknown certificate":  func(c *nodev1.NodeConfig) { c.L4Apps[2].CertificateId = "other" },
		"TLS version 1.1":      func(c *nodev1.NodeConfig) { c.L4Apps[2].TlsMinimumVersion = "1.1" },
		"TLS without version":  func(c *nodev1.NodeConfig) { c.L4Apps[2].TlsMinimumVersion = "" },
		"version without cert": func(c *nodev1.NodeConfig) { c.L4Apps[0].TlsMinimumVersion = "1.2" },
	} {
		c := proto.CloneOf(c)
		mutate(c)
		if _, err := Build(c, Options{}); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: err = %v, want rejection", name, err)
		}
	}
}

// TestApplyDiffClientAddress: the client address setting travels in full
// with every diff, and canonical form sorts the new sets.
func TestApplyDiffClientAddress(t *testing.T) {
	base := &nodev1.NodeConfig{Revision: 1, Listeners: []*nodev1.Listener{{Port: 80}}}
	target := proto.CloneOf(base)
	target.Revision = 2
	target.ClientAddress = &nodev1.ClientAddress{Mode: "header", Header: "x-real-ip", TrustedCidrs: []string{"192.0.2.0/24", "10.0.0.0/8", "10.0.0.0/8"}}
	target.Sites = []*nodev1.Site{{Id: "s", Ports: []uint32{8081, 80, 80}, Tls: &nodev1.TlsOptions{RedirectExcludedDomains: []string{"b.test", "a.test"}}}}
	Canonicalize(target)
	if !slices.Equal(target.ClientAddress.TrustedCidrs, []string{"10.0.0.0/8", "192.0.2.0/24"}) || !slices.Equal(target.Sites[0].Ports, []uint32{80, 8081}) || !slices.Equal(target.Sites[0].Tls.RedirectExcludedDomains, []string{"a.test", "b.test"}) {
		t.Fatalf("canonical = %v", target)
	}
	hash, err := ContentHash(target)
	if err != nil {
		t.Fatal(err)
	}
	target.ContentHash = hash
	got, err := ApplyDiff(base, &nodev1.NodeConfigDiff{BaseRevision: 1, Revision: 2, ContentHash: hash, Listeners: target.Listeners, UpsertedSites: target.Sites, ClientAddress: target.ClientAddress})
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got.GetClientAddress(), target.ClientAddress) {
		t.Fatalf("client address = %v", got.GetClientAddress())
	}
}
