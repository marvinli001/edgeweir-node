package render

import (
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

// edgePortsPlan: listeners on 80, 8081, 443 and 9443 (HTTP/3 on 9443); a
// site on 80 and 443 only, one on 8081 and 9443 with HTTP/3, one on every
// listener (no ports: a configuration without edge-ports-v1), behind
// trusted proxies that name the client in X-Forwarded-For.
func edgePortsPlan() *configir.Plan {
	tls := func(http3 bool) *configir.TLSOptions {
		return &configir.TLSOptions{MinimumVersion: "1.2", CipherProfile: "modern", HTTP2: true, HTTP3: http3}
	}
	return &configir.Plan{
		Listeners: []configir.Listener{
			{Port: 80},
			{Port: 443, TLS: true, HTTP2: true},
			{Port: 8081},
			{Port: 9443, TLS: true, HTTP2: true, HTTP3: true},
		},
		CacheZones: []configir.CacheZone{{Name: "default", MaxSizeMB: 1024, KeysZoneMB: 16, InactiveSeconds: 3600}},
		Sites: []configir.Site{
			{ID: "a", Domains: []configir.Domain{{Name: "a.test"}}, CertificateID: "c", TLS: tls(false), Ports: []uint32{80, 443}},
			{ID: "b", Domains: []configir.Domain{{Name: "b.test"}}, CertificateID: "c", TLS: tls(true), Ports: []uint32{8081, 9443}},
			{ID: "c", Domains: []configir.Domain{{Name: "c.test"}}, TLS: tls(false)},
		},
		ClientAddress: &configir.ClientAddress{Mode: configir.ClientAddressHeader, TrustedCIDRs: []string{"10.0.0.0/8", "2001:db8::/32"}, Header: "x-forwarded-for"},
	}
}

func TestRenderEdgePortsGolden(t *testing.T) {
	p := params()
	p.ListenIPv6 = true
	got, err := Render(p, edgePortsPlan())
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "edgeports.conf.golden", got)
}

// TestRenderEdgePortsServers: one default server per listener; a site's
// own server only on the ports it is bound to (HTTPS ones with its
// certificate), and QUIC on the HTTPS port whose sites use HTTP/3.
func TestRenderEdgePortsServers(t *testing.T) {
	got, err := Render(params(), edgePortsPlan())
	if err != nil {
		t.Fatal(err)
	}
	conf := string(got)
	for _, want := range []string{
		"listen 80 default_server;", "listen 8081 default_server;",
		"listen 443 default_server ssl;", "listen 9443 default_server ssl;",
		"listen 9443 quic reuseport default_server;",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(conf, "listen 443 quic") {
		t.Error("QUIC on 443, where no site uses HTTP/3")
	}
	servers := map[string][]string{} // server_name -> listen lines
	for _, block := range strings.Split(conf, "    server {")[1:] {
		name := ""
		var listens []string
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			if v, ok := strings.CutPrefix(line, "server_name "); ok {
				name = strings.TrimSuffix(v, ";")
			}
			if v, ok := strings.CutPrefix(line, "listen "); ok && !strings.HasPrefix(v, "unix:") {
				listens = append(listens, strings.TrimSuffix(v, ";"))
			}
		}
		if name != "" && name != "_" {
			servers[name] = append(servers[name], strings.Join(listens, " | "))
		}
	}
	want := map[string][]string{
		"a.test": {"80", "443 ssl"},
		"b.test": {"8081", "9443 ssl | 9443 quic"},
		"c.test": {"80", "8081"},
	}
	for name, listens := range want {
		if strings.Join(servers[name], " / ") != strings.Join(listens, " / ") {
			t.Errorf("%s: servers %q, want %q", name, servers[name], listens)
		}
	}
}

// TestRenderClientAddress: the realip directives of each mode on the
// public listeners (never on the local ones), and the X-Forwarded-For the
// edge sends: the received header and the TCP peer.
func TestRenderClientAddress(t *testing.T) {
	render := func(ca *configir.ClientAddress, proxy bool) string {
		plan := &configir.Plan{
			Listeners:     []configir.Listener{{Port: 80, ProxyProtocol: proxy}, {Port: 8081, ProxyProtocol: proxy}},
			CacheZones:    []configir.CacheZone{{Name: "z", MaxSizeMB: 1, KeysZoneMB: 1, InactiveSeconds: 60}},
			ClientAddress: ca,
		}
		got, err := Render(params(), plan)
		if err != nil {
			t.Fatal(err)
		}
		return string(got)
	}
	header := render(&configir.ClientAddress{Mode: configir.ClientAddressHeader, TrustedCIDRs: []string{"192.0.2.0/24"}, Header: "cf-connecting-ip"}, false)
	for _, port := range []string{"80", "8081"} {
		s := section(t, header, "listen "+port+" default_server;", "location /")
		for _, want := range []string{"set_real_ip_from 192.0.2.0/24;", "real_ip_header cf-connecting-ip;", "real_ip_recursive on;"} {
			if !strings.Contains(s, want) {
				t.Errorf("header mode, port %s lacks %q", port, want)
			}
		}
		if strings.Contains(s, "0.0.0.0/0") {
			t.Errorf("header mode, port %s trusts every address", port)
		}
	}
	local := section(t, header, "listen unix:/run/edgeweir-node/edge.sock default_server;", "location /")
	if strings.Contains(local, "cf-connecting-ip") {
		t.Error("the local edge socket reads the trusted proxies' header")
	}
	if !strings.Contains(header, "proxy_set_header X-Forwarded-For $edgeweir_forwarded_for;") || !strings.Contains(header, `default "$http_x_forwarded_for, $edgeweir_peer";`) {
		t.Error("header mode: X-Forwarded-For is not the received header and the TCP peer")
	}
	xff := render(&configir.ClientAddress{Mode: configir.ClientAddressHeader, TrustedCIDRs: []string{"192.0.2.0/24"}, Header: "x-forwarded-for"}, false)
	if !strings.Contains(xff, "real_ip_header X-Forwarded-For;") {
		t.Error("x-forwarded-for is not written as nginx's X-Forwarded-For (every line of the header)")
	}
	xri := render(&configir.ClientAddress{Mode: configir.ClientAddressHeader, TrustedCIDRs: []string{"192.0.2.0/24"}, Header: "x-real-ip"}, false)
	if !strings.Contains(xri, "real_ip_header X-Real-IP;") {
		t.Error("x-real-ip is not written as nginx's X-Real-IP")
	}

	proxy := render(&configir.ClientAddress{Mode: configir.ClientAddressProxyProtocol}, true)
	for _, port := range []string{"80", "8081"} {
		s := section(t, proxy, "listen "+port+" default_server proxy_protocol;", "location /")
		if !strings.Contains(s, "real_ip_header proxy_protocol;") {
			t.Errorf("PROXY mode, port %s lacks the PROXY protocol's address", port)
		}
	}
	if !strings.Contains(proxy, "X-Forwarded-For $edgeweir_forwarded_for;") {
		t.Error("PROXY mode: X-Forwarded-For does not end with the TCP peer")
	}

	drop := render(&configir.ClientAddress{Mode: configir.ClientAddressDirect, DropForwardedFor: true}, false)
	if !strings.Contains(drop, "proxy_set_header X-Forwarded-For $remote_addr;") || !strings.Contains(drop, "grpc_set_header X-Forwarded-For $remote_addr;") || strings.Contains(drop, "real_ip_recursive") || strings.Contains(drop, "$edgeweir_forwarded_for") {
		t.Error("direct mode without the client's X-Forwarded-For")
	}
	direct := render(nil, false)
	if !strings.Contains(direct, "X-Forwarded-For $proxy_add_x_forwarded_for;") || strings.Contains(direct, "$edgeweir_forwarded_for") {
		t.Error("without a setting the edge must keep nginx's $proxy_add_x_forwarded_for")
	}

	for name, ca := range map[string]*configir.ClientAddress{
		"bad header":  {Mode: configir.ClientAddressHeader, TrustedCIDRs: []string{"192.0.2.0/24"}, Header: "x-a; evil"},
		"bad CIDR":    {Mode: configir.ClientAddressHeader, TrustedCIDRs: []string{"192.0.2.1/24"}, Header: "x-a"},
		"no CIDR":     {Mode: configir.ClientAddressHeader, Header: "x-a"},
		"bad mode":    {Mode: "magic"},
		"injected ip": {Mode: configir.ClientAddressHeader, TrustedCIDRs: []string{"0.0.0.0/0;\nevil"}, Header: "x-a"},
	} {
		plan := &configir.Plan{Listeners: []configir.Listener{{Port: 80}}, CacheZones: []configir.CacheZone{{Name: "z", MaxSizeMB: 1, KeysZoneMB: 1, InactiveSeconds: 60}}, ClientAddress: ca}
		if _, err := Render(params(), plan); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
}

// TestRenderWorkerConnectionsCountListeningSockets: nginx counts every
// listening socket (reuseport ones once per worker) against
// worker_connections; Render adds them to the configured connections.
func TestRenderWorkerConnectionsCountListeningSockets(t *testing.T) {
	count := func(plan *configir.Plan, cpus int) string {
		p := params()
		p.CPUs = cpus
		got, err := Render(p, plan)
		if err != nil {
			t.Fatal(err)
		}
		return section(t, string(got), "worker_connections", ";")
	}
	base := configir.Bootstrap(80)
	if got := count(base, 2); got != "worker_connections 4107;" {
		t.Errorf("bootstrap: %s", got)
	}
	tcp := configir.Bootstrap(80)
	tcp.L4Apps = []configir.L4App{l4App("range", configir.L4TCP, 10000)}
	tcp.L4Apps[0].PortEnd = 10999
	udp := configir.Bootstrap(80)
	udp.L4Apps = []configir.L4App{l4App("range", configir.L4UDP, 10000)}
	udp.L4Apps[0].PortEnd = 10999
	// TCP ranges: one socket per port; UDP: one per port and worker.
	if got := count(tcp, 4); got != "worker_connections 5107;" {
		t.Errorf("TCP range: %s", got)
	}
	if got := count(udp, 4); got != "worker_connections 8107;" {
		t.Errorf("UDP range: %s", got)
	}
}
