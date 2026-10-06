package render

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

func l4App(id, protocol string, port uint32) configir.L4App {
	return configir.L4App{
		ID: id, Protocol: protocol, Port: port,
		Origins:  []configir.L4Origin{{ID: "o1", Address: "origin.test", Port: 7000, Weight: 1}},
		MaxFails: 3, FailTimeout: 30, ConnectTimeoutMS: 5000, IdleTimeout: 600,
	}
}

// l4Plan has one application of every kind of stream server.
func l4Plan() *configir.Plan {
	plan := configir.Bootstrap(80)
	pp1, pp2 := l4App("tcp-v1", configir.L4TCP, 9001), l4App("tcp-v2", configir.L4TCP, 9002)
	pp1.ProxyProtocolVersion, pp2.ProxyProtocolVersion = 1, 2
	accept := l4App("tcp-accept", configir.L4TCP, 9003)
	accept.AcceptProxyProtocol = true
	relay1, relay2 := l4App("tcp-relay-v1", configir.L4TCP, 9004), l4App("tcp-relay-v2", configir.L4TCP, 9005)
	relay1.AcceptProxyProtocol, relay1.ProxyProtocolVersion = true, 1
	relay2.AcceptProxyProtocol, relay2.ProxyProtocolVersion = true, 2
	// l4-v2: port ranges (TCP: one socket per port; UDP: reuseport) and
	// TLS termination, also after a PROXY protocol header.
	tcpRange, udpRange := l4App("tcp-range", configir.L4TCP, 9100), l4App("udp-range", configir.L4UDP, 9100)
	tcpRange.PortEnd, udpRange.PortEnd = 9109, 9104
	tcpRange.Origins[0].Port, udpRange.Origins[0].Port = 0, 0
	tlsApp, tlsAccept := l4App("tcp-tls", configir.L4TCP, 9200), l4App("tcp-tls-accept", configir.L4TCP, 9201)
	tlsApp.CertificateID, tlsApp.TLSMinimumVersion = "c", "1.3"
	tlsAccept.CertificateID, tlsAccept.TLSMinimumVersion, tlsAccept.AcceptProxyProtocol = "c", "1.2", true
	plan.L4Apps = []configir.L4App{l4App("tcp-plain", configir.L4TCP, 9000), pp1, pp2, accept, relay1, relay2, l4App("udp", configir.L4UDP, 9000), tcpRange, udpRange, tlsApp, tlsAccept}
	return plan
}

func TestRenderL4Golden(t *testing.T) {
	p := params()
	p.ListenIPv6 = true
	p.ResolverIPv6 = true
	p.WorkerShutdownTimeout = 90 * time.Second
	got, err := Render(p, l4Plan())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte("origin.test")) || bytes.Contains(got, []byte("tcp-plain")) {
		t.Fatal("hot application data leaked into nginx.conf")
	}
	golden(t, "l4.conf.golden", got)
}

// TestRenderL4HotFields: origins, passive health, timeouts, IP lists,
// limits and which application owns a port never change nginx.conf; the
// port, the protocol and the PROXY protocol settings do.
func TestRenderL4HotFields(t *testing.T) {
	base, err := Render(params(), l4Plan())
	if err != nil {
		t.Fatal(err)
	}
	hot := l4Plan()
	for i := range hot.L4Apps {
		a := &hot.L4Apps[i]
		a.ID += "-renamed"
		a.Origins = []configir.L4Origin{{ID: "x", Address: "10.0.0.9", Port: 1, Weight: 100, Backup: true, Forbidden: true}, {ID: "y", Address: "b.test", Port: 2, Weight: 2}}
		a.MaxFails, a.FailTimeout, a.ConnectTimeoutMS, a.IdleTimeout = 100, 3600, 100, 86400
		a.AllowLists, a.BlockLists = []string{"l1"}, []string{"l2", "l3"}
		a.MaxConnections, a.NewConnectionsPerSecond = 10, 5
	}
	hot.Revision, hot.ContentHash = 9, "x"
	got, err := Render(params(), hot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, base) {
		t.Fatal("hot layer-4 fields changed nginx.conf")
	}
	for name, mutate := range map[string]func(p *configir.Plan){
		"port":               func(p *configir.Plan) { p.L4Apps[0].Port = 9300 },
		"protocol":           func(p *configir.Plan) { p.L4Apps[1].Protocol, p.L4Apps[1].ProxyProtocolVersion = configir.L4UDP, 0 },
		"accept PROXY":       func(p *configir.Plan) { p.L4Apps[0].AcceptProxyProtocol = true },
		"PROXY version":      func(p *configir.Plan) { p.L4Apps[1].ProxyProtocolVersion = 2 },
		"new application":    func(p *configir.Plan) { p.L4Apps = append(p.L4Apps, l4App("new", configir.L4UDP, 9300)) },
		"range":              func(p *configir.Plan) { p.L4Apps[6].PortEnd = 9050 },
		"range end":          func(p *configir.Plan) { p.L4Apps[7].PortEnd = 9110 },
		"TLS":                func(p *configir.Plan) { p.L4Apps[0].CertificateID, p.L4Apps[0].TLSMinimumVersion = "c", "1.2" },
		"removed":            func(p *configir.Plan) { p.L4Apps = p.L4Apps[1:] },
		"last one removed":   func(p *configir.Plan) { p.L4Apps = nil },
		"relay to non-PROXY": func(p *configir.Plan) { p.L4Apps[4].ProxyProtocolVersion = 0 },
	} {
		plan := l4Plan()
		mutate(plan)
		got, err := Render(params(), plan)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if bytes.Equal(got, base) {
			t.Errorf("%s did not change nginx.conf", name)
		}
	}
	// Without applications there is no stream block at all.
	got, err = Render(params(), configir.Bootstrap(80))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte("stream {")) || bytes.Contains(got, []byte("l4_socket")) || bytes.Contains(got, []byte("worker_shutdown_timeout")) {
		t.Fatal("a configuration without layer-4 applications renders stream settings")
	}
}

func TestRenderL4RejectsUnsafeInput(t *testing.T) {
	for name, mutate := range map[string]func(p *configir.Plan){
		"protocol":      func(p *configir.Plan) { p.L4Apps[0].Protocol = "sctp" },
		"protocol case": func(p *configir.Plan) { p.L4Apps[0].Protocol = "TCP" },
		"port 80":       func(p *configir.Plan) { p.L4Apps[0].Port = 80 },
		"port 70000":    func(p *configir.Plan) { p.L4Apps[0].Port = 70000 },
		"listener port": func(p *configir.Plan) { p.Listeners = append(p.Listeners, configir.Listener{Port: 9000}) },
		"duplicate":     func(p *configir.Plan) { p.L4Apps[1].Port, p.L4Apps[1].ProxyProtocolVersion = 9000, 0 },
		"PROXY v3":      func(p *configir.Plan) { p.L4Apps[1].ProxyProtocolVersion = 3 },
		"UDP PROXY":     func(p *configir.Plan) { p.L4Apps[6].ProxyProtocolVersion = 1 },
		"UDP accept":    func(p *configir.Plan) { p.L4Apps[6].AcceptProxyProtocol = true },
	} {
		plan := l4Plan()
		mutate(plan)
		if _, err := Render(params(), plan); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
	for name, mutate := range map[string]func(p *Params){
		"socket":           func(p *Params) { p.L4Socket = "/run/l4 sock" },
		"relative socket":  func(p *Params) { p.L4Socket = "l4.sock" },
		"dict size":        func(p *Params) { p.L4DictMB = 70000 },
		"negative timeout": func(p *Params) { p.WorkerShutdownTimeout = -time.Second },
	} {
		p := params()
		mutate(&p)
		if _, err := Render(p, l4Plan()); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
}

func TestRenderWorkerShutdownTimeout(t *testing.T) {
	for timeout, want := range map[time.Duration]string{
		time.Second:             "worker_shutdown_timeout 1000ms;",
		1500 * time.Microsecond: "worker_shutdown_timeout 2ms;",
		time.Hour:               "worker_shutdown_timeout 3600000ms;",
	} {
		p := params()
		p.WorkerShutdownTimeout = timeout
		got, err := Render(p, configir.Bootstrap(80))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(got), "\n"+want+"\n") {
			t.Errorf("%s: no %q in\n%s", timeout, want, got[:400])
		}
	}
}
