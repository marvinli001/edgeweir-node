package configir

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// l4App returns a valid TCP application on port with one origin.
func l4App(id string, port uint32) *nodev1.L4App {
	return &nodev1.L4App{
		Id: id, Protocol: nodev1.L4Protocol_L4_PROTOCOL_TCP, Port: port,
		Origins:  []*nodev1.L4Origin{{Id: "o1", Address: "origin.test", Port: 7000, Weight: 1}},
		MaxFails: 3, FailTimeoutSeconds: 30, ConnectTimeoutMs: 5000, IdleTimeoutSeconds: 600,
	}
}

// l4Config is a configuration with an HTTP listener on 80 and 8443, two IP
// lists and apps.
func l4Config(apps ...*nodev1.L4App) *nodev1.NodeConfig {
	return &nodev1.NodeConfig{
		Listeners: []*nodev1.Listener{{Port: 80}, {Port: 8443, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTPS, Http3: true}},
		IpLists: []*nodev1.IpList{
			{Id: "list-allow", Kind: "allow", Entries: []string{"198.51.100.0/24"}},
			{Id: "list-block", Kind: "block", Entries: []string{"203.0.113.7/32"}},
			{Id: "list-unused", Kind: "collection", Entries: []string{"192.0.2.0/24"}},
		},
		OriginAllowedCidrs: []string{"10.1.0.0/16"},
		L4Apps:             apps,
	}
}

func TestBuildL4Apps(t *testing.T) {
	tcp := l4App("app-a", 9000)
	tcp.AcceptProxyProtocol = true
	tcp.ProxyProtocolVersion = 2
	tcp.Origins = []*nodev1.L4Origin{
		{Id: "o1", Address: " Origin.Test ", Port: 7000, Weight: 100},
		{Id: "o2", Address: "10.1.2.3", Port: 7001, Weight: 1, Backup: true},
		{Id: "o3", Address: "127.0.0.1", Port: 7002, Weight: 5},
		{Id: "o4", Address: "2001:DB8::1", Port: 65535, Weight: 1},
	}
	tcp.AllowListIds = []string{"list-allow"}
	tcp.BlockListIds = []string{"list-block"}
	tcp.MaxConnections, tcp.NewConnectionsPerSecond = 100, 10
	// The same port for UDP is another application.
	udp := l4App("app-b", 9000)
	udp.Protocol = nodev1.L4Protocol_L4_PROTOCOL_UDP
	udp.IdleTimeoutSeconds = 30
	plain := l4App("app-c", 65535)
	plain.ProxyProtocolVersion = 1
	plain.ConnectTimeoutMs, plain.IdleTimeoutSeconds, plain.MaxFails, plain.FailTimeoutSeconds = 100, 86400, 100, 3600

	p, err := Build(l4Config(tcp, udp, plain), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.L4Apps) != 3 {
		t.Fatalf("apps = %+v", p.L4Apps)
	}
	a := p.L4Apps[0]
	want := L4App{
		ID: "app-a", Protocol: L4TCP, Port: 9000, AcceptProxyProtocol: true, ProxyProtocolVersion: 2,
		Origins: []L4Origin{
			{ID: "o1", Address: "origin.test", Port: 7000, Weight: 100},
			{ID: "o2", Address: "10.1.2.3", Port: 7001, Weight: 1, Backup: true},
			{ID: "o3", Address: "127.0.0.1", Port: 7002, Weight: 5, Forbidden: true},
			{ID: "o4", Address: "2001:db8::1", Port: 65535, Weight: 1, Forbidden: true},
		},
		MaxFails: 3, FailTimeout: 30, ConnectTimeoutMS: 5000, IdleTimeout: 600,
		AllowLists: []string{"list-allow"}, BlockLists: []string{"list-block"},
		MaxConnections: 100, NewConnectionsPerSecond: 10,
	}
	if fmt.Sprint(a) != fmt.Sprint(want) {
		t.Fatalf("app-a =\n%+v\nwant\n%+v", a, want)
	}
	if !a.Relay() || p.L4Apps[1].Relay() || p.L4Apps[2].Relay() {
		t.Fatal("only a TCP application that accepts and sends the PROXY protocol uses the relay")
	}
	if b := p.L4Apps[1]; b.Protocol != L4UDP || b.Port != 9000 || b.IdleTimeout != 30 {
		t.Fatalf("app-b = %+v", b)
	}
	if len(p.Warnings) != 2 || !strings.Contains(p.Warnings[0], `origin "o3" refused: 127.0.0.1`) || !strings.Contains(p.Warnings[1], `"o4"`) {
		t.Fatalf("warnings = %q", p.Warnings)
	}
	lists := p.L4Lists()
	if len(lists) != 2 || lists[0].GetId() != "list-allow" || lists[1].GetId() != "list-block" {
		t.Fatalf("L4Lists = %v", lists)
	}
	if !slices.Contains(SupportedFeatures, FeatureL4) {
		t.Fatal("l4-v1 is not announced")
	}
	// A configuration that requires the feature is accepted.
	c := l4Config(l4App("app-a", 9000))
	c.RequiredFeatures = []string{FeatureL4}
	if _, err := Build(c, Options{}); err != nil {
		t.Fatal(err)
	}
	// No applications: no plan entries, no lists.
	p, err = Build(l4Config(), Options{})
	if err != nil || p.L4Apps != nil || p.L4Lists() != nil {
		t.Fatalf("empty: %+v %v", p.L4Apps, err)
	}
}

func TestBuildL4AppsRejects(t *testing.T) {
	for name, mutate := range map[string]func(c *nodev1.NodeConfig){
		"id with a dot":        func(c *nodev1.NodeConfig) { c.L4Apps[0].Id = "app.a" },
		"empty id":             func(c *nodev1.NodeConfig) { c.L4Apps[0].Id = "" },
		"unsorted":             func(c *nodev1.NodeConfig) { c.L4Apps[0].Id, c.L4Apps[1].Id = "app-z", "app-b" },
		"duplicate id":         func(c *nodev1.NodeConfig) { c.L4Apps[1].Id = "app-a" },
		"protocol unspecified": func(c *nodev1.NodeConfig) { c.L4Apps[0].Protocol = nodev1.L4Protocol_L4_PROTOCOL_UNSPECIFIED },
		"protocol unknown":     func(c *nodev1.NodeConfig) { c.L4Apps[0].Protocol = 7 },
		"port 1023":            func(c *nodev1.NodeConfig) { c.L4Apps[0].Port = 1023 },
		"port 0":               func(c *nodev1.NodeConfig) { c.L4Apps[0].Port = 0 },
		"port 65536":           func(c *nodev1.NodeConfig) { c.L4Apps[0].Port = 65536 },
		"listener port":        func(c *nodev1.NodeConfig) { c.L4Apps[0].Port = 8443 },
		"HTTP/3 port for UDP":  func(c *nodev1.NodeConfig) { c.L4Apps[1].Port = 8443 },
		"skipped listener's port": func(c *nodev1.NodeConfig) {
			c.Listeners = append(c.Listeners, &nodev1.Listener{Port: 9000}, &nodev1.Listener{Port: 9000})
		},
		"same port and protocol": func(c *nodev1.NodeConfig) {
			c.L4Apps[1].Protocol, c.L4Apps[1].Port = nodev1.L4Protocol_L4_PROTOCOL_TCP, 9000
		},
		"UDP accepting PROXY":       func(c *nodev1.NodeConfig) { c.L4Apps[1].AcceptProxyProtocol = true },
		"UDP sending PROXY":         func(c *nodev1.NodeConfig) { c.L4Apps[1].ProxyProtocolVersion = 1 },
		"PROXY version 3":           func(c *nodev1.NodeConfig) { c.L4Apps[0].ProxyProtocolVersion = 3 },
		"no origin":                 func(c *nodev1.NodeConfig) { c.L4Apps[0].Origins = nil },
		"33 origins":                func(c *nodev1.NodeConfig) { c.L4Apps[0].Origins = manyL4Origins(33) },
		"origin id":                 func(c *nodev1.NodeConfig) { c.L4Apps[0].Origins[0].Id = "o|1" },
		"origin id empty":           func(c *nodev1.NodeConfig) { c.L4Apps[0].Origins[0].Id = "" },
		"origin repeated":           func(c *nodev1.NodeConfig) { c.L4Apps[0].Origins = append(c.L4Apps[0].Origins, c.L4Apps[0].Origins[0]) },
		"origin address empty":      func(c *nodev1.NodeConfig) { c.L4Apps[0].Origins[0].Address = "" },
		"origin address underscore": func(c *nodev1.NodeConfig) { c.L4Apps[0].Origins[0].Address = "bad_name.test" },
		"origin address with port":  func(c *nodev1.NodeConfig) { c.L4Apps[0].Origins[0].Address = "origin.test:80" },
		"origin address zoned":      func(c *nodev1.NodeConfig) { c.L4Apps[0].Origins[0].Address = "fe80::1%eth0" },
		"origin port 65536":         func(c *nodev1.NodeConfig) { c.L4Apps[0].Origins[0].Port = 65536 },
		"weight 0":                  func(c *nodev1.NodeConfig) { c.L4Apps[0].Origins[0].Weight = 0 },
		"weight 101":                func(c *nodev1.NodeConfig) { c.L4Apps[0].Origins[0].Weight = 101 },
		"max fails 0":               func(c *nodev1.NodeConfig) { c.L4Apps[0].MaxFails = 0 },
		"max fails 101":             func(c *nodev1.NodeConfig) { c.L4Apps[0].MaxFails = 101 },
		"fail timeout 0":            func(c *nodev1.NodeConfig) { c.L4Apps[0].FailTimeoutSeconds = 0 },
		"fail timeout 3601":         func(c *nodev1.NodeConfig) { c.L4Apps[0].FailTimeoutSeconds = 3601 },
		"connect timeout 99":        func(c *nodev1.NodeConfig) { c.L4Apps[0].ConnectTimeoutMs = 99 },
		"connect timeout 60001":     func(c *nodev1.NodeConfig) { c.L4Apps[0].ConnectTimeoutMs = 60001 },
		"idle timeout 0":            func(c *nodev1.NodeConfig) { c.L4Apps[0].IdleTimeoutSeconds = 0 },
		"idle timeout 86401":        func(c *nodev1.NodeConfig) { c.L4Apps[0].IdleTimeoutSeconds = 86401 },
		"unknown allow list":        func(c *nodev1.NodeConfig) { c.L4Apps[0].AllowListIds = []string{"list-none"} },
		"unknown block list":        func(c *nodev1.NodeConfig) { c.L4Apps[1].BlockListIds = []string{"list-none"} },
		"unsorted lists":            func(c *nodev1.NodeConfig) { c.L4Apps[0].BlockListIds = []string{"list-block", "list-allow"} },
		"repeated list":             func(c *nodev1.NodeConfig) { c.L4Apps[0].AllowListIds = []string{"list-allow", "list-allow"} },
		"too many apps": func(c *nodev1.NodeConfig) {
			c.L4Apps = nil
			for i := range MaxL4Apps + 1 {
				c.L4Apps = append(c.L4Apps, l4App(fmt.Sprintf("app-%05d", i), uint32(10000+i)))
			}
		},
	} {
		udp := l4App("app-b", 9000)
		udp.Protocol = nodev1.L4Protocol_L4_PROTOCOL_UDP
		c := l4Config(l4App("app-a", 9000), udp)
		mutate(c)
		if _, err := Build(c, Options{}); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: err = %v, want rejection", name, err)
		}
	}
	// The limits have no upper bound; zero means no limit.
	c := l4Config(l4App("app-a", 9000))
	c.L4Apps[0].MaxConnections, c.L4Apps[0].NewConnectionsPerSecond = 4294967295, 4294967295
	if _, err := Build(c, Options{}); err != nil {
		t.Fatal(err)
	}
	// 32 origins, all backups, are accepted (the backups then take traffic).
	c = l4Config(l4App("app-a", 1024))
	c.L4Apps[0].Origins = manyL4Origins(32)
	for _, o := range c.L4Apps[0].Origins {
		o.Backup = true
	}
	if _, err := Build(c, Options{}); err != nil {
		t.Fatal(err)
	}
}

func manyL4Origins(n int) []*nodev1.L4Origin {
	var out []*nodev1.L4Origin
	for i := range n {
		out = append(out, &nodev1.L4Origin{Id: fmt.Sprintf("o%02d", i), Address: "origin.test", Port: 7000, Weight: 1})
	}
	return out
}

// TestCanonicalizeL4Apps: applications by id, their origins by id and the
// list ids as sorted sets; every order of the same content hashes alike.
func TestCanonicalizeL4Apps(t *testing.T) {
	b := l4App("b", 9001)
	b.Origins = []*nodev1.L4Origin{{Id: "z", Address: "a.test", Port: 1, Weight: 1}, {Id: "a", Address: "b.test", Port: 2, Weight: 1}}
	b.AllowListIds = []string{"list-b", "list-a", "list-b"}
	b.BlockListIds = []string{"list-d", "list-c", "list-c"}
	c := &nodev1.NodeConfig{L4Apps: []*nodev1.L4App{b, l4App("a", 9000)}}
	shuffled := proto.CloneOf(c)
	shuffled.L4Apps[0].AllowListIds = []string{"list-a", "list-b"}
	shuffled.L4Apps[0].Origins[0], shuffled.L4Apps[0].Origins[1] = shuffled.L4Apps[0].Origins[1], shuffled.L4Apps[0].Origins[0]
	h1, err := ContentHash(c)
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := ContentHash(shuffled)
	if h1 != h2 {
		t.Fatal("equal application sets hash differently")
	}
	Canonicalize(c)
	got := c.L4Apps
	if got[0].GetId() != "a" || got[1].GetId() != "b" || got[1].Origins[0].GetId() != "a" ||
		!slices.Equal(got[1].AllowListIds, []string{"list-a", "list-b"}) || !slices.Equal(got[1].BlockListIds, []string{"list-c", "list-d"}) {
		t.Fatalf("canonical applications = %v", got)
	}
	// Every field counts.
	changed := proto.CloneOf(c)
	changed.L4Apps[1].Origins[1].Backup = true
	if h3, _ := ContentHash(changed); h3 == h1 {
		t.Fatal("origin backup does not change the hash")
	}
}

// TestApplyDiffReplacesL4Apps: the diff carries the applications in full.
func TestApplyDiffReplacesL4Apps(t *testing.T) {
	base := withHash(t, &nodev1.NodeConfig{Revision: 1, Listeners: []*nodev1.Listener{{Port: 80}}, Sites: []*nodev1.Site{site("a", "a.test")},
		L4Apps: []*nodev1.L4App{l4App("app-a", 9000), l4App("app-b", 9001)}})
	changed := l4App("app-b", 9001)
	changed.Origins[0].Port = 7100
	target := withHash(t, &nodev1.NodeConfig{Revision: 2, Listeners: []*nodev1.Listener{{Port: 80}}, Sites: []*nodev1.Site{site("a", "a.test")},
		L4Apps: []*nodev1.L4App{changed, l4App("app-c", 9002)}})
	d := Diff(base, target)
	if len(d.GetL4Apps()) != 2 || len(d.GetUpsertedSites()) != 0 {
		t.Fatalf("diff = %v", d)
	}
	got, err := ApplyDiff(base, d)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, target) {
		t.Fatalf("applied diff = %v, want %v", got, target)
	}
	// A diff without applications removes them all.
	empty := withHash(t, &nodev1.NodeConfig{Revision: 3, Listeners: []*nodev1.Listener{{Port: 80}}, Sites: []*nodev1.Site{site("a", "a.test")}})
	got, err = ApplyDiff(target, Diff(target, empty))
	if err != nil || len(got.GetL4Apps()) != 0 {
		t.Fatalf("removing applications: %v %v", got.GetL4Apps(), err)
	}
	// A diff whose hash does not cover the applications is refused.
	d = Diff(base, target)
	d.L4Apps = d.L4Apps[:1]
	if _, err := ApplyDiff(base, d); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("err = %v, want a hash mismatch", err)
	}
}
