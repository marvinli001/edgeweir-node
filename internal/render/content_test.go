package render

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func contentSite(id, domain string) *nodev1.Site {
	return &nodev1.Site{Id: id, Enabled: true, Domains: []*nodev1.Domain{{Name: domain}},
		OriginPool: &nodev1.OriginPool{Id: "p-" + id, Origins: []*nodev1.Origin{{Id: "o1", Address: "origin.test", Port: 80, Weight: 1}}}}
}

func renderConfig(t *testing.T, c *nodev1.NodeConfig, opts configir.Options) string {
	t.Helper()
	if len(c.Listeners) == 0 {
		c.Listeners = []*nodev1.Listener{{Port: 80, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTP}}
	}
	plan, err := configir.Build(c, opts)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render(params(), plan)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestRenderClientMaxBodySize: the http block admits the largest body any
// site or rule accepts (0 when one accepts any), the former 100m without
// limits; the sites check their own limits in Lua.
func TestRenderClientMaxBodySize(t *testing.T) {
	small, large := contentSite("a", "a.test"), contentSite("b", "b.test")
	for _, tc := range []struct {
		name  string
		edit  func()
		sites []*nodev1.Site
		want  string
	}{
		{"defaults", func() {}, []*nodev1.Site{small}, "client_max_body_size 100m;"},
		{"no sites", func() {}, nil, "client_max_body_size 100m;"},
		{"largest", func() {
			small.RequestBodyLimit, large.RequestBodyLimit = proto.Uint64(1<<20), proto.Uint64(2<<30)
		}, []*nodev1.Site{small, large}, "client_max_body_size 2147483648;"},
		{"unlimited", func() { large.RequestBodyLimit = proto.Uint64(0) }, []*nodev1.Site{small, large}, "client_max_body_size 0;"},
	} {
		tc.edit()
		conf := renderConfig(t, &nodev1.NodeConfig{Sites: tc.sites}, configir.Options{})
		if got := strings.Count(conf, "client_max_body_size "); !strings.Contains(conf, "    "+tc.want) || got < 1 {
			t.Errorf("%s: nginx.conf lacks %q", tc.name, tc.want)
		}
	}
}

// TestRenderContentDirectives pins the static parts of the proto v0.24.0
// settings: X-Cache through a variable, the hidden Set-Cookie carrier in
// every caching location, the agent socket, gzip_comp_level and the
// per-node cache zone size.
func TestRenderContentDirectives(t *testing.T) {
	s := contentSite("a", "a.test")
	s.Tls = &nodev1.TlsOptions{MinimumVersion: "1.2", CipherProfile: "modern", Gzip: true, GzipLevel: 6}
	c := &nodev1.NodeConfig{
		Sites: []*nodev1.Site{s},
		CacheZones: []*nodev1.CacheZone{{Name: "default", MaxSizeMb: 10240, KeysZoneMb: 64, InactiveSeconds: 604800,
			NodeSizes: []*nodev1.CacheZoneNodeSize{{NodeId: "node-1", MaxSizeMb: 2048, KeysZoneMb: 16}}}},
	}
	conf := renderConfig(t, c, configir.Options{NodeID: "node-1"})
	for _, want := range []string{
		"map $edgeweir_x_cache_off $edgeweir_x_cache {",
		`agent_socket = "/run/edgeweir-node/agent.sock",`,
		"gzip_comp_level 6;",
		"keys_zone=default:16m max_size=2048m inactive=604800s",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("nginx.conf lacks %q", want)
		}
	}
	if strings.Contains(conf, "add_header X-Cache $upstream_cache_status") {
		t.Error("X-Cache must come from $edgeweir_x_cache")
	}
	// Every location that caches hides the carrier of cached cookies.
	if caching, hidden := strings.Count(conf, "proxy_cache $edgeweir_cache_zone;"), strings.Count(conf, "proxy_hide_header X-Edgeweir-Set-Cookie;"); caching == 0 || caching != hidden {
		t.Errorf("%d caching locations, %d hide X-Edgeweir-Set-Cookie", caching, hidden)
	}
	if n := strings.Count(conf, "set $edgeweir_x_cache_off \"\";"); n == 0 {
		t.Error("location / must reset $edgeweir_x_cache_off")
	}
	// Another node keeps the cluster's size.
	if conf := renderConfig(t, c, configir.Options{NodeID: "node-2"}); !strings.Contains(conf, "keys_zone=default:64m max_size=10240m") {
		t.Error("node-2 must use the zone's own size")
	}
}
