package configir

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/extension"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"google.golang.org/protobuf/proto"
)

func nodeExtensionConfig() *nodev1.NodeConfig {
	e := validExtension()
	e.Scope, e.LuaApi = extension.ScopeNode, 2
	e.Listeners = []*nodev1.ExtensionListener{{
		Name: "http", Port: 9100, Bind: "127.0.0.1", Allow: []string{"127.0.0.1"}, Methods: []string{"HEAD", "GET"},
	}}
	return &nodev1.NodeConfig{Extensions: []*nodev1.Extension{e}, RequiredFeatures: []string{FeatureExtensions, FeatureExtensionsV2, FeatureExtensionsNode}}
}

func TestExtensionBindingsNormalize(t *testing.T) {
	c := nodeExtensionConfig()
	binding := c.Extensions[0].Listeners[0]
	binding.Bind = "2001:0DB8:0::0001"
	binding.Allow = []string{"::ffff:1:c000:201", "10.2.3.4/8", "127.0.0.1", "10.0.0.0/8", "::1"}
	before, err := proto.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	exts, err := buildExtensions(c)
	if err != nil {
		t.Fatal(err)
	}
	got := exts[0].Listeners[0]
	if got.Bind != "2001:db8::1" || got.MaxBody != 4096 || !slices.Equal(got.Methods, []string{"GET", "HEAD"}) ||
		!slices.Equal(got.Allow, []string{"10.0.0.0/8", "127.0.0.1/32", "::1/128", "::ffff:1:c000:201/128"}) {
		t.Fatalf("normalized binding %+v", got)
	}
	after, err := proto.Marshal(c)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("normalization changed the wire source: %v", err)
	}
	zero := uint32(0)
	binding.MaxBody = &zero
	exts, err = buildExtensions(c)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(exts[0])
	if err != nil || !bytes.Contains(data, []byte(`"max_body":0`)) || string(exts[0].Config) != `{"greeting":"hi"}` {
		t.Fatalf("zero body/configuration: %s, %v", data, err)
	}
	c.Extensions[0].Listeners = nil
	exts, err = buildExtensions(c)
	if err != nil || len(exts[0].Listeners) != 0 {
		t.Fatalf("omitted binding must stay closed: %+v, %v", exts, err)
	}
	c = nodeExtensionConfig()
	binding = c.Extensions[0].Listeners[0]
	binding.Port, binding.Bind = 65535, "::ffff:1:c000:201"
	body := uint32(65536)
	binding.MaxBody = &body
	binding.Allow = make([]string, 64)
	for i := range binding.Allow {
		binding.Allow[i] = "127.0.0.1"
	}
	other := proto.Clone(binding).(*nodev1.ExtensionListener)
	other.Name, other.Port, other.Bind = "alpha", 1024, "::"
	c.Extensions[0].Listeners = append(c.Extensions[0].Listeners, other)
	exts, err = buildExtensions(c)
	if err != nil {
		t.Fatal(err)
	}
	if got := exts[0].Listeners; len(got) != 2 || got[0].Name != "alpha" || got[1].MaxBody != 65536 || len(got[1].Allow) != 1 || got[1].Bind != "::ffff:1:c000:201" {
		t.Fatalf("valid binding limits: %+v", got)
	}
}

func TestExtensionBindingsRejected(t *testing.T) {
	for name, change := range map[string]func(*nodev1.NodeConfig){
		"scope":        func(c *nodev1.NodeConfig) { c.Extensions[0].Scope = "sites" },
		"API 1":        func(c *nodev1.NodeConfig) { c.Extensions[0].LuaApi = 1 },
		"API 3":        func(c *nodev1.NodeConfig) { c.Extensions[0].LuaApi = 3 },
		"site binding": func(c *nodev1.NodeConfig) { c.Extensions[0].Scope = "" },
		"disabled":     func(c *nodev1.NodeConfig) { c.Extensions[0].Enabled = false },
		"kill switch":  func(c *nodev1.NodeConfig) { c.ExtensionsDisabled = true },
		"nil binding":  func(c *nodev1.NodeConfig) { c.Extensions[0].Listeners = []*nodev1.ExtensionListener{nil} },
		"same name": func(c *nodev1.NodeConfig) {
			other := proto.Clone(c.Extensions[0].Listeners[0]).(*nodev1.ExtensionListener)
			other.Port++
			c.Extensions[0].Listeners = append(c.Extensions[0].Listeners, other)
		},
		"same port": func(c *nodev1.NodeConfig) {
			other := proto.Clone(c.Extensions[0].Listeners[0]).(*nodev1.ExtensionListener)
			other.Name = "other"
			c.Extensions[0].Listeners = append(c.Extensions[0].Listeners, other)
		},
		"too many": func(c *nodev1.NodeConfig) {
			for i, name := range []string{"other", "third"} {
				other := proto.Clone(c.Extensions[0].Listeners[0]).(*nodev1.ExtensionListener)
				other.Name, other.Port = name, uint32(9101+i)
				c.Extensions[0].Listeners = append(c.Extensions[0].Listeners, other)
			}
		},
		"other extension port": func(c *nodev1.NodeConfig) {
			other := proto.Clone(c.Extensions[0]).(*nodev1.Extension)
			other.Id = "other-ext"
			c.Extensions = append(c.Extensions, other)
		},
		"edge port": func(c *nodev1.NodeConfig) { c.Listeners = []*nodev1.Listener{{Port: 9100}} },
		"layer 4 range": func(c *nodev1.NodeConfig) {
			c.L4Apps = []*nodev1.L4App{{Port: 9099, PortEnd: 9101}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := nodeExtensionConfig()
			change(c)
			if _, err := buildExtensions(c); !errors.Is(err, ErrRejected) {
				t.Fatalf("invalid binding accepted: %v", err)
			}
		})
	}
	for _, feature := range []string{FeatureExtensions, FeatureExtensionsV2, FeatureExtensionsNode} {
		c := nodeExtensionConfig()
		c.RequiredFeatures = slices.DeleteFunc(c.RequiredFeatures, func(value string) bool { return value == feature })
		if _, err := buildExtensions(c); !errors.Is(err, ErrRejected) {
			t.Errorf("missing %s accepted: %v", feature, err)
		}
	}
	for name, change := range map[string]func(*nodev1.ExtensionListener){
		"name":             func(l *nodev1.ExtensionListener) { l.Name = "Bad" },
		"low port":         func(l *nodev1.ExtensionListener) { l.Port = 1023 },
		"high port":        func(l *nodev1.ExtensionListener) { l.Port = 65536 },
		"reserved":         func(l *nodev1.ExtensionListener) { l.Port = 8443 },
		"methods":          func(l *nodev1.ExtensionListener) { l.Methods = []string{"PUT"} },
		"no method":        func(l *nodev1.ExtensionListener) { l.Methods = nil },
		"duplicate method": func(l *nodev1.ExtensionListener) { l.Methods = []string{"GET", "GET"} },
		"body": func(l *nodev1.ExtensionListener) {
			body := uint32(65537)
			l.MaxBody = &body
		},
		"unknown field": func(l *nodev1.ExtensionListener) { l.ProtoReflect().SetUnknown([]byte{0x38, 0x01}) },
		"empty ACL":     func(l *nodev1.ExtensionListener) { l.Allow = nil },
		"long ACL": func(l *nodev1.ExtensionListener) {
			l.Allow = make([]string, 65)
			for i := range l.Allow {
				l.Allow[i] = "127.0.0.1"
			}
		},
	} {
		c := nodeExtensionConfig()
		change(c.Extensions[0].Listeners[0])
		if _, err := buildExtensions(c); !errors.Is(err, ErrRejected) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	for _, address := range []string{"", "localhost", "[::1]", "fe80::1%lo", "::ffff:192.0.2.1", "::ffff:c000:201"} {
		c := nodeExtensionConfig()
		c.Extensions[0].Listeners[0].Bind = address
		if _, err := buildExtensions(c); !errors.Is(err, ErrRejected) {
			t.Errorf("bind %q accepted: %v", address, err)
		}
	}
	for _, address := range []string{"", "localhost", "[::1]", "fe80::1%lo", "::ffff:192.0.2.1", "::ffff:c000:201/80", "10.0.0.1/33"} {
		c := nodeExtensionConfig()
		c.Extensions[0].Listeners[0].Allow = []string{address}
		if _, err := buildExtensions(c); !errors.Is(err, ErrRejected) {
			t.Errorf("ACL %q accepted: %v", address, err)
		}
	}
}

func TestExtensionNodeRuntimeCapability(t *testing.T) {
	c := nodeExtensionConfig()
	if _, err := Build(c, Options{ExtraFeatures: []string{FeatureExtensions, FeatureExtensionsV2}}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), FeatureExtensionsNode) {
		t.Fatalf("node scope accepted without its runtime capability: %v", err)
	}
	if plan, err := Build(c, Options{ExtraFeatures: slices.Clone(c.RequiredFeatures)}); err != nil || len(plan.Extensions) != 1 || len(plan.Sites) != 0 {
		t.Fatalf("zero-site node plan: %+v, %v", plan, err)
	}
	if _, err := Build(c, Options{DefaultPort: 9100, ExtraFeatures: slices.Clone(c.RequiredFeatures)}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "port") {
		t.Fatalf("effective default port conflict accepted: %v", err)
	}
	c.TieredCache = &nodev1.TieredCache{Port: 9100}
	if _, err := Build(c, Options{ExtraFeatures: slices.Clone(c.RequiredFeatures)}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "port") {
		t.Fatalf("tier port conflict accepted: %v", err)
	}
	exts, err := buildExtensions(c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildSiteExtensions(&nodev1.Site{Extensions: []*nodev1.SiteExtension{{Id: exts[0].ID, ConfigJson: "{}"}}}, exts); !errors.Is(err, ErrRejected) {
		t.Fatalf("node extension accepted on a site: %v", err)
	}
}

func TestLegacyExtensionEncoding(t *testing.T) {
	c := &nodev1.NodeConfig{Extensions: []*nodev1.Extension{validExtension()}}
	hash, err := ContentHash(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Extensions[0].Listeners = []*nodev1.ExtensionListener{}
	if got, err := ContentHash(c); err != nil || got != hash {
		t.Fatalf("empty bindings changed legacy hash: %s, %v", got, err)
	}
	for _, scope := range []string{"", extension.ScopeSite} {
		c.Extensions[0].Scope = scope
		exts, err := buildExtensions(c)
		if err != nil {
			t.Fatal(err)
		}
		got, err := json.Marshal(exts[0])
		want := `{"id":"hello-header","version":"1.0.0","publisher":"example.org","sha256":"` + strings.Repeat("ab", 32) + `","enabled":true,"failure_mode":"open","config":{"greeting":"hi"},"state":""}`
		if err != nil || string(got) != want {
			t.Fatalf("site IR changed: %s, %v", got, err)
		}
	}
}

func TestExtensionSignedDeclarations(t *testing.T) {
	m, err := extension.ParseManifest([]byte(`{"format":"edgeweir-node-extension-v1","id":"hello-header","version":"1.0.0","publisher":"example.org","name":{"en":"Status"},"requires":{"lua_api":2},"scope":"node","hooks":["listen"],"listeners":[{"name":"http","default_port":9101,"methods":["HEAD","GET"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	model := func() Extension {
		t.Helper()
		exts, err := buildExtensions(nodeExtensionConfig())
		if err != nil {
			t.Fatal(err)
		}
		return exts[0]
	}
	e := model()
	if err := e.CheckManifest(m); err != nil {
		t.Fatal(err)
	}
	e.Listeners = nil
	if err := e.CheckManifest(m); err != nil {
		t.Fatalf("unbound declaration is valid: %v", err)
	}
	for name, change := range map[string]func(*Extension){
		"scope":         func(e *Extension) { e.Scope = "" },
		"Lua API":       func(e *Extension) { e.LuaAPI = 1 },
		"unknown name":  func(e *Extension) { e.Listeners[0].Name = "other" },
		"more methods":  func(e *Extension) { e.Listeners[0].Methods = []string{"GET", "HEAD", "POST"} },
		"fewer methods": func(e *Extension) { e.Listeners[0].Methods = []string{"GET"} },
		"larger body":   func(e *Extension) { e.Listeners[0].MaxBody = 65536 },
		"smaller body":  func(e *Extension) { e.Listeners[0].MaxBody = 0 },
	} {
		e := model()
		change(&e)
		if err := e.CheckManifest(m); err == nil {
			t.Errorf("%s differs but was accepted", name)
		}
	}
	zero := 0
	m.Listeners[0].MaxBody = &zero
	e = model()
	if err := e.CheckManifest(m); err == nil {
		t.Fatal("default wire body accepted for signed zero")
	}
	e.Listeners[0].MaxBody = 0
	if err := e.CheckManifest(m); err != nil {
		t.Fatalf("explicit zero differs: %v", err)
	}
	m.Scope = extension.ScopeSite
	if err := e.CheckManifest(m); err == nil {
		t.Fatal("node wire accepted for signed site scope")
	}
}
