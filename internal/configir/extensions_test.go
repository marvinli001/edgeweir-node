package configir

import (
	"errors"
	"strings"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

var withExtensions = Options{ExtraFeatures: []string{FeatureExtensions}}

func validExtension() *nodev1.Extension {
	return &nodev1.Extension{
		Id: "hello-header", Version: "1.0.0", Publisher: "example.org", Sha256: strings.Repeat("ab", 32), Size: 2048,
		Signature: "h.p.s", PublicKey: `{"kty":"OKP","crv":"Ed25519","x":"x"}`, Enabled: true, FailureMode: "open",
		ConfigJson:  `{"greeting": "hi"}`,
		SharedDicts: []*nodev1.ExtensionSharedDict{{Name: "state", SizeKb: 64}},
	}
}

func extensionConfig(t *testing.T, change func(c *nodev1.NodeConfig, e *nodev1.Extension, a *nodev1.Site)) *nodev1.NodeConfig {
	return g16Config(t, func(c *nodev1.NodeConfig, a *nodev1.Site) {
		e := validExtension()
		c.Extensions = []*nodev1.Extension{e}
		c.RequiredFeatures = append(c.RequiredFeatures, FeatureExtensions)
		a.Extensions = []*nodev1.SiteExtension{{Id: e.Id, ConfigJson: `{"header":"X-Hello"}`}}
		if change != nil {
			change(c, e, a)
		}
	})
}

func TestExtensionsBuild(t *testing.T) {
	p, err := Build(extensionConfig(t, func(c *nodev1.NodeConfig, _ *nodev1.Extension, _ *nodev1.Site) {
		c.ExtensionsDisabled = true
	}), withExtensions)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Extensions) != 1 || !p.ExtensionsDisabled || string(p.Extensions[0].Config) != `{"greeting":"hi"}` {
		t.Fatalf("extensions %+v disabled %v", p.Extensions, p.ExtensionsDisabled)
	}
	if d := p.Extensions[0].SharedDicts[0].DictName("hello-header"); d != "ewx_68656c6c6f2d686561646572_state" {
		t.Fatalf("dict name %s", d)
	}
	site := p.Sites[0]
	for _, s := range p.Sites {
		if s.ID == "a" {
			site = s
		}
	}
	if len(site.Extensions) != 1 || string(site.Extensions[0].Config) != `{"header":"X-Hello"}` {
		t.Fatalf("site extensions %+v", site.Extensions)
	}
	if _, err := Build(extensionConfig(t, nil), Options{}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), FeatureExtensions) {
		t.Fatalf("a node without extensions accepted them: %v", err)
	}
}

func TestExtensionsRejected(t *testing.T) {
	cases := map[string]func(c *nodev1.NodeConfig, e *nodev1.Extension, a *nodev1.Site){
		"id":           func(_ *nodev1.NodeConfig, e *nodev1.Extension, _ *nodev1.Site) { e.Id = "Hello" },
		"digest":       func(_ *nodev1.NodeConfig, e *nodev1.Extension, _ *nodev1.Site) { e.Sha256 = "abc" },
		"size":         func(_ *nodev1.NodeConfig, e *nodev1.Extension, _ *nodev1.Site) { e.Size = 5 << 20 },
		"failure mode": func(_ *nodev1.NodeConfig, e *nodev1.Extension, _ *nodev1.Site) { e.FailureMode = "maybe" },
		"signature":    func(_ *nodev1.NodeConfig, e *nodev1.Extension, _ *nodev1.Site) { e.Signature = "" },
		"config":       func(_ *nodev1.NodeConfig, e *nodev1.Extension, _ *nodev1.Site) { e.ConfigJson = `[1]` },
		"dict name":    func(_ *nodev1.NodeConfig, e *nodev1.Extension, _ *nodev1.Site) { e.SharedDicts[0].Name = "Bad" },
		"dict size": func(_ *nodev1.NodeConfig, e *nodev1.Extension, _ *nodev1.Site) {
			e.SharedDicts = []*nodev1.ExtensionSharedDict{{Name: "a", SizeKb: 16384}, {Name: "b", SizeKb: 16384}, {Name: "c", SizeKb: 16}}
		},
		"repeated": func(c *nodev1.NodeConfig, e *nodev1.Extension, _ *nodev1.Site) { c.Extensions = append(c.Extensions, e) },
		"unknown on site": func(_ *nodev1.NodeConfig, _ *nodev1.Extension, a *nodev1.Site) {
			a.Extensions[0].Id = "other-one"
		},
		"site config": func(_ *nodev1.NodeConfig, _ *nodev1.Extension, a *nodev1.Site) { a.Extensions[0].ConfigJson = `"x"` },
	}
	for name, change := range cases {
		if _, err := Build(extensionConfig(t, change), withExtensions); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestExtensionNames(t *testing.T) {
	for s, want := range map[string]bool{
		"ext.hello-header.greeted": true, "ext.hello-header.faults": true, "ext.a.b": false, "ext.hello-header.Bad": false,
		"hello-header.greeted": false, "ext.hello-header": false,
	} {
		if ValidExtensionName(s) != want {
			t.Errorf("ValidExtensionName(%q) = %v", s, !want)
		}
	}
	for s, want := range map[string]bool{"ext:hello-header": true, "ext:Hello": false, "hello-header": false, "ext:": false} {
		if ValidExtensionRuleID(s) != want {
			t.Errorf("ValidExtensionRuleID(%q) = %v", s, !want)
		}
	}
}
