package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/extension"
)

func cachedScopePackage(t *testing.T, scope string) (*Agent, configir.Extension, []byte) {
	t.Helper()
	extra := ""
	if scope != "" {
		extra = `,"scope":"` + scope + `"`
	}
	hooks := `["init"]`
	if scope == extension.ScopeNode {
		hooks = `["init","listen"]`
		extra += `,"listeners":[{"name":"http","default_port":9100,"methods":["HEAD","GET"],"max_body":0}]`
	}
	manifest := []byte(`{"format":"edgeweir-node-extension-v1","id":"status-ext","version":"1.0.0","publisher":"example.org","name":{"en":"Status"},"requires":{"lua_api":2},"hooks":` + hooks + extra + "}\n")
	archive, err := extension.Pack([]extension.File{
		{Path: "manifest.json", Data: manifest}, {Path: "lua/main.lua", Data: []byte("return {}\n")},
	})
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("extension scope test key"))
	private := ed25519.NewKeyFromSeed(seed[:])
	key := extension.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), D: base64.RawURLEncoding.EncodeToString(seed[:])}
	signature, err := extension.Sign(archive, key, 1)
	if err != nil {
		t.Fatal(err)
	}
	key.D = ""
	public, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := extension.Verify(archive, signature, key, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	e := configir.Extension{
		ID: "status-ext", Version: "1.0.0", Publisher: "example.org", SHA256: pkg.SHA256, Size: len(archive),
		Signature: signature, PublicKey: string(public), Enabled: true, FailureMode: "open", LuaAPI: 2,
	}
	if scope == extension.ScopeNode {
		e.Scope = extension.ScopeNode
		e.Listeners = []configir.ExtensionListener{{Name: "http", Port: 9100, Bind: "127.0.0.1", Allow: []string{"127.0.0.1/32"}, Methods: []string{"GET", "HEAD"}, MaxBody: 0}}
	}
	a := &Agent{cfg: Config{StateDir: t.TempDir()}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if err := os.MkdirAll(a.extensionsDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(a.extensionsDir(), e.SHA256+".ewx"), archive, 0o600); err != nil {
		t.Fatal(err)
	}
	return a, e, manifest
}

func TestExtensionTreeScopeGuards(t *testing.T) {
	for _, scope := range []string{"", extension.ScopeSite, extension.ScopeNode} {
		a, e, manifest := cachedScopePackage(t, scope)
		dir, err := a.extensionTree(context.Background(), &e, nil)
		if err != nil {
			t.Fatalf("site scope %q: %v", scope, err)
		}
		got, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if err != nil || !bytes.Equal(got, manifest) {
			t.Fatalf("signed manifest bytes changed: %v", err)
		}
		if cached, err := a.extensionTree(context.Background(), &e, nil); err != nil || cached != dir {
			t.Fatalf("verified cache: %q, %v", cached, err)
		}
	}
	for name, change := range map[string]func(*testing.T, *Agent, *configir.Extension){
		"scope differs": func(_ *testing.T, _ *Agent, e *configir.Extension) { e.Scope = "" },
		"not declared":  func(_ *testing.T, _ *Agent, e *configir.Extension) { e.Listeners[0].Name = "other" },
		"methods or body limit differ": func(_ *testing.T, _ *Agent, e *configir.Extension) {
			e.Listeners[0].Methods = []string{"GET", "HEAD", "POST"}
		},
		"body limit differs": func(_ *testing.T, _ *Agent, e *configir.Extension) { e.Listeners[0].MaxBody = 4096 },
	} {
		t.Run(name, func(t *testing.T) {
			a, e, _ := cachedScopePackage(t, extension.ScopeNode)
			if _, err := a.extensionTree(context.Background(), &e, nil); err != nil {
				t.Fatal(err)
			}
			change(t, a, &e)
			dir, err := a.extensionTree(context.Background(), &e, nil)
			want := name
			if name == "body limit differs" {
				want = "methods or body limit differ"
			}
			if err == nil || dir != "" || !strings.Contains(err.Error(), want) {
				t.Fatalf("node package guard: dir %q, %v", dir, err)
			}
		})
	}
	a, e, _ := cachedScopePackage(t, extension.ScopeNode)
	e.Scope, e.Signature = "", "invalid"
	if _, err := a.extensionTree(context.Background(), &e, nil); err == nil || strings.Contains(err.Error(), "configured scope") || strings.Contains(err.Error(), "unsupported runtime") {
		t.Fatalf("scope considered before signature verification: %v", err)
	}
}

func TestExtensionNodeCapability(t *testing.T) {
	a := &Agent{}
	features := append(slices.Clone(configir.SupportedFeatures), a.extraFeatures()...)
	if !slices.Contains(features, configir.FeatureExtensionsV2) || !slices.Contains(features, configir.FeatureExtensionsNode) {
		t.Fatalf("extension runtime features %v", features)
	}
	a.cfg.Extensions.Disabled = true
	for _, feature := range []string{configir.FeatureExtensions, configir.FeatureExtensionsV2, configir.FeatureExtensionsNode} {
		if slices.Contains(a.extraFeatures(), feature) {
			t.Fatalf("local disable announced %s", feature)
		}
	}
}

func TestEnsureExtensionsOffline(t *testing.T) {
	for _, scope := range []string{"", extension.ScopeNode} {
		a, e, _ := cachedScopePackage(t, scope)
		e.FailureMode = "closed"
		e.Config = []byte(`{"global":true}`)
		site := configir.Site{ID: "old-site"}
		if scope == "" {
			site.Extensions = []configir.SiteExtension{{ID: e.ID, Config: []byte(`{"saved":true}`)}}
		}
		plan := &configir.Plan{Extensions: []configir.Extension{e}, Sites: []configir.Site{site}}
		if err := a.ensureExtensions(context.Background(), plan); err != nil || plan.Extensions[0].State != "loaded" || plan.Extensions[0].Dir == "" {
			t.Fatalf("valid cached package without a channel: %+v, %v", plan.Extensions, err)
		}
		if err := os.Remove(filepath.Join(a.extensionsDir(), e.SHA256+".ewx")); err != nil {
			t.Fatal(err)
		}
		plan.Extensions = []configir.Extension{e}
		if err := a.ensureExtensions(context.Background(), plan); err != nil || plan.Extensions[0].State != "failed" || plan.Extensions[0].Dir != "" {
			t.Fatalf("missing offline archive: %+v, %v", plan.Extensions, err)
		}
		if !plan.Extensions[0].Enabled || plan.Extensions[0].FailureMode != "closed" || string(plan.Extensions[0].Config) != `{"global":true}` || len(plan.Sites[0].Extensions) != len(site.Extensions) {
			t.Fatal("offline package failure changed global or site settings")
		}
		if scope == "" && string(plan.Sites[0].Extensions[0].Config) != `{"saved":true}` {
			t.Fatal("offline package failure changed site configuration")
		}
	}
}
