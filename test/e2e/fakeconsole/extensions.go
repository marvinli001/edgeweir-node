package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/extension"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

func extensionHelpers(mux *http.ServeMux, c *fakeconsole.Console, origin string) {
	manifest := []byte(`{"format":"edgeweir-node-extension-v1","id":"node-status","version":"1.0.0","publisher":"example.org","name":{"en":"Node status"},"requires":{"lua_api":2},"scope":"node","hooks":["init","log","listen"],"capabilities":["request_body","timers"],"secret":true,"shared_dicts":[{"name":"state","size_kb":16}],"listeners":[{"name":"http","default_port":19145,"methods":["GET","HEAD","POST"]},{"name":"empty","default_port":19146,"methods":["GET","HEAD","POST"],"max_body":0}]}`)
	archive, err := extension.Pack([]extension.File{
		{Path: "manifest.json", Data: manifest},
		{Path: "lua/main.lua", Data: []byte(`
local M = {}
function M.init(ew)
  assert(ew.site_id == nil and ew.site_config == nil)
  ew.shared("state"):set("inited", true)
  ew.log("warn", "node extension initialized token=" .. ew.global_config.token .. " node=" .. ew.node.id())
  local function tick(current)
    current.shared("state"):set("token", current.global_config.token)
    current.shared("state"):set("secret", current.equal(current.secret(), string.rep(current.global_config.key, 32)))
    current.timer(0.1, tick)
  end
  ew.timer(0, tick)
end
function M.log(ew)
  assert(ew.site_config == nil)
  ew.shared("state"):incr("logs", 1, 0)
end
function M.listen(ew, name, path)
  assert(ew.site_id == nil and ew.site_config == nil)
  if path == "/fail" then error("deliberate listener failure") end
  local d = ew.shared("state")
  return ew.respond(200, ew.json_encode({path=path, listener=name, body=ew.req.body(),
    token=d:get("token"), secret=d:get("secret"), inited=d:get("inited"), logs=d:get("logs") or 0}),
    {["Content-Type"]="application/json"})
end
return M
`)},
	})
	if err != nil {
		log.Fatal(err)
	}
	seed := sha256.Sum256([]byte("deterministic listener smoke test signing key"))
	private := ed25519.NewKeyFromSeed(seed[:])
	key := extension.JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey)), D: base64.RawURLEncoding.EncodeToString(seed[:])}
	signature, err := extension.Sign(archive, key, 1)
	if err != nil {
		log.Fatal(err)
	}
	siteArchive, err := extension.Pack([]extension.File{
		{Path: "manifest.json", Data: []byte(`{"format":"edgeweir-node-extension-v1","id":"site-header","version":"1.0.0","publisher":"example.org","name":{"en":"Site header"},"requires":{"lua_api":1},"hooks":["access"]}`)},
		{Path: "lua/main.lua", Data: []byte("return { access = function() end }\n")},
	})
	if err != nil {
		log.Fatal(err)
	}
	siteSignature, err := extension.Sign(siteArchive, key, 1)
	if err != nil {
		log.Fatal(err)
	}
	key.D = ""
	public, _ := json.Marshal(key)
	digest := sha256.Sum256(archive)
	base := &nodev1.Extension{
		Id: "node-status", Version: "1.0.0", Publisher: "example.org", Sha256: fmt.Sprintf("%x", digest),
		Size: uint64(len(archive)), Signature: signature, PublicKey: string(public), Enabled: true,
		FailureMode: "open", ConfigJson: `{"token":"one","key":"a"}`, Scope: "node", LuaApi: 2, SecretVersion: 1,
		SharedDicts: []*nodev1.ExtensionSharedDict{{Name: "state", SizeKb: 16}},
	}
	c.SetExtensionPackage(base.Sha256, archive)
	siteDigest := fmt.Sprintf("%x", sha256.Sum256(siteArchive))
	c.SetExtensionPackage(siteDigest, siteArchive)
	c.SetExtensionSecret(&nodev1.ExtensionSecret{Id: base.Id, Version: 1, Current: []byte(strings.Repeat("a", 32))})
	mux.HandleFunc("POST /extensions", func(w http.ResponseWriter, r *http.Request) {
		cfg := config(baseSites(origin)...)
		e := proto.CloneOf(base)
		c.SetExtensionSecret(&nodev1.ExtensionSecret{Id: e.Id, Version: 1, Current: []byte(strings.Repeat("a", 32))})
		mode := r.URL.Query().Get("mode")
		c.SetExtensionPackageError(nil)
		cfg.ClientAddress = &nodev1.ClientAddress{Mode: "header", Header: "x-forwarded-for", TrustedCidrs: allowList}
		for _, listener := range cfg.Listeners {
			listener.ProxyProtocol = false
		}
		if mode == "zero" {
			cfg.Sites = nil
			e.ConfigJson = `{"token":"zero","key":"a"}`
		}
		if mode != "unbound" && mode != "disabled" && mode != "kill" {
			for i, name := range []string{"http", "empty"} {
				limit := uint32(4096)
				if name == "empty" {
					limit = 0
				}
				e.Listeners = append(e.Listeners, &nodev1.ExtensionListener{
					Name: name, Port: uint32(19145 + i), Bind: "0.0.0.0", Allow: append([]string{"127.0.0.1/32"}, allowList...),
					Methods: []string{"GET", "HEAD", "POST"}, MaxBody: &limit,
				})
			}
		}
		switch mode {
		case "deny":
			e.Listeners[0].Allow = []string{"192.0.2.1/32"}
		case "loopback":
			e.Listeners[0].Bind = "127.0.0.1"
			e.Listeners[0].Port = 19147
			e.Listeners[0].Allow = []string{"127.0.0.1/32"}
		case "conflict":
			e.Listeners[0].Port = 19148
		case "reload":
			e.Listeners[0].Bind = r.URL.Query().Get("bind")
			e.Listeners[0].Port = 19149
		case "badbind":
			e.Listeners[0].Bind = "192.0.2.1"
		case "unknown":
			e.Listeners[0].Name = "undeclared"
		case "disabled":
			e.Enabled = false
		case "kill":
			cfg.ExtensionsDisabled = true
		case "hot":
			e.ConfigJson, e.SecretVersion = `{"token":"two","key":"b"}`, 2
			c.SetExtensionSecret(&nodev1.ExtensionSecret{Id: e.Id, Version: 2, Current: []byte(strings.Repeat("b", 32))})
		}
		cfg.Extensions = []*nodev1.Extension{e}
		if mode == "mixed" || mode == "transient" {
			closed := site("site-closed-extension", "ext-closed.test", origin, 80)
			closed.Extensions = []*nodev1.SiteExtension{{Id: "site-header", ConfigJson: `{"saved":true}`}}
			cfg.Sites = append(cfg.Sites, closed)
			cfg.Extensions = append(cfg.Extensions, &nodev1.Extension{
				Id: "site-header", Version: "1.0.0", Publisher: "example.org", Sha256: siteDigest,
				Size: uint64(len(siteArchive)), Signature: siteSignature, PublicKey: string(public),
				Enabled: true, FailureMode: "closed", ConfigJson: "{}", LuaApi: 1,
			})
		}
		if mode == "transient" {
			c.SetExtensionPackageError(connect.NewError(connect.CodeUnavailable, errors.New("temporary package download failure")))
		}
		cfg.RequiredFeatures = append(cfg.RequiredFeatures, configir.FeatureExtensions, configir.FeatureExtensionsV2, configir.FeatureExtensionsNode)
		fmt.Fprint(w, c.Publish(cfg))
	})
	mux.HandleFunc("GET /extensions/status", func(w http.ResponseWriter, _ *http.Request) {
		for _, e := range c.LastStatus().GetExtensions() {
			fmt.Fprintf(w, "%s %s %s %s\n", e.GetId(), e.GetState(), e.GetMessage(), e.GetDetailsJson())
		}
	})
	mux.HandleFunc("GET /extensions/digests", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "%s %s", base.Sha256, siteDigest)
	})
}
