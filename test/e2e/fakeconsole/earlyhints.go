package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/extension"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

func informationalHelpers(mux *http.ServeMux, c *fakeconsole.Console) {
	root := "/examples/extensions/informational-links/"
	manifest, err := os.ReadFile(root + "manifest.json")
	if err != nil {
		log.Fatal(err)
	}
	source, err := os.ReadFile(root + "lua/main.lua")
	if err != nil {
		log.Fatal(err)
	}
	seed := sha256.Sum256([]byte("informational response fixture signing key"))
	key := extension.JWK{Kty: "OKP", Crv: "Ed25519", D: base64.RawURLEncoding.EncodeToString(seed[:]),
		X: base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))}
	public := key
	public.D = ""
	jwk, _ := json.Marshal(public)
	var packages []*nodev1.Extension
	for _, id := range []string{"informational-links", "informational-links-second"} {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(manifest, &raw); err != nil {
			log.Fatal(err)
		}
		raw["id"], _ = json.Marshal(id)
		data, _ := json.Marshal(raw)
		archive, err := extension.Pack([]extension.File{{Path: "manifest.json", Data: data}, {Path: "lua/main.lua", Data: source}})
		if err != nil {
			log.Fatal(err)
		}
		sig, err := extension.Sign(archive, key, 1)
		if err != nil {
			log.Fatal(err)
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(archive))
		c.SetExtensionPackage(digest, archive)
		packages = append(packages, &nodev1.Extension{Id: id, Version: "1.0.0", Publisher: "example.org",
			Sha256: digest, Size: uint64(len(archive)), Signature: sig, PublicKey: string(jwk),
			Enabled: true, FailureMode: "closed", ConfigJson: "{}", LuaApi: 2})
	}
	g11SiteCert(c, "informational", false, "hints.test")
	cert := g11Certs["informational"]
	mux.HandleFunc("POST /informational", func(w http.ResponseWriter, r *http.Request) {
		s := site("site-informational", "hints.test", "console", 8082)
		s.CertificateId = "informational"
		s.Tls = &nodev1.TlsOptions{MinimumVersion: "1.2", CipherProfile: "modern", Http2: true, Http3: true}
		s.OriginPool.Connection = &nodev1.OriginConnection{ReadTimeoutMs: 1000}
		s.CacheRules[0].Match.PathPrefixes = []string{"/informational-links/cache"}
		phase := r.URL.Query().Get("phase")
		if phase == "" {
			phase = "both"
		}
		for _, e := range packages {
			settings, _ := json.Marshal(map[string]any{"phase": phase, "deny": r.URL.Query().Get("deny") == "1" && e.Id == "informational-links-second"})
			s.Extensions = append(s.Extensions, &nodev1.SiteExtension{Id: e.Id, ConfigJson: string(settings)})
		}
		cfg := config(s)
		cfg.Extensions = packages
		cfg.ExtensionsDisabled = r.URL.Query().Get("disabled") == "1"
		cfg.Certificates = []*nodev1.CertificateRef{{Id: "informational", Names: cert.names, Sha256Fingerprint: cert.material.Sha256Fingerprint}}
		for _, listener := range cfg.Listeners {
			if listener.Port == 8443 {
				listener.Http2, listener.Http3 = true, true
			}
		}
		cfg.RequiredFeatures = append(cfg.RequiredFeatures, configir.FeatureExtensions, configir.FeatureExtensionsV2, configir.FeatureExtensionsEarlyHints, "http3-v1")
		fmt.Fprint(w, c.Publish(cfg))
	})
}

func serveInformationalOrigin(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/informational-links/") {
		return false
	}
	w.Header().Set("Link", "</final.css>; rel=preload; as=style")
	switch r.URL.Path {
	case "/informational-links/not-modified":
		w.WriteHeader(304)
	case "/informational-links/redirect":
		w.Header().Set("Location", "/destination")
		w.WriteHeader(301)
	case "/informational-links/timeout":
		time.Sleep(2500 * time.Millisecond)
		fmt.Fprint(w, "late origin\n")
	default:
		fmt.Fprint(w, "origin informational response\n")
	}
	return true
}
