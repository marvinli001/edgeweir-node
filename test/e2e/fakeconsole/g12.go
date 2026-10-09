package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

// G12 (access-auth-v1, ADR-0038): the sites, all with the whoami origin
// (it echoes the request) and the base site's "cache everything" rule:
//
//	basic.g12.test  Basic (alice / g12-password), X-Auth-User to the origin
//	url.g12.test    signed URLs: A for .mp4, B under /b/, C under /c/, D
//	                everywhere else, keys g12UrlKey and g12BackupKey
//	fwd.g12.test    forward authentication at console:8086: /login/ passes
//	                3xx on, /open/ lets requests through when the service
//	                fails, /down/ asks a failing service, everything else
//	                /check with answers cached 30 s
//
// The authentication service on :8086: /check answers 200 with X-Auth-User
// for the cookie sid=good, else 401 (Bearer challenge, JSON body); /login
// 302 to the login page with the original URI; /fail 500. It counts its
// requests and keeps the headers of the last one (helper GET /g12/auth).
const (
	g12Password  = "g12-password"
	g12UrlKey    = "g12-url-key-0123456789"
	g12BackupKey = "g12-backup-key-abcdefghij"
)

var (
	g12Calls atomic.Int64
	g12Mu    sync.Mutex
	g12Seen  http.Header
)

func serveAuthService(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		g12Calls.Add(1)
		g12Mu.Lock()
		g12Seen = r.Header.Clone()
		g12Seen.Set("X-Seen-Method", r.Method)
		g12Seen.Set("X-Seen-URI", r.RequestURI)
		g12Seen.Set("X-Seen-Host", r.Host)
		g12Mu.Unlock()
		switch r.URL.Path {
		case "/check":
			if c, err := r.Cookie("sid"); err == nil && c.Value == "good" {
				w.Header().Set("X-Auth-User", "alice")
				w.Header().Set("X-Auth-Other", "not copied")
				w.WriteHeader(http.StatusOK)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="g12"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"login required"}`)
		case "/login":
			http.Redirect(w, r, "https://login.g12.test/?rd="+r.Header.Get("X-Original-URI"), http.StatusFound)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("authentication service on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

// g12Setup gives the console the rules' secrets (as the real one does,
// over GetOriginCredentials).
func g12Setup(c *fakeconsole.Console) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		log.Fatal(err)
	}
	key, err := pbkdf2.Key(sha256.New, g12Password, salt, 10000, 32)
	if err != nil {
		log.Fatal(err)
	}
	users, _ := json.Marshal(map[string]any{"users": []map[string]string{
		{"name": "alice", "hash": "pbkdf2-sha256$10000$" + hex.EncodeToString(salt) + "$" + hex.EncodeToString(key)},
	}})
	c.SetCredential(&nodev1.OriginCredential{Id: "g12-basic", Version: 1, SecretAccessKey: string(users)})
	keys, _ := json.Marshal(map[string]any{"keys": []string{g12UrlKey, g12BackupKey}})
	for _, id := range []string{"g12-url-a", "g12-url-b", "g12-url-c", "g12-url-d"} {
		c.SetCredential(&nodev1.OriginCredential{Id: id, Version: 1, SecretAccessKey: string(keys)})
	}
}

func g12URLRule(id string, kind nodev1.AuthKind) *nodev1.AuthRule {
	return &nodev1.AuthRule{Id: id, Kind: kind, CredentialId: id, CredentialVersion: 1,
		Url: &nodev1.UrlAuth{ValiditySeconds: 1800, SkewSeconds: 300, SignParam: "sign", TimeParam: "t"}}
}

func g12Forward(id, path string, change func(*nodev1.ForwardAuth)) *nodev1.AuthRule {
	f := &nodev1.ForwardAuth{Url: "http://console:8086" + path, TimeoutMs: 2000,
		RequestHeaders: []string{"authorization", "cookie"}, ResponseHeaders: []string{"x-auth-user"}}
	change(f)
	return &nodev1.AuthRule{Id: id, Kind: nodev1.AuthKind_AUTH_KIND_FORWARD, Forward: f}
}

// g12Config is the base configuration with the G12 sites.
func g12Config(origin string) *nodev1.NodeConfig {
	b := site("site-g12b", "basic.g12.test", origin, 80)
	b.AuthRules = []*nodev1.AuthRule{{Id: "g12-basic", Kind: nodev1.AuthKind_AUTH_KIND_BASIC, CredentialId: "g12-basic",
		CredentialVersion: 1, Basic: &nodev1.BasicAuth{Realm: "G12", UserHeader: true}}}
	u := site("site-g12u", "url.g12.test", origin, 80)
	a := g12URLRule("g12-url-a", nodev1.AuthKind_AUTH_KIND_URL_A)
	a.Extensions = []string{"mp4"}
	rb := g12URLRule("g12-url-b", nodev1.AuthKind_AUTH_KIND_URL_B)
	rb.PathPrefixes = []string{"/b/"}
	rc := g12URLRule("g12-url-c", nodev1.AuthKind_AUTH_KIND_URL_C)
	rc.PathPrefixes = []string{"/c/"}
	u.AuthRules = []*nodev1.AuthRule{a, rb, rc, g12URLRule("g12-url-d", nodev1.AuthKind_AUTH_KIND_URL_D)}
	f := site("site-g12f", "fwd.g12.test", origin, 80)
	f.AuthRules = []*nodev1.AuthRule{
		g12Forward("g12-login", "/login", func(f *nodev1.ForwardAuth) { f.PassRedirects = true }),
		g12Forward("g12-open", "/fail", func(f *nodev1.ForwardAuth) { f.AllowUnavailable = true }),
		g12Forward("g12-down", "/fail", func(*nodev1.ForwardAuth) {}),
		g12Forward("g12-check", "/check", func(f *nodev1.ForwardAuth) { f.CacheSeconds = 30 }),
	}
	f.AuthRules[0].PathPrefixes = []string{"/login/"}
	f.AuthRules[1].PathPrefixes = []string{"/open/"}
	f.AuthRules[2].PathPrefixes = []string{"/down/"}
	cfg := config(append(baseSites(origin), b, u, f)...)
	cfg.RequiredFeatures = append(cfg.RequiredFeatures, configir.FeatureAccessAuth)
	return cfg
}

// g12Handlers: POST /g12 publishes g12Config (?enabled=false: the base
// configuration again); GET /g12/auth reports the authentication service's
// requests and the last one's headers ("<count>\n<Name>: <value>...").
func g12Handlers(mux *http.ServeMux, c *fakeconsole.Console, origin string) {
	mux.HandleFunc("POST /g12", func(w http.ResponseWriter, r *http.Request) {
		cfg := g12Config(origin)
		if r.URL.Query().Get("enabled") == "false" {
			cfg = config(baseSites(origin)...)
		}
		fmt.Fprint(w, c.Publish(cfg))
	})
	mux.HandleFunc("GET /g12/auth", func(w http.ResponseWriter, _ *http.Request) {
		g12Mu.Lock()
		defer g12Mu.Unlock()
		fmt.Fprintln(w, g12Calls.Load())
		for name, values := range g12Seen {
			fmt.Fprintf(w, "%s: %s\n", name, strings.Join(values, ", "))
		}
	})
}
