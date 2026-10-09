package configir

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// v0270Vector reads testdata/content_hash_vector_v0270.json, a copy of the
// console's fixture: a site with four access authentication rules in the
// site's order (Basic, forward authentication, signed URLs A and C) and a
// site without; sites and the rules' lists reversed.
func v0270Vector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_v0270.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v hashVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	cfg := &nodev1.NodeConfig{}
	if err := protojson.Unmarshal(v.Config, cfg); err != nil {
		t.Fatal(err)
	}
	return cfg, v
}

// TestContentHashVectorV0270 checks the proto v0.27.0 vector shared with
// the console: the rules keep their order, their lists are sorted, every
// new field is in the hash, and the plan.
func TestContentHashVectorV0270(t *testing.T) {
	cfg, v := v0270Vector(t)
	if cfg.GetSites()[0].GetId() != "b" || vectorSite(cfg, "a").GetAuthRules()[1].GetPathPrefixes()[0] != "/app/" {
		t.Fatalf("vector is already canonical")
	}
	b, err := CanonicalBytes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ContentHash(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v.CanonicalHex != hex.EncodeToString(b) {
		t.Fatalf("canonical bytes differ from the console\n got %x\nwant %s", b, v.CanonicalHex)
	}
	if v.ContentHash != h {
		t.Fatalf("vector hash %s, Go computes %s", v.ContentHash, h)
	}
	if err := VerifyHash(cfg); err != nil {
		t.Fatal(err)
	}
	rule := func(c *nodev1.NodeConfig, i int) *nodev1.AuthRule { return vectorSite(c, "a").AuthRules[i] }
	for name, change := range map[string]func(*nodev1.NodeConfig){
		// The rules' order decides which one applies: never sorted.
		"order": func(c *nodev1.NodeConfig) {
			r := vectorSite(c, "a").AuthRules
			r[0], r[1] = r[1], r[0]
		},
		"kind":     func(c *nodev1.NodeConfig) { rule(c, 3).Kind = nodev1.AuthKind_AUTH_KIND_URL_B },
		"domain":   func(c *nodev1.NodeConfig) { rule(c, 0).Domains = nil },
		"version":  func(c *nodev1.NodeConfig) { rule(c, 0).CredentialVersion = 3 },
		"realm":    func(c *nodev1.NodeConfig) { rule(c, 0).Basic.Realm = "x" },
		"keep":     func(c *nodev1.NodeConfig) { rule(c, 0).Basic.KeepAuthorization = true },
		"url":      func(c *nodev1.NodeConfig) { rule(c, 1).Forward.Url += "&x=1" },
		"timeout":  func(c *nodev1.NodeConfig) { rule(c, 1).Forward.TimeoutMs = 3000 },
		"cache":    func(c *nodev1.NodeConfig) { rule(c, 1).Forward.CacheSeconds = 0 },
		"redirect": func(c *nodev1.NodeConfig) { rule(c, 1).Forward.PassRedirects = false },
		"validity": func(c *nodev1.NodeConfig) { rule(c, 2).Url.ValiditySeconds = 60 },
		"param":    func(c *nodev1.NodeConfig) { rule(c, 2).Url.SignParam = "s" },
		"exclude":  func(c *nodev1.NodeConfig) { rule(c, 3).ExcludePathPrefixes = nil },
	} {
		c, _ := v0270Vector(t)
		change(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}

	Canonicalize(cfg)
	p, err := Build(cfg, Options{ClusterID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sites) != 2 || p.Sites[0].ID != "a" || len(p.Sites[1].AuthRules) != 0 {
		t.Fatalf("plan sites %+v", p.Sites)
	}
	rules := p.Sites[0].AuthRules
	if len(rules) != 4 || rules[0].Kind != AuthBasic || rules[1].Kind != AuthForward || rules[2].Kind != AuthURLA || rules[3].Kind != AuthURLC {
		t.Fatalf("rules %+v", rules)
	}
	f := rules[1].Forward
	if f.Scheme != "https" || f.Address != "auth.test" || f.Port != 443 || f.HostHeader != "auth.test" || f.URI != "/verify?from=edge" ||
		f.SNI != "auth.test" || f.TimeoutMS != 2000 || !slices.Equal(f.RequestHeaders, []string{"authorization", "cookie", "x-token"}) ||
		!slices.Equal(rules[1].PathPrefixes, []string{"/api/", "/app/"}) {
		t.Fatalf("forward %+v", rules[1])
	}
	refs := p.CredentialRefs()
	if refs["r-basic"] != 2 || refs["r-url-a"] != 1 || refs["r-url-c"] != 3 || len(refs) != 3 {
		t.Fatalf("credential refs %v", refs)
	}
}

func authSite(rules ...*nodev1.AuthRule) *nodev1.Site {
	return &nodev1.Site{Id: "s", AuthRules: rules}
}

func urlRule(id string) *nodev1.AuthRule {
	return &nodev1.AuthRule{
		Id: id, Kind: nodev1.AuthKind_AUTH_KIND_URL_B, CredentialId: id, CredentialVersion: 1,
		Url: &nodev1.UrlAuth{ValiditySeconds: 1800, SkewSeconds: 300, SignParam: "sign", TimeParam: "t"},
	}
}

// TestAuthRulesRefused rejects what the console never sends.
func TestAuthRulesRefused(t *testing.T) {
	forward := func(change func(*nodev1.ForwardAuth)) *nodev1.AuthRule {
		f := &nodev1.ForwardAuth{Url: "https://auth.test/v", TimeoutMs: 2000, RequestHeaders: []string{"cookie"}}
		change(f)
		return &nodev1.AuthRule{Id: "f", Kind: nodev1.AuthKind_AUTH_KIND_FORWARD, Forward: f}
	}
	basic := &nodev1.AuthRule{Id: "b", Kind: nodev1.AuthKind_AUTH_KIND_BASIC, CredentialId: "b", Basic: &nodev1.BasicAuth{Realm: "R"}}
	many := make([]*nodev1.AuthRule, 17)
	for i := range many {
		many[i] = urlRule("r" + string(rune('a'+i)))
	}
	cases := map[string][]*nodev1.AuthRule{
		"too many":     many,
		"twice":        {urlRule("a"), urlRule("a")},
		"unknown kind": {{Id: "x", Url: urlRule("x").Url, CredentialId: "x"}},
		"two parts":    {func() *nodev1.AuthRule { r := urlRule("x"); r.Basic = &nodev1.BasicAuth{Realm: "R"}; return r }()},
		"no secret":    {func() *nodev1.AuthRule { r := urlRule("x"); r.CredentialId = ""; return r }()},
		"validity":     {func() *nodev1.AuthRule { r := urlRule("x"); r.Url.ValiditySeconds = 0; return r }()},
		"skew":         {func() *nodev1.AuthRule { r := urlRule("x"); r.Url.SkewSeconds = 601; return r }()},
		"param":        {func() *nodev1.AuthRule { r := urlRule("x"); r.Url.SignParam = "a b"; return r }()},
		"same D params": {func() *nodev1.AuthRule {
			r := urlRule("x")
			r.Kind = nodev1.AuthKind_AUTH_KIND_URL_D
			r.Url.TimeParam = "sign"
			return r
		}()},
		"domain":           {func() *nodev1.AuthRule { r := urlRule("x"); r.Domains = []string{"A.test"}; return r }()},
		"pattern":          {func() *nodev1.AuthRule { r := urlRule("x"); r.Domains = []string{"~(a"}; return r }()},
		"prefix":           {func() *nodev1.AuthRule { r := urlRule("x"); r.PathPrefixes = []string{"a"}; return r }()},
		"prefix query":     {func() *nodev1.AuthRule { r := urlRule("x"); r.ExcludePathPrefixes = []string{"/a?b"}; return r }()},
		"extension":        {func() *nodev1.AuthRule { r := urlRule("x"); r.Extensions = []string{".jpg"}; return r }()},
		"realm quote":      {{Id: "b", Kind: nodev1.AuthKind_AUTH_KIND_BASIC, CredentialId: "b", Basic: &nodev1.BasicAuth{Realm: `a"b`}}},
		"realm long":       {{Id: "b", Kind: nodev1.AuthKind_AUTH_KIND_BASIC, CredentialId: "b", Basic: &nodev1.BasicAuth{Realm: strings.Repeat("r", 65)}}},
		"basic secretless": {func() *nodev1.AuthRule { r := *basic; r.CredentialId = ""; return &r }()},
		"forward secret":   {func() *nodev1.AuthRule { r := forward(func(*nodev1.ForwardAuth) {}); r.CredentialId = "f"; return r }()},
		"scheme":           {forward(func(f *nodev1.ForwardAuth) { f.Url = "ftp://auth.test/" })},
		"credentials":      {forward(func(f *nodev1.ForwardAuth) { f.Url = "https://u:p@auth.test/" })},
		"fragment":         {forward(func(f *nodev1.ForwardAuth) { f.Url = "https://auth.test/#x" })},
		"port":             {forward(func(f *nodev1.ForwardAuth) { f.Url = "https://auth.test:0/" })},
		"timeout":          {forward(func(f *nodev1.ForwardAuth) { f.TimeoutMs = 10001 })},
		"cache":            {forward(func(f *nodev1.ForwardAuth) { f.CacheSeconds = 301 })},
		"host header":      {forward(func(f *nodev1.ForwardAuth) { f.RequestHeaders = []string{"host"} })},
		"node header":      {forward(func(f *nodev1.ForwardAuth) { f.RequestHeaders = []string{"x-real-ip"} })},
		"protected copy":   {forward(func(f *nodev1.ForwardAuth) { f.ResponseHeaders = []string{"set-cookie"} })},
		"internal copy":    {forward(func(f *nodev1.ForwardAuth) { f.ResponseHeaders = []string{"x-edgeweir-site"} })},
		"uppercase":        {forward(func(f *nodev1.ForwardAuth) { f.ResponseHeaders = []string{"X-Auth-User"} })},
	}
	for name, rules := range cases {
		if _, err := buildAuthRules(authSite(rules...), AddressPolicy{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := buildAuthRules(authSite(urlRule("a"), basic, forward(func(*nodev1.ForwardAuth) {})), AddressPolicy{}); err != nil {
		t.Fatalf("valid rules refused: %v", err)
	}
}

// TestForwardAuthURL splits the authentication service's URL for the
// origin layer and applies the origin address policy to IP literals.
func TestForwardAuthURL(t *testing.T) {
	policy, _, _ := NewAddressPolicy([]string{"10.20.0.0/16"})
	for _, c := range []struct {
		url                     string
		address, host, uri, sni string
		port                    uint32
		forbidden               bool
	}{
		{"https://Auth.Example.com/verify?x=1", "auth.example.com", "auth.example.com", "/verify?x=1", "auth.example.com", 443, false},
		{"http://auth.test:8080", "auth.test", "auth.test:8080", "/", "auth.test", 8080, false},
		{"http://auth.test:80?q", "auth.test", "auth.test", "/?q", "auth.test", 80, false},
		{"http://10.20.0.5:9000/a%20b", "10.20.0.5", "10.20.0.5:9000", "/a%20b", "", 9000, false},
		{"https://127.0.0.1/v", "127.0.0.1", "127.0.0.1", "/v", "", 443, true},
		{"http://[::1]:81/v", "::1", "[::1]:81", "/v", "", 81, true},
		{"http://[2001:db8::1]/", "2001:db8::1", "[2001:db8::1]", "/", "", 80, true},
	} {
		f, err := buildForwardAuth(&nodev1.ForwardAuth{Url: c.url, TimeoutMs: 100}, policy)
		if err != nil {
			t.Fatalf("%s: %v", c.url, err)
		}
		if f.Address != c.address || f.HostHeader != c.host || f.URI != c.uri || f.SNI != c.sni || f.Port != c.port || f.Forbidden != c.forbidden {
			t.Errorf("%s: %+v", c.url, f)
		}
	}
}

// TestAuthSecrets attaches users and keys from the rules' secrets; a rule
// without a usable secret stays, refusing its requests, with a warning
// that names IDs only.
func TestAuthSecrets(t *testing.T) {
	hash := "pbkdf2-sha256$10000$" + strings.Repeat("ab", 16) + "$" + strings.Repeat("cd", 32)
	basic := &nodev1.AuthRule{Id: "b", Kind: nodev1.AuthKind_AUTH_KIND_BASIC, CredentialId: "b", CredentialVersion: 2, Basic: &nodev1.BasicAuth{Realm: "R"}}
	rules, err := buildAuthRules(authSite(basic, urlRule("u"), urlRule("gone")), AddressPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	p := &Plan{Sites: []Site{{ID: "s", Origins: []Origin{{ID: "o"}}, AuthRules: rules}}}
	secret := `{"users":[{"name":"alice","hash":"` + hash + `"},{"name":"bad:name","hash":"` + hash + `"},{"name":"bob","hash":"md5$x"}]}`
	p.AttachCredentials(map[string]Credential{
		"b": {Version: 2, SecretKey: secret},
		"u": {Version: 1, SecretKey: `{"keys":["short","0123456789abcdef-key","backup-key-0123456789","third-key-0123456789"]}`},
	})
	got := p.Sites[0].AuthRules
	if want := []BasicUser{{Name: "alice", Iterations: 10000, Salt: strings.Repeat("ab", 16), Hash: strings.Repeat("cd", 32)}}; !slices.Equal(got[0].Users, want) || got[0].SecretVersion != 2 {
		t.Fatalf("users %+v", got[0])
	}
	if !slices.Equal(got[1].Keys, []string{"0123456789abcdef-key", "backup-key-0123456789"}) {
		t.Fatalf("keys %v", got[1].Keys)
	}
	if got[2].Keys != nil || len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "rule gone: secret gone (version 1) unavailable") {
		t.Fatalf("missing secret: %+v %v", got[2], p.Warnings)
	}
	// An older version than the configuration asks for is not used.
	p = &Plan{Sites: []Site{{ID: "s", Origins: []Origin{{ID: "o"}}, AuthRules: rules}}}
	p.AttachCredentials(map[string]Credential{"b": {Version: 1, SecretKey: secret}})
	if p.Sites[0].AuthRules[0].Users != nil {
		t.Fatalf("stale secret attached")
	}
	// Secrets never appear in warnings; the JSON for the data plane carries them.
	for _, w := range p.Warnings {
		if strings.Contains(w, hash) || strings.Contains(w, "alice") {
			t.Fatalf("warning leaks the secret: %s", w)
		}
	}
	raw, _ := json.Marshal(got[0])
	if !strings.Contains(string(raw), `"users":[{"name":"alice","iterations":10000`) || strings.Contains(string(raw), "credential") {
		t.Fatalf("site table JSON %s", raw)
	}
}

// TestAuthRulesRejectConfiguration: a disabled site's invalid rule rejects
// the configuration too.
func TestAuthRulesRejectConfiguration(t *testing.T) {
	cfg, _ := v0270Vector(t)
	Canonicalize(cfg)
	s := vectorSite(cfg, "b")
	s.Enabled = false
	s.AuthRules = []*nodev1.AuthRule{{Id: "x", Kind: nodev1.AuthKind_AUTH_KIND_URL_A}}
	if _, err := Build(cfg, Options{}); !errors.Is(err, ErrRejected) {
		t.Fatalf("err %v", err)
	}
}
