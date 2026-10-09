package configir

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// accessConfig is the v0.27.0 vector with three IP lists, site "b" with
// the access control of change (nil: none), canonical.
func accessConfig(t *testing.T, change func(*nodev1.AccessControl)) *nodev1.NodeConfig {
	t.Helper()
	cfg, _ := v0270Vector(t)
	cfg.IpLists = []*nodev1.IpList{
		{Id: "l-block", Name: "block", Kind: "block", Entries: []string{"198.51.100.0/24"}},
		{Id: "l-allow", Name: "allow", Kind: "allow", Platform: true, Entries: []string{"203.0.113.7/32"}},
		{Id: "l-rules", Name: "rules", Kind: "collection", Entries: []string{"2001:db8::/32"}},
	}
	for i := range 17 {
		for _, prefix := range []string{"b-", "a-"} {
			cfg.IpLists = append(cfg.IpLists, &nodev1.IpList{Id: prefix + strconv.Itoa(i), Kind: "collection"})
		}
	}
	if change != nil {
		a := fullAccessControl()
		change(a)
		vectorSite(cfg, "b").AccessControl = a
	}
	Canonicalize(cfg)
	return cfg
}

// fullAccessControl uses every part.
func fullAccessControl() *nodev1.AccessControl {
	return &nodev1.AccessControl{
		BlockListIds: []string{"l-block"},
		AllowListIds: []string{"l-allow", "l-rules"},
		Hotlink: &nodev1.Hotlink{
			AllowEmpty: true, AllowSiteDomains: true, Allowed: []string{"*.friend.test", ".deep.test", "10.0.0.1", "a_b.test"},
			Denied: []string{"evil.test", "*"}, CheckOrigin: true, Extensions: []string{"jpg", "mp4"},
			PathPrefixes: []string{"/dl/"}, ExcludePathPrefixes: []string{"/dl/free/"}, RedirectUrl: "/hotlink.png",
		},
		UserAgents: &nodev1.UserAgentRules{
			Rules:        []*nodev1.UserAgentRule{{Pattern: "*Googlebot*", Allow: true}, {Pattern: "*"}, {Pattern: ""}, {Pattern: `a\*b\\c`}},
			PathPrefixes: []string{"/"}, ExcludePathPrefixes: []string{"/robots.txt"},
		},
		Cors: &nodev1.Cors{
			AllowedOrigins: []string{"https://app.test", "https://*.app.test:8443", "http://localhost:3000"}, AllowCredentials: true,
			AllowedMethods: []string{"GET", "POST", "OPTIONS"}, AllowedHeaders: []string{"content-type", "x-token"},
			EchoRequestHeaders: true, ExposedHeaders: []string{"X-Total"}, MaxAgeSeconds: 600, KeepOriginHeaders: true,
			PathPrefixes: []string{"/api/"},
		},
		Geo: &nodev1.GeoAccess{
			AllowOnly: true, Countries: []string{"NZ", "AU"}, Subdivisions: []string{"US-CA", "CN-Guangdong", "FR-Île-de-France"},
			Asns: []uint32{64512, 13335}, PathPrefixes: []string{"/"}, ExceptPathPrefixes: []string{"/health"},
		},
		Websocket:       &nodev1.WebSocketAccess{Origins: []string{"https://chat.test", "https://*.chat.test"}},
		SecurityHeaders: &nodev1.SecurityHeaders{Nosniff: true, FrameOptions: "SAMEORIGIN", ReferrerPolicy: "strict-origin-when-cross-origin", PermissionsPolicy: "camera=(), geolocation=()", HideServer: true, RemovePoweredBy: true},
	}
}

// geoFeaturesAll are the GeoIP capabilities of a node with every database.
var geoFeaturesAll = []string{"geoip-country-v1", "geoip-city-v1", "geoip-subdivision-v1", "geoip-asn-v1"}

func planSite(t *testing.T, p *Plan, id string) Site {
	t.Helper()
	for _, s := range p.Sites {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("site %s not in the plan", id)
	return Site{}
}

// TestAccessControlPlan: every part reaches the site table (snake_case,
// canonical lists, the WebSocket idle timeout's default applied).
func TestAccessControlPlan(t *testing.T) {
	cfg := accessConfig(t, func(a *nodev1.AccessControl) {})
	p, err := Build(cfg, Options{ExtraFeatures: geoFeaturesAll})
	if err != nil {
		t.Fatal(err)
	}
	a := planSite(t, p, "b").AccessControl
	if a == nil || planSite(t, p, "a").AccessControl != nil {
		t.Fatalf("access control %+v", a)
	}
	if a.WebSocket.IdleTimeoutSeconds != DefaultWebSocketIdle {
		t.Fatalf("idle timeout %d", a.WebSocket.IdleTimeoutSeconds)
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"block_list_ids":["l-block"],"allow_list_ids":["l-allow","l-rules"],` +
		`"hotlink":{"allow_empty":true,"allow_site_domains":true,"allowed":["*.friend.test",".deep.test","10.0.0.1","a_b.test"],"denied":["*","evil.test"],"check_origin":true,"extensions":["jpg","mp4"],"path_prefixes":["/dl/"],"exclude_path_prefixes":["/dl/free/"],"redirect_url":"/hotlink.png"},` +
		`"user_agents":{"rules":[{"pattern":"*Googlebot*","allow":true},{"pattern":"*"},{"pattern":""},{"pattern":"a\\*b\\\\c"}],"path_prefixes":["/"],"exclude_path_prefixes":["/robots.txt"]},` +
		`"cors":{"allowed_origins":["http://localhost:3000","https://*.app.test:8443","https://app.test"],"allow_credentials":true,"allowed_methods":["GET","POST","OPTIONS"],"allowed_headers":["content-type","x-token"],"echo_request_headers":true,"exposed_headers":["X-Total"],"max_age_seconds":600,"keep_origin_headers":true,"path_prefixes":["/api/"]},` +
		`"geo":{"allow_only":true,"countries":["AU","NZ"],"subdivisions":["CN-Guangdong","FR-Île-de-France","US-CA"],"asns":[13335,64512],"path_prefixes":["/"],"except_path_prefixes":["/health"]},` +
		`"websocket":{"origins":["https://*.chat.test","https://chat.test"],"idle_timeout_seconds":3600},` +
		`"security_headers":{"nosniff":true,"frame_options":"SAMEORIGIN","referrer_policy":"strict-origin-when-cross-origin","permissions_policy":"camera=(), geolocation=()","hide_server":true,"remove_powered_by":true}}`
	if string(raw) != want {
		t.Fatalf("site table JSON\n got %s\nwant %s", raw, want)
	}
	if !slices.Contains(SupportedFeatures, FeatureAccessControl) || FeatureAccessControl != "access-control-v1" {
		t.Fatalf("SupportedFeatures lacks access-control-v1: %v", SupportedFeatures)
	}
	// A node that announces the feature takes a configuration requiring it.
	cfg.RequiredFeatures = append(cfg.RequiredFeatures, FeatureAccessControl)
	if _, err := Build(cfg, Options{ExtraFeatures: geoFeaturesAll}); err != nil {
		t.Fatal(err)
	}
}

// TestAccessControlParts: a part on its own, the WebSocket idle timeout
// kept, an empty access control or a security header part with nothing on.
func TestAccessControlParts(t *testing.T) {
	cfg := accessConfig(t, func(a *nodev1.AccessControl) {
		*a = nodev1.AccessControl{Websocket: &nodev1.WebSocketAccess{IdleTimeoutSeconds: 86400}}
	})
	p, err := Build(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	a := planSite(t, p, "b").AccessControl
	if raw, _ := json.Marshal(a); string(raw) != `{"websocket":{"idle_timeout_seconds":86400}}` {
		t.Fatalf("site table JSON %s", raw)
	}
	cfg = accessConfig(t, func(a *nodev1.AccessControl) { *a = nodev1.AccessControl{SecurityHeaders: &nodev1.SecurityHeaders{}} })
	if p, err = Build(cfg, Options{}); err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(planSite(t, p, "b").AccessControl); string(raw) != `{"security_headers":{}}` {
		t.Fatalf("site table JSON %s", raw)
	}
	// Geo with lists the databases cover; without lists none is needed.
	cfg = accessConfig(t, func(a *nodev1.AccessControl) { *a = nodev1.AccessControl{Geo: &nodev1.GeoAccess{AllowOnly: true}} })
	if _, err = Build(cfg, Options{}); err != nil {
		t.Fatal(err)
	}
}

// TestAccessControlSiteJSON: a site without access control, or with an
// empty one, has the same site table JSON as before access control
// existed (no access_control key); a site with it differs only there.
func TestAccessControlSiteJSON(t *testing.T) {
	siteJSON := func(cfg *nodev1.NodeConfig) []byte {
		t.Helper()
		p, err := Build(cfg, Options{ExtraFeatures: geoFeaturesAll})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(planSite(t, p, "b"))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	before := siteJSON(accessConfig(t, nil))
	if strings.Contains(string(before), "access_control") {
		t.Fatalf("site without access control: %s", before)
	}
	empty := siteJSON(accessConfig(t, func(a *nodev1.AccessControl) { *a = nodev1.AccessControl{} }))
	if string(empty) != string(before) {
		t.Fatalf("empty access control changes the site table\n got %s\nwant %s", empty, before)
	}
	var with, without map[string]json.RawMessage
	if err := json.Unmarshal(siteJSON(accessConfig(t, func(*nodev1.AccessControl) {})), &with); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(before, &without); err != nil {
		t.Fatal(err)
	}
	if _, ok := with["access_control"]; !ok {
		t.Fatalf("access_control missing")
	}
	delete(with, "access_control")
	a, _ := json.Marshal(with)
	b, _ := json.Marshal(without)
	if string(a) != string(b) {
		t.Fatalf("access control changed other fields\n got %s\nwant %s", a, b)
	}
}

// TestAccessControlRefused rejects the whole configuration for anything
// the console never sends, disabled sites included.
func TestAccessControlRefused(t *testing.T) {
	many := func(n int, f func(int) string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = f(i)
		}
		return out
	}
	letters := func(i int) string { return string(rune('a'+i/26)) + string(rune('a'+i%26)) }
	cases := map[string]func(*nodev1.AccessControl){
		"unknown block list": func(a *nodev1.AccessControl) { a.BlockListIds = []string{"nope"} },
		"unknown allow list": func(a *nodev1.AccessControl) { a.AllowListIds = []string{"nope"} },
		"list on both sides": func(a *nodev1.AccessControl) { a.BlockListIds = []string{"l-allow"} },
		"17 block lists": func(a *nodev1.AccessControl) {
			a.BlockListIds = many(17, func(i int) string { return "b-" + strconv.Itoa(i) })
		},
		"17 allow lists": func(a *nodev1.AccessControl) {
			a.AllowListIds = many(17, func(i int) string { return "a-" + strconv.Itoa(i) })
		},
		"hotlink uppercase":    func(a *nodev1.AccessControl) { a.Hotlink.Allowed = []string{"Friend.test"} },
		"hotlink trailing dot": func(a *nodev1.AccessControl) { a.Hotlink.Allowed = []string{"friend.test."} },
		"hotlink URL":          func(a *nodev1.AccessControl) { a.Hotlink.Denied = []string{"https://evil.test"} },
		"hotlink deep star":    func(a *nodev1.AccessControl) { a.Hotlink.Denied = []string{"*.*.evil.test"} },
		"hotlink star IP":      func(a *nodev1.AccessControl) { a.Hotlink.Denied = []string{"*.1.2.3.4"} },
		"hotlink IPv6":         func(a *nodev1.AccessControl) { a.Hotlink.Denied = []string{"2001:db8::1"} },
		"hotlink 201 sources": func(a *nodev1.AccessControl) {
			a.Hotlink.Allowed = many(201, func(i int) string { return letters(i) + ".test" })
		},
		"hotlink extension": func(a *nodev1.AccessControl) { a.Hotlink.Extensions = []string{".jpg"} },
		"hotlink 65 extensions": func(a *nodev1.AccessControl) {
			a.Hotlink.Extensions = many(65, letters)
		},
		"hotlink prefix":         func(a *nodev1.AccessControl) { a.Hotlink.PathPrefixes = []string{"dl/"} },
		"hotlink prefix query":   func(a *nodev1.AccessControl) { a.Hotlink.ExcludePathPrefixes = []string{"/a?b"} },
		"hotlink prefix control": func(a *nodev1.AccessControl) { a.Hotlink.ExcludePathPrefixes = []string{"/a\x01"} },
		"hotlink prefix long":    func(a *nodev1.AccessControl) { a.Hotlink.PathPrefixes = []string{"/" + strings.Repeat("a", 1024)} },
		"hotlink 33 prefixes": func(a *nodev1.AccessControl) {
			a.Hotlink.PathPrefixes = many(33, func(i int) string { return "/" + letters(i) })
		},
		"redirect protocol relative": func(a *nodev1.AccessControl) { a.Hotlink.RedirectUrl = "//evil.test/x.png" },
		"redirect scheme":            func(a *nodev1.AccessControl) { a.Hotlink.RedirectUrl = "ftp://img.test/x.png" },
		"redirect credentials":       func(a *nodev1.AccessControl) { a.Hotlink.RedirectUrl = "https://u:p@img.test/x.png" },
		"redirect space":             func(a *nodev1.AccessControl) { a.Hotlink.RedirectUrl = "https://img.test/a b.png" },
		"redirect backslash":         func(a *nodev1.AccessControl) { a.Hotlink.RedirectUrl = `/a\b.png` },
		"redirect control":           func(a *nodev1.AccessControl) { a.Hotlink.RedirectUrl = "/a\r\nX: y" },
		"redirect long":              func(a *nodev1.AccessControl) { a.Hotlink.RedirectUrl = "/" + strings.Repeat("a", 2048) },
		"no user agent rules":        func(a *nodev1.AccessControl) { a.UserAgents.Rules = nil },
		"201 user agent rules": func(a *nodev1.AccessControl) {
			a.UserAgents.Rules = make([]*nodev1.UserAgentRule, 201)
			for i := range a.UserAgents.Rules {
				a.UserAgents.Rules[i] = &nodev1.UserAgentRule{Pattern: "x"}
			}
		},
		"user agent escape":    func(a *nodev1.AccessControl) { a.UserAgents.Rules[0].Pattern = `a\b` },
		"user agent 9 stars":   func(a *nodev1.AccessControl) { a.UserAgents.Rules[0].Pattern = strings.Repeat("*", 9) },
		"user agent tab":       func(a *nodev1.AccessControl) { a.UserAgents.Rules[0].Pattern = "a\tb" },
		"user agent non-ASCII": func(a *nodev1.AccessControl) { a.UserAgents.Rules[0].Pattern = "ü" },
		"user agent long":      func(a *nodev1.AccessControl) { a.UserAgents.Rules[0].Pattern = strings.Repeat("x", 513) },
		"user agent prefix":    func(a *nodev1.AccessControl) { a.UserAgents.ExcludePathPrefixes = []string{"robots.txt"} },
		"CORS no origins":      func(a *nodev1.AccessControl) { a.Cors.AllowedOrigins = nil },
		"CORS star credentials": func(a *nodev1.AccessControl) {
			a.Cors.AllowedOrigins = []string{"*"}
		},
		"CORS origin path":         func(a *nodev1.AccessControl) { a.Cors.AllowedOrigins = []string{"https://app.test/"} },
		"CORS origin default port": func(a *nodev1.AccessControl) { a.Cors.AllowedOrigins = []string{"https://app.test:443"} },
		"CORS origin uppercase":    func(a *nodev1.AccessControl) { a.Cors.AllowedOrigins = []string{"https://App.test"} },
		"CORS origin IPv6":         func(a *nodev1.AccessControl) { a.Cors.AllowedOrigins = []string{"https://[::1]"} },
		"CORS origin ws":           func(a *nodev1.AccessControl) { a.Cors.AllowedOrigins = []string{"ws://app.test"} },
		"CORS 101 origins": func(a *nodev1.AccessControl) {
			a.Cors.AllowedOrigins = many(101, func(i int) string { return "https://" + letters(i) + ".test" })
		},
		"CORS no methods":       func(a *nodev1.AccessControl) { a.Cors.AllowedMethods = nil },
		"CORS lowercase method": func(a *nodev1.AccessControl) { a.Cors.AllowedMethods = []string{"get"} },
		"CORS 17 methods": func(a *nodev1.AccessControl) {
			a.Cors.AllowedMethods = many(17, func(i int) string { return "M" + letters(i) })
		},
		"CORS uppercase header":  func(a *nodev1.AccessControl) { a.Cors.AllowedHeaders = []string{"Content-Type"} },
		"CORS header with space": func(a *nodev1.AccessControl) { a.Cors.ExposedHeaders = []string{"x total"} },
		"CORS 65 headers":        func(a *nodev1.AccessControl) { a.Cors.ExposedHeaders = many(65, letters) },
		"CORS max age":           func(a *nodev1.AccessControl) { a.Cors.MaxAgeSeconds = 86401 },
		"CORS prefix":            func(a *nodev1.AccessControl) { a.Cors.PathPrefixes = []string{"/a#b"} },
		"geo lowercase country":  func(a *nodev1.AccessControl) { a.Geo.Countries = []string{"nz"} },
		"geo country length":     func(a *nodev1.AccessControl) { a.Geo.Countries = []string{"NZL"} },
		"geo subdivision":        func(a *nodev1.AccessControl) { a.Geo.Subdivisions = []string{"US"} },
		"geo subdivision empty":  func(a *nodev1.AccessControl) { a.Geo.Subdivisions = []string{"US-"} },
		"geo subdivision country": func(a *nodev1.AccessControl) {
			a.Geo.Subdivisions = []string{"us-CA"}
		},
		"geo subdivision long":    func(a *nodev1.AccessControl) { a.Geo.Subdivisions = []string{"US-" + strings.Repeat("x", 65)} },
		"geo subdivision control": func(a *nodev1.AccessControl) { a.Geo.Subdivisions = []string{"US-a\nb"} },
		"geo ASN 0":               func(a *nodev1.AccessControl) { a.Geo.Asns = []uint32{0} },
		"geo 257 countries": func(a *nodev1.AccessControl) {
			a.Geo.Countries = many(257, func(i int) string { return strings.ToUpper(letters(i % 676)) })
		},
		"geo prefix":       func(a *nodev1.AccessControl) { a.Geo.ExceptPathPrefixes = []string{""} },
		"WebSocket star":   func(a *nodev1.AccessControl) { a.Websocket.Origins = []string{"*"} },
		"WebSocket origin": func(a *nodev1.AccessControl) { a.Websocket.Origins = []string{"chat.test"} },
		"WebSocket 101 origins": func(a *nodev1.AccessControl) {
			a.Websocket.Origins = many(101, func(i int) string { return "https://" + letters(i) + ".test" })
		},
		"WebSocket idle 59":    func(a *nodev1.AccessControl) { a.Websocket.IdleTimeoutSeconds = 59 },
		"WebSocket idle 86401": func(a *nodev1.AccessControl) { a.Websocket.IdleTimeoutSeconds = 86401 },
		"frame options":        func(a *nodev1.AccessControl) { a.SecurityHeaders.FrameOptions = "ALLOW-FROM x" },
		"frame options case":   func(a *nodev1.AccessControl) { a.SecurityHeaders.FrameOptions = "deny" },
		"referrer policy":      func(a *nodev1.AccessControl) { a.SecurityHeaders.ReferrerPolicy = "always" },
		"permissions policy":   func(a *nodev1.AccessControl) { a.SecurityHeaders.PermissionsPolicy = strings.Repeat("a", 1025) },
		"permissions control":  func(a *nodev1.AccessControl) { a.SecurityHeaders.PermissionsPolicy = "a\r\nb" },
		"permissions non-ASCII": func(a *nodev1.AccessControl) {
			a.SecurityHeaders.PermissionsPolicy = "camera=(\"é\")"
		},
	}
	for name, change := range cases {
		cfg := accessConfig(t, change)
		if _, err := Build(cfg, Options{ExtraFeatures: geoFeaturesAll}); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: err %v", name, err)
		}
		// A disabled site's access control is checked too.
		vectorSite(cfg, "b").Enabled = false
		if _, err := Build(cfg, Options{ExtraFeatures: geoFeaturesAll}); !errors.Is(err, ErrRejected) {
			t.Errorf("%s (disabled site): err %v", name, err)
		}
	}
	// Bounds that are still accepted.
	for name, change := range map[string]func(*nodev1.AccessControl){
		"16 lists each": func(a *nodev1.AccessControl) {
			a.BlockListIds = many(16, func(i int) string { return "b-" + strconv.Itoa(i) })
			a.AllowListIds = many(16, func(i int) string { return "a-" + strconv.Itoa(i) })
		},
		"CORS star": func(a *nodev1.AccessControl) {
			a.Cors.AllowCredentials = false
			a.Cors.AllowedOrigins = []string{"*", "https://app.test"}
		},
		"CORS max age 0":       func(a *nodev1.AccessControl) { a.Cors.MaxAgeSeconds = 0 },
		"CORS max age 86400":   func(a *nodev1.AccessControl) { a.Cors.MaxAgeSeconds = 86400 },
		"WebSocket idle 60":    func(a *nodev1.AccessControl) { a.Websocket.IdleTimeoutSeconds = 60 },
		"WebSocket idle 86400": func(a *nodev1.AccessControl) { a.Websocket.IdleTimeoutSeconds = 86400 },
		"WebSocket any origin": func(a *nodev1.AccessControl) { a.Websocket.Origins = nil },
		"redirect URL":         func(a *nodev1.AccessControl) { a.Hotlink.RedirectUrl = "https://img.test/hotlink.png?x=1" },
		"redirect site path":   func(a *nodev1.AccessControl) { a.Hotlink.RedirectUrl = "/" + strings.Repeat("a", 2047) },
		"no redirect":          func(a *nodev1.AccessControl) { a.Hotlink.RedirectUrl = "" },
		"user agent 512":       func(a *nodev1.AccessControl) { a.UserAgents.Rules[0].Pattern = strings.Repeat("x", 512) },
		"user agent 8 stars":   func(a *nodev1.AccessControl) { a.UserAgents.Rules[0].Pattern = strings.Repeat("*", 8) },
		"permissions 1024":     func(a *nodev1.AccessControl) { a.SecurityHeaders.PermissionsPolicy = strings.Repeat("a", 1024) },
		"frame options DENY":   func(a *nodev1.AccessControl) { a.SecurityHeaders.FrameOptions = "DENY" },
		"subdivision 64 bytes": func(a *nodev1.AccessControl) { a.Geo.Subdivisions = []string{"US-" + strings.Repeat("x", 64)} },
		"ASN 4294967295":       func(a *nodev1.AccessControl) { a.Geo.Asns = []uint32{4294967295} },
		"all methods": func(a *nodev1.AccessControl) {
			a.Cors.AllowedMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
		},
		"hotlink default scope": func(a *nodev1.AccessControl) { a.Hotlink.Extensions, a.Hotlink.PathPrefixes = nil, nil },
	} {
		cfg := accessConfig(t, change)
		if _, err := Build(cfg, Options{ExtraFeatures: geoFeaturesAll}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestAccessControlGeoDatabases: geo lists need the node's GeoIP databases,
// as rules reading the same fields do.
func TestAccessControlGeoDatabases(t *testing.T) {
	for _, c := range []struct {
		geo     *nodev1.GeoAccess
		feature string
	}{
		{&nodev1.GeoAccess{Countries: []string{"NZ"}}, "geoip-country-v1"},
		{&nodev1.GeoAccess{Subdivisions: []string{"US-CA"}}, "geoip-subdivision-v1"},
		{&nodev1.GeoAccess{Asns: []uint32{64512}}, "geoip-asn-v1"},
	} {
		cfg := accessConfig(t, func(a *nodev1.AccessControl) { *a = nodev1.AccessControl{Geo: proto.CloneOf(c.geo)} })
		others := slices.DeleteFunc(slices.Clone(geoFeaturesAll), func(f string) bool { return f == c.feature })
		if _, err := Build(cfg, Options{ExtraFeatures: others}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), c.feature) {
			t.Errorf("%s missing: err %v", c.feature, err)
		}
		if _, err := Build(cfg, Options{ExtraFeatures: []string{c.feature}}); err != nil {
			t.Errorf("%s: %v", c.feature, err)
		}
	}
}

// TestCanonicalAccessControl: shuffled sets canonicalize to the same bytes;
// user agent rules and CORS methods keep their order (it is meaningful).
func TestCanonicalAccessControl(t *testing.T) {
	sorted := fullAccessControl()
	canonicalizeAccessControl(sorted)
	shuffled := fullAccessControl()
	reverse := func(lists ...[]string) {
		for _, l := range lists {
			slices.Reverse(l)
		}
	}
	reverse(shuffled.BlockListIds, shuffled.AllowListIds, shuffled.Hotlink.Allowed, shuffled.Hotlink.Denied, shuffled.Hotlink.Extensions,
		shuffled.UserAgents.PathPrefixes, shuffled.Cors.AllowedOrigins, shuffled.Cors.AllowedHeaders, shuffled.Geo.Countries,
		shuffled.Geo.Subdivisions, shuffled.Websocket.Origins)
	shuffled.AllowListIds = append(shuffled.AllowListIds, "l-allow")
	shuffled.Hotlink.PathPrefixes = append(shuffled.Hotlink.PathPrefixes, "/a/", "/dl/")
	shuffled.Hotlink.ExcludePathPrefixes = append([]string{"/z/"}, shuffled.Hotlink.ExcludePathPrefixes...)
	shuffled.UserAgents.ExcludePathPrefixes = append(shuffled.UserAgents.ExcludePathPrefixes, "/robots.txt")
	shuffled.Cors.ExposedHeaders = append(shuffled.Cors.ExposedHeaders, "A-Count", "X-Total")
	shuffled.Cors.PathPrefixes = append([]string{"/v2/"}, shuffled.Cors.PathPrefixes...)
	shuffled.Geo.Asns = []uint32{64512, 13335, 64512, 9}
	shuffled.Geo.PathPrefixes = append(shuffled.Geo.PathPrefixes, "/")
	shuffled.Geo.ExceptPathPrefixes = append(shuffled.Geo.ExceptPathPrefixes, "/a", "/health")
	shuffled.Websocket.Origins = append(shuffled.Websocket.Origins, "https://chat.test")
	canonicalizeAccessControl(shuffled)
	if !slices.Equal(shuffled.Geo.Asns, []uint32{9, 13335, 64512}) {
		t.Fatalf("asns %v", shuffled.Geo.Asns)
	}
	if !slices.Equal(shuffled.Hotlink.Allowed, []string{"*.friend.test", ".deep.test", "10.0.0.1", "a_b.test"}) {
		t.Fatalf("allowed %v", shuffled.Hotlink.Allowed)
	}
	// The extra entries aside, both are the same.
	shuffled.Hotlink.PathPrefixes = slices.DeleteFunc(shuffled.Hotlink.PathPrefixes, func(s string) bool { return s == "/a/" })
	shuffled.Hotlink.ExcludePathPrefixes = slices.DeleteFunc(shuffled.Hotlink.ExcludePathPrefixes, func(s string) bool { return s == "/z/" })
	shuffled.Cors.ExposedHeaders = slices.DeleteFunc(shuffled.Cors.ExposedHeaders, func(s string) bool { return s == "A-Count" })
	shuffled.Cors.PathPrefixes = slices.DeleteFunc(shuffled.Cors.PathPrefixes, func(s string) bool { return s == "/v2/" })
	shuffled.Geo.Asns = slices.DeleteFunc(shuffled.Geo.Asns, func(n uint32) bool { return n == 9 })
	shuffled.Geo.ExceptPathPrefixes = slices.DeleteFunc(shuffled.Geo.ExceptPathPrefixes, func(s string) bool { return s == "/a" })
	if !proto.Equal(sorted, shuffled) {
		t.Fatalf("canonical forms differ\n%v\n%v", sorted, shuffled)
	}

	// In whole configurations: shuffled sets give the same hash; the order of
	// user agent rules and CORS methods changes it.
	hash := func(change func(*nodev1.AccessControl)) string {
		t.Helper()
		cfg, _ := v0270Vector(t)
		a := fullAccessControl()
		change(a)
		vectorSite(cfg, "b").AccessControl = a
		h, err := ContentHash(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	base := hash(func(*nodev1.AccessControl) {})
	if h := hash(func(a *nodev1.AccessControl) {
		reverse(a.BlockListIds, a.AllowListIds, a.Hotlink.Allowed, a.Hotlink.Denied, a.Hotlink.Extensions, a.Cors.AllowedOrigins,
			a.Cors.AllowedHeaders, a.Geo.Countries, a.Geo.Subdivisions, a.Websocket.Origins)
		a.Hotlink.Denied = append(a.Hotlink.Denied, "evil.test")
		slices.Reverse(a.Geo.Asns)
	}); h != base {
		t.Errorf("shuffled sets change the hash")
	}
	if hash(func(a *nodev1.AccessControl) { slices.Reverse(a.UserAgents.Rules) }) == base {
		t.Errorf("the order of user agent rules does not change the hash")
	}
	if hash(func(a *nodev1.AccessControl) { slices.Reverse(a.Cors.AllowedMethods) }) == base {
		t.Errorf("the order of CORS methods does not change the hash")
	}
	if hash(func(a *nodev1.AccessControl) { a.Websocket.IdleTimeoutSeconds = 600 }) == base {
		t.Errorf("the idle timeout does not change the hash")
	}
	// A site without access control encodes as before (no field 30).
	cfg, _ := v0270Vector(t)
	b1, _ := CanonicalBytes(cfg)
	vectorSite(cfg, "b").AccessControl = nil
	b2, _ := CanonicalBytes(cfg)
	if string(b1) != string(b2) {
		t.Errorf("nil access control changes the encoding")
	}
}

// accessVectors is test/lua/access_vectors.json, a copy of the console's
// packages/rule-engine/test/access_vectors.json: the stored forms the
// console's normalizers produce are the ones configir accepts.
type accessVectors struct {
	NormalizeHostForm []struct {
		Input  string  `json:"input"`
		Output *string `json:"output"`
	} `json:"normalizeHostForm"`
	NormalizeOriginForm []struct {
		Input  string  `json:"input"`
		Star   bool    `json:"star"`
		Output *string `json:"output"`
	} `json:"normalizeOriginForm"`
	ValidUserAgentPattern []struct {
		Pattern string `json:"pattern"`
		Valid   bool   `json:"valid"`
	} `json:"validUserAgentPattern"`
}

func TestAccessFormsVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "lua", "access_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v accessVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.NormalizeHostForm) < 20 || len(v.NormalizeOriginForm) < 20 || len(v.ValidUserAgentPattern) < 10 {
		t.Fatalf("vectors not read")
	}
	for _, c := range v.NormalizeHostForm {
		if c.Output != nil && !ValidHostForm(*c.Output) {
			t.Errorf("host form %q (from %q) refused", *c.Output, c.Input)
		}
		if got, want := ValidHostForm(c.Input), c.Output != nil && *c.Output == c.Input; got != want {
			t.Errorf("host form %q: valid %v, want %v", c.Input, got, want)
		}
	}
	for _, c := range v.NormalizeOriginForm {
		if c.Input == "*" {
			continue // "*" is checked by the CORS settings
		}
		got, ok := NormalizeOriginForm(c.Input)
		if (c.Output == nil) != !ok || (ok && got != *c.Output) {
			t.Errorf("origin form %q: %q %v, want %v", c.Input, got, ok, c.Output)
		}
		if c.Output != nil && !ValidOriginForm(*c.Output) {
			t.Errorf("origin form %q refused", *c.Output)
		}
	}
	for _, c := range v.ValidUserAgentPattern {
		if ValidUserAgentPattern(c.Pattern) != c.Valid {
			t.Errorf("user agent pattern %q: want %v", c.Pattern, c.Valid)
		}
	}
}
