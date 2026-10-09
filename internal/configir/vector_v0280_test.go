package configir

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// v0280Vector reads testdata/content_hash_vector_v0280.json, a copy of the
// console's fixture: a site with every part of Site.access_control and a
// site without; sites, IP lists and the access control's set lists
// reversed, user agent rules and CORS methods in their order.
func v0280Vector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_v0280.json"))
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

// TestContentHashVectorV0280 checks the proto v0.28.0 vector shared with
// the console: the access control's sets sorted (ASNs as numbers), user
// agent rules and CORS methods kept in order, every new field in the hash,
// and the plan.
func TestContentHashVectorV0280(t *testing.T) {
	cfg, v := v0280Vector(t)
	if cfg.GetSites()[0].GetId() != "b" || vectorSite(cfg, "a").GetAccessControl().GetBlockListIds()[0] != "list-block-2" {
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
	ac := func(c *nodev1.NodeConfig) *nodev1.AccessControl { return vectorSite(c, "a").AccessControl }
	for name, change := range map[string]func(*nodev1.NodeConfig){
		// Allow rules win whatever their place, but the order is the
		// operator's: kept, so it changes the hash.
		"user agent order": func(c *nodev1.NodeConfig) {
			r := ac(c).UserAgents.Rules
			r[0], r[1] = r[1], r[0]
		},
		// The methods are sent in this order.
		"method order": func(c *nodev1.NodeConfig) {
			m := ac(c).Cors.AllowedMethods
			m[0], m[1] = m[1], m[0]
		},
		"block list":    func(c *nodev1.NodeConfig) { ac(c).BlockListIds = ac(c).BlockListIds[1:] },
		"redirect":      func(c *nodev1.NodeConfig) { ac(c).Hotlink.RedirectUrl = "" },
		"check origin":  func(c *nodev1.NodeConfig) { ac(c).Hotlink.CheckOrigin = false },
		"credentials":   func(c *nodev1.NodeConfig) { ac(c).Cors.AllowCredentials = false },
		"max age":       func(c *nodev1.NodeConfig) { ac(c).Cors.MaxAgeSeconds = 0 },
		"keep":          func(c *nodev1.NodeConfig) { ac(c).Cors.KeepOriginHeaders = false },
		"to origin":     func(c *nodev1.NodeConfig) { ac(c).Cors.PreflightToOrigin = true },
		"allow only":    func(c *nodev1.NodeConfig) { ac(c).Geo.AllowOnly = true },
		"asn":           func(c *nodev1.NodeConfig) { ac(c).Geo.Asns = []uint32{64512} },
		"idle":          func(c *nodev1.NodeConfig) { ac(c).Websocket.IdleTimeoutSeconds = 0 },
		"frame options": func(c *nodev1.NodeConfig) { ac(c).SecurityHeaders.FrameOptions = "DENY" },
		"hide server":   func(c *nodev1.NodeConfig) { ac(c).SecurityHeaders.HideServer = false },
		"no part":       func(c *nodev1.NodeConfig) { ac(c).SecurityHeaders = nil },
	} {
		c, _ := v0280Vector(t)
		change(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}
	// Reordering the sets once more changes nothing.
	c, _ := v0280Vector(t)
	slices.Reverse(ac(c).Hotlink.Extensions)
	slices.Reverse(ac(c).Geo.Asns)
	slices.Reverse(ac(c).Cors.ExposedHeaders)
	if hc, _ := ContentHash(c); hc != h {
		t.Errorf("reordered sets change the hash")
	}

	Canonicalize(cfg)
	p, err := Build(cfg, Options{ClusterID: cfg.GetClusterId(), ExtraFeatures: []string{"geoip-country-v1", "geoip-city-v1", "geoip-subdivision-v1", "geoip-asn-v1"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sites) != 2 || p.Sites[0].ID != "a" || p.Sites[1].AccessControl != nil {
		t.Fatalf("plan sites %+v", p.Sites)
	}
	a := p.Sites[0].AccessControl
	if a == nil || !slices.Equal(a.BlockListIDs, []string{"list-block-1", "list-block-2"}) || !slices.Equal(a.Geo.ASNs, []uint32{64512, 64513}) ||
		!slices.Equal(a.CORS.AllowedMethods, []string{"GET", "POST", "OPTIONS"}) || a.UserAgents.Rules[1] != (UserAgentRule{Pattern: "*Googlebot*", Allow: true}) ||
		a.UserAgents.Rules[2] != (UserAgentRule{}) || a.WebSocket.IdleTimeoutSeconds != 600 || a.Hotlink.RedirectURL != "/hotlink.png" {
		t.Fatalf("access control %+v", a)
	}
}
