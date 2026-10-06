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

// v0230Vector reads testdata/content_hash_vector_v0230.json, a copy of the
// console's fixture (packages/config-compiler/test/fixtures): listeners 80,
// 443, 8081 and 9443, a site on 8081 and 9443 with a 308 redirect to 9443
// and excluded domains, a rule on ip.peer, the client address header mode
// and layer-4 applications with a port range on the arriving port and with
// TLS; site ports, excluded domains, trusted CIDRs (with a duplicate) and
// required_features unsorted. Its canonical_hex and content_hash come from
// protobuf-es.
func v0230Vector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_v0230.json"))
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

// TestContentHashVectorV0230 checks the proto v0.23.0 vector shared with
// the console: Go's canonical form encodes to the console's bytes and
// hash, sorts the new sets, every v0.23.0 field counts, and configir
// accepts the configuration.
func TestContentHashVectorV0230(t *testing.T) {
	cfg, v := v0230Vector(t)
	if !slices.Equal(vectorSite(cfg, "a").GetPorts(), []uint32{9443, 8081}) || len(cfg.GetClientAddress().GetTrustedCidrs()) != 3 {
		t.Fatalf("vector sets are already canonical: %v %v", vectorSite(cfg, "a").GetPorts(), cfg.GetClientAddress().GetTrustedCidrs())
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
	Canonicalize(cfg)
	a := vectorSite(cfg, "a")
	if !slices.Equal(a.GetPorts(), []uint32{8081, 9443}) || !slices.Equal(a.GetTls().GetRedirectExcludedDomains(), []string{"*.w.test", "b.test"}) ||
		!slices.Equal(cfg.GetClientAddress().GetTrustedCidrs(), []string{"10.0.0.0/8", "192.0.2.0/24"}) {
		t.Errorf("canonical sets %v %v %v", a.GetPorts(), a.GetTls().GetRedirectExcludedDomains(), cfg.GetClientAddress().GetTrustedCidrs())
	}
	if want := []string{"client-ip-v1", "edge-ports-v1", "http3-v1", "l4-v1", "l4-v2", "rules-v1", "tls-v1"}; !slices.Equal(cfg.RequiredFeatures, want) {
		t.Errorf("canonical required features %v, want %v", cfg.RequiredFeatures, want)
	}

	// Every v0.23.0 field is part of the canonical bytes.
	app := func(c *nodev1.NodeConfig, id string) *nodev1.L4App {
		for _, a := range c.L4Apps {
			if a.Id == id {
				return a
			}
		}
		t.Fatalf("no application %s", id)
		return nil
	}
	for name, change := range map[string]func(*nodev1.NodeConfig){
		"site ports":       func(c *nodev1.NodeConfig) { vectorSite(c, "a").Ports = []uint32{8081} },
		"redirect status":  func(c *nodev1.NodeConfig) { vectorSite(c, "a").Tls.RedirectStatus = 307 },
		"redirect port":    func(c *nodev1.NodeConfig) { vectorSite(c, "a").Tls.RedirectPort = 0 },
		"excluded domains": func(c *nodev1.NodeConfig) { vectorSite(c, "a").Tls.RedirectExcludedDomains = nil },
		"client header":    func(c *nodev1.NodeConfig) { c.ClientAddress.Header = "x-real-ip" },
		"trusted CIDRs":    func(c *nodev1.NodeConfig) { c.ClientAddress.TrustedCidrs = []string{"10.0.0.0/8"} },
		"port end":         func(c *nodev1.NodeConfig) { app(c, "range").PortEnd = 20010 },
		"origin port":      func(c *nodev1.NodeConfig) { app(c, "range").Origins[0].Port = 1 },
		"L4 certificate":   func(c *nodev1.NodeConfig) { app(c, "tls").CertificateId = "" },
		"L4 TLS version":   func(c *nodev1.NodeConfig) { app(c, "tls").TlsMinimumVersion = "1.2" },
	} {
		c, _ := v0230Vector(t)
		change(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}

	p, err := Build(cfg, Options{ClusterID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	if p.ClientAddress == nil || p.ClientAddress.Header != "x-forwarded-for" || len(p.L4Apps) != 2 || p.L4Apps[0].PortEnd != 20099 {
		t.Fatalf("plan = %+v %+v", p.ClientAddress, p.L4Apps)
	}
}
