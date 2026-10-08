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

// v0260Vector reads testdata/content_hash_vector_v0260.json, a copy of the
// console's fixture: a site with three certificates (additional ones in
// the site's order), required client certificates and a rule reading
// tls.client.verified, a second site with one certificate, and session
// ticket keys; sites, ticket keys and required_features reversed.
func v0260Vector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_v0260.json"))
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

// TestContentHashVectorV0260 checks the proto v0.26.0 vector shared with
// the console: session ticket keys sorted by id, additional certificates
// kept in the site's order, every new field in the hash, and the plan.
func TestContentHashVectorV0260(t *testing.T) {
	cfg, v := v0260Vector(t)
	if cfg.GetSites()[0].GetId() != "b" || cfg.GetSessionTicketKeys()[0].GetId() != "k3" {
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
	for name, change := range map[string]func(*nodev1.NodeConfig){
		// The site's order is the handshake's tie-break: never sorted.
		"additional order": func(c *nodev1.NodeConfig) {
			ids := vectorSite(c, "a").AdditionalCertificateIds
			ids[0], ids[1] = ids[1], ids[0]
		},
		"mode": func(c *nodev1.NodeConfig) {
			vectorSite(c, "a").ClientCertificate.Mode = nodev1.ClientCertificateMode_CLIENT_CERTIFICATE_MODE_OPTIONAL
		},
		"depth":   func(c *nodev1.NodeConfig) { vectorSite(c, "a").ClientCertificate.Depth = 3 },
		"forward": func(c *nodev1.NodeConfig) { vectorSite(c, "a").ClientCertificate.ForwardHeaders = false },
		"ca":      func(c *nodev1.NodeConfig) { vectorSite(c, "a").ClientCertificate.CaPem += "\n" },
		"role":    func(c *nodev1.NodeConfig) { c.SessionTicketKeys[0].Role = "previous" },
		"keys":    func(c *nodev1.NodeConfig) { c.SessionTicketKeys = c.SessionTicketKeys[1:] },
	} {
		c, _ := v0260Vector(t)
		change(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}
	// Reordered ticket keys hash alike.
	c, _ := v0260Vector(t)
	slices.Reverse(c.SessionTicketKeys)
	if hc, _ := ContentHash(c); hc != h {
		t.Errorf("ticket key order changes the hash")
	}

	Canonicalize(cfg)
	p, err := Build(cfg, Options{ClusterID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sites) != 2 || p.Sites[0].ID != "a" {
		t.Fatalf("plan sites %v", p.Sites)
	}
	a := p.Sites[0]
	if !slices.Equal(a.CertificateIDs(), []string{"cert-ec", "cert-rsa", "cert-b"}) {
		t.Fatalf("certificates %v", a.CertificateIDs())
	}
	cc := a.ClientCertificate
	if cc == nil || cc.Mode != ClientCertRequired || cc.Depth != 2 || !cc.ForwardHeaders || cc.CAPEM != vectorSite(cfg, "a").GetClientCertificate().GetCaPem() {
		t.Fatalf("client certificate %+v", cc)
	}
	if p.Sites[1].ClientCertificate != nil || p.Sites[1].AdditionalCertificateIDs != nil {
		t.Fatalf("site b %+v", p.Sites[1])
	}
	if want := []SessionTicketKeyRef{{"k1", "previous"}, {"k2", "current"}, {"k3", "next"}}; !slices.Equal(p.SessionTicketKeys, want) {
		t.Fatalf("ticket keys %v", p.SessionTicketKeys)
	}
	if want := []string{"k2", "k1", "k3"}; !slices.Equal(p.SessionTicketKeyIDs(), want) {
		t.Fatalf("ticket key order %v, want %v", p.SessionTicketKeyIDs(), want)
	}
	if len(p.Warnings) != 0 {
		t.Fatalf("warnings %v", p.Warnings)
	}
	// The JSON for the data plane carries the new fields.
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var table map[string]any
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	if ids, _ := table["additional_certificate_ids"].([]any); len(ids) != 2 || ids[0] != "cert-rsa" {
		t.Fatalf("additional_certificate_ids %v", table["additional_certificate_ids"])
	}
	if c, _ := table["client_certificate"].(map[string]any); c["mode"] != "required" || c["depth"] != 2.0 || c["forward_headers"] != true || c["ca_pem"] == "" {
		t.Fatalf("client_certificate %v", table["client_certificate"])
	}
}
