package configir

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// testOriginCA is a throwaway Origin CA: its certificate, key and a CRL of
// the given serials valid until nextUpdate, PEM encoded the console's way.
type testOriginCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newTestOriginCA(t *testing.T) testOriginCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Edgeweir Origin CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(20 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testOriginCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (ca testOriginCA) crl(t *testing.T, label string, nextUpdate time.Time, serials ...int64) string {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: big.NewInt(s), RevocationTime: time.Now()})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: nextUpdate,
		RevokedCertificateEntries: entries,
	}, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der}))
}

var fp = strings.Repeat("ab", 32)

// originProtectedConfig has site a presenting client certificate occ and
// verifying against the Origin CA, and site b with neither.
func originProtectedConfig(t *testing.T, ca testOriginCA) *nodev1.NodeConfig {
	t.Helper()
	a := site("a", "a.test")
	a.OriginPool.Origins[0].Scheme = nodev1.OriginScheme_ORIGIN_SCHEME_HTTPS
	a.OriginPool.ClientCertificateId = "occ"
	a.OriginPool.TlsTrust = nodev1.OriginTlsTrust_ORIGIN_TLS_TRUST_ORIGIN_CA
	return &nodev1.NodeConfig{
		Revision: 1, ClusterId: "c1",
		Sites:                    []*nodev1.Site{a, site("b", "b.test")},
		OriginClientCertificates: []*nodev1.CertificateRef{{Id: "occ", Sha256Fingerprint: fp}},
		OriginCa:                 &nodev1.OriginCa{CertificatePem: ca.pem, CrlPem: ca.crl(t, "X509 CRL", time.Now().Add(time.Hour), 7, 0x1f)},
		RequiredFeatures:         []string{FeatureOriginMTLS, FeatureOriginCA},
	}
}

func TestBuildOriginProtection(t *testing.T) {
	if !slices.Contains(SupportedFeatures, FeatureOriginMTLS) || !slices.Contains(SupportedFeatures, FeatureOriginCA) {
		t.Fatal("origin protection features are not announced")
	}
	ca := newTestOriginCA(t)
	p, err := Build(originProtectedConfig(t, ca), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if p.OriginClientCertificates["occ"] != fp {
		t.Fatalf("origin client certificates %v", p.OriginClientCertificates)
	}
	if p.OriginCA == nil || !p.OriginCA.Certificate.Equal(ca.cert) {
		t.Fatal("origin CA not built")
	}
	for serial, want := range map[int64]bool{7: true, 0x1f: true, 8: false} {
		if got := p.OriginCA.IsRevoked(&x509.Certificate{SerialNumber: big.NewInt(serial)}); got != want {
			t.Errorf("serial %d revoked = %v, want %v", serial, got, want)
		}
	}
	a, b := p.Sites[0], p.Sites[1]
	if a.OriginTrust != TrustOriginCA || a.OriginClientCertID != "occ" {
		t.Fatalf("site a: trust %q, client certificate %q", a.OriginTrust, a.OriginClientCertID)
	}
	if b.OriginTrust != "" || b.OriginClientCertID != "" {
		t.Fatalf("site b: trust %q, client certificate %q", b.OriginTrust, b.OriginClientCertID)
	}
	// The data plane gets the trust and, once the agent fills it in, the files.
	a.OriginClientCert = &OriginClientCert{Ref: "occ/" + fp, CertPath: "/c.crt", KeyPath: "/c.key"}
	raw, _ := json.Marshal(a)
	for _, want := range []string{`"tls_trust":"origin_ca"`, `"origin_client_cert":{"ref":"occ/` + fp + `","crt":"/c.crt","key":"/c.key"}`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("site JSON lacks %s: %s", want, raw)
		}
	}
	if raw, _ := json.Marshal(b); strings.Contains(string(raw), "tls_trust") || strings.Contains(string(raw), "origin_client_cert") {
		t.Errorf("site b JSON: %s", raw)
	}
}

func TestBuildOriginProtectionRejects(t *testing.T) {
	ca := newTestOriginCA(t)
	other := newTestOriginCA(t)
	for name, change := range map[string]func(*nodev1.NodeConfig){
		"trust without the CA":       func(c *nodev1.NodeConfig) { c.OriginCa = nil },
		"trust without verification": func(c *nodev1.NodeConfig) { c.Sites[0].OriginPool.SkipTlsVerify = true },
		"trust with an S3 origin": func(c *nodev1.NodeConfig) {
			c.Sites[0].OriginPool.Origins[0].S3 = &nodev1.S3Auth{Region: "r", CredentialId: "k"}
		},
		"unknown client certificate": func(c *nodev1.NodeConfig) { c.Sites[0].OriginPool.ClientCertificateId = "other" },
		"bad fingerprint":            func(c *nodev1.NodeConfig) { c.OriginClientCertificates[0].Sha256Fingerprint = "AB" },
		"bad id":                     func(c *nodev1.NodeConfig) { c.OriginClientCertificates[0].Id = "a b" },
		"duplicate client certificates": func(c *nodev1.NodeConfig) {
			c.OriginClientCertificates = append(c.OriginClientCertificates, c.OriginClientCertificates[0])
		},
		"unknown trust":     func(c *nodev1.NodeConfig) { c.Sites[0].OriginPool.TlsTrust = 9 },
		"CRL of another CA": func(c *nodev1.NodeConfig) { c.OriginCa.CrlPem = other.crl(t, "X509 CRL", time.Now().Add(time.Hour)) },
		// nginx's *_ssl_crl reads the "X509 CRL" label only.
		"CRL label":   func(c *nodev1.NodeConfig) { c.OriginCa.CrlPem = ca.crl(t, "CRL", time.Now().Add(time.Hour)) },
		"expired CRL": func(c *nodev1.NodeConfig) { c.OriginCa.CrlPem = ca.crl(t, "X509 CRL", time.Now().Add(-time.Minute)) },
		"no CRL":      func(c *nodev1.NodeConfig) { c.OriginCa.CrlPem = "" },
		"no CA":       func(c *nodev1.NodeConfig) { c.OriginCa.CertificatePem = "" },
		"two CAs":     func(c *nodev1.NodeConfig) { c.OriginCa.CertificatePem += other.pem },
		"leaf as CA": func(c *nodev1.NodeConfig) {
			leaf := *ca.cert
			leaf.IsCA = false
			der, _ := x509.CreateCertificate(rand.Reader, &leaf, &leaf, &ca.key.PublicKey, ca.key)
			c.OriginCa.CertificatePem = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		},
	} {
		c := originProtectedConfig(t, ca)
		change(c)
		if _, err := Build(c, Options{}); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: err = %v, want rejection", name, err)
		}
	}
	// Disabled sites are checked too.
	c := originProtectedConfig(t, ca)
	c.Sites[0].Enabled = false
	c.OriginCa = nil
	if _, err := Build(c, Options{}); !errors.Is(err, ErrRejected) {
		t.Errorf("disabled site trusting a missing CA: err = %v", err)
	}
}

func TestDiffCarriesOriginProtection(t *testing.T) {
	ca := newTestOriginCA(t)
	base := withHash(t, &nodev1.NodeConfig{Revision: 1, ClusterId: "c1", Sites: []*nodev1.Site{site("b", "b.test")}})
	target := originProtectedConfig(t, ca)
	target.Revision = 2
	target.OriginClientCertificates = append(target.OriginClientCertificates, &nodev1.CertificateRef{Id: "a-first", Sha256Fingerprint: fp})
	withHash(t, target)
	got, err := ApplyDiff(base, Diff(base, target))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, target) {
		t.Fatal("diff loses origin protection")
	}
	back, err := ApplyDiff(target, Diff(target, withHash(t, &nodev1.NodeConfig{Revision: 3, ClusterId: "c1", Sites: []*nodev1.Site{site("b", "b.test")}})))
	if err != nil {
		t.Fatal(err)
	}
	if back.GetOriginCa() != nil || len(back.GetOriginClientCertificates()) != 0 {
		t.Fatal("diff does not clear origin protection")
	}
}

// TestContentHashVectorV130 checks the proto v1.3.0 vector shared with the
// console: origin client certificates sorted by id, the Origin CA and the
// pools' trust and certificate in the hash, and the plan.
func TestContentHashVectorV130(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_v130.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v hashVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	load := func() *nodev1.NodeConfig {
		cfg := &nodev1.NodeConfig{}
		if err := protojson.Unmarshal(v.Config, cfg); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	cfg := load()
	if cfg.GetSites()[0].GetId() != "d" {
		t.Fatal("vector is already canonical")
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
	for name, change := range map[string]func(*nodev1.NodeConfig){
		"client certificate": func(c *nodev1.NodeConfig) { vectorSite(c, "a").OriginPool.ClientCertificateId = "" },
		"trust":              func(c *nodev1.NodeConfig) { vectorSite(c, "b").OriginPool.TlsTrust = 0 },
		"CRL":                func(c *nodev1.NodeConfig) { c.OriginCa.CrlPem += "\n" },
		"reference":          func(c *nodev1.NodeConfig) { c.OriginClientCertificates[0].Sha256Fingerprint = fp },
	} {
		c := load()
		change(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}
	Canonicalize(cfg)
	p, err := Build(cfg, Options{ClusterID: cfg.GetClusterId()})
	if err != nil {
		t.Fatal(err)
	}
	trust := map[string]string{}
	certs := map[string]string{}
	for _, s := range p.Sites {
		trust[s.ID], certs[s.ID] = s.OriginTrust, s.OriginClientCertID
	}
	if trust["b"] != TrustOriginCA || trust["c"] != TrustOriginCA || trust["a"] != "" || trust["d"] != "" {
		t.Errorf("trust %v", trust)
	}
	if certs["a"] != "occ-2" || certs["c"] != "occ-2" || certs["b"] != "" || certs["d"] != "" {
		t.Errorf("client certificates %v", certs)
	}
}
