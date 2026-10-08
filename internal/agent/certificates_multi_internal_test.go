package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

// keyedCertificate is a self-signed certificate for names with key.
func keyedCertificate(t *testing.T, key crypto.Signer, names ...string) configir.Certificate {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return configir.Certificate{
		ChainPEM:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		Fingerprint:   hex.EncodeToString(sum[:]),
	}
}

func ecKey(t *testing.T, curve elliptic.Curve) crypto.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func rsaKey(t *testing.T) crypto.Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// TestAttachMultipleCertificates: the site's certificates together cover
// its domains; each carries its names, key type and curve, in the site's
// order with the first one also as `certificate`; sites with one
// certificate keep the old shape.
func TestAttachMultipleCertificates(t *testing.T) {
	ec := keyedCertificate(t, ecKey(t, elliptic.P256()), "a.test", "*.a.test")
	rsaCert := keyedCertificate(t, rsaKey(t), "A.test")
	other := keyedCertificate(t, ecKey(t, elliptic.P384()), "b.test", "*.wild.test")
	a := &Agent{certificates: map[string]configir.Certificate{
		"ec/" + ec.Fingerprint: ec, "rsa/" + rsaCert.Fingerprint: rsaCert, "other/" + other.Fingerprint: other,
	}}
	refs := map[string]string{"ec": ec.Fingerprint, "rsa": rsaCert.Fingerprint, "other": other.Fingerprint}
	plan := func(domains ...configir.Domain) *configir.Plan {
		return &configir.Plan{
			Certificates: refs,
			Sites: []configir.Site{
				{ID: "multi", CertificateID: "ec", AdditionalCertificateIDs: []string{"rsa", "other"}, Domains: domains},
				{ID: "single", CertificateID: "ec", Domains: []configir.Domain{{Name: "a.test"}}},
			},
		}
	}
	// b.test and *.wild.test only through the third certificate.
	p := plan(configir.Domain{Name: "a.test"}, configir.Domain{Name: "x.a.test"}, configir.Domain{Name: "b.test"}, configir.Domain{Name: "wild.test", Wildcard: true})
	if err := a.attachCertificates(p); err != nil {
		t.Fatal(err)
	}
	multi := p.Sites[0]
	if len(multi.Certificates) != 3 || multi.Certificate == nil || multi.Certificate.Fingerprint != ec.Fingerprint {
		t.Fatalf("certificates %+v", multi.Certificates)
	}
	for i, want := range []struct {
		fingerprint, keyType, curve string
		names                       []string
	}{
		{ec.Fingerprint, "ec", "P-256", []string{"a.test", "*.a.test"}},
		{rsaCert.Fingerprint, "rsa", "", []string{"a.test"}},
		{other.Fingerprint, "ec", "P-384", []string{"b.test", "*.wild.test"}},
	} {
		got := multi.Certificates[i]
		if got.Fingerprint != want.fingerprint || got.KeyType != want.keyType || got.Curve != want.curve || !slices.Equal(got.DNSNames, want.names) || got.PrivateKeyPEM == "" {
			t.Errorf("certificate %d: %s %s %s %v", i, got.Fingerprint[:8], got.KeyType, got.Curve, got.DNSNames)
		}
	}
	single := p.Sites[1]
	if single.Certificates != nil || single.Certificate.DNSNames != nil || single.Certificate.KeyType != "ec" || single.Certificate.Curve != "P-256" {
		t.Fatalf("single %+v", single.Certificate)
	}
	// The material in the agent's store stays unchanged.
	if stored := a.certificates["ec/"+ec.Fingerprint]; stored.KeyType != "" || stored.DNSNames != nil {
		t.Fatalf("stored certificate changed: %+v", stored)
	}

	// A domain none of them covers, an uncovered wildcard.
	for _, d := range []configir.Domain{{Name: "c.test"}, {Name: "b.test", Wildcard: true}} {
		err := a.attachCertificates(plan(configir.Domain{Name: "a.test"}, d))
		if err == nil || !strings.Contains(err.Error(), "does not cover") {
			t.Errorf("%+v: err = %v", d, err)
		}
	}
	// A missing additional certificate.
	p = plan(configir.Domain{Name: "a.test"})
	delete(p.Certificates, "other")
	if err := a.attachCertificates(p); err == nil {
		t.Fatal("missing additional certificate attached")
	}
}

// TestSessionContext: the context is SHA-256 of the documented input and
// changes with the site, its minimum version, client certificate setting
// and certificates (their order included).
func TestSessionContext(t *testing.T) {
	ec := keyedCertificate(t, ecKey(t, elliptic.P256()), "a.test")
	rsaCert := keyedCertificate(t, rsaKey(t), "a.test")
	a := &Agent{certificates: map[string]configir.Certificate{"ec/" + ec.Fingerprint: ec, "rsa/" + rsaCert.Fingerprint: rsaCert}}
	refs := map[string]string{"ec": ec.Fingerprint, "rsa": rsaCert.Fingerprint}
	ca := "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"
	base := func() configir.Site {
		return configir.Site{
			ID: "s1", CertificateID: "ec", AdditionalCertificateIDs: []string{"rsa"}, Domains: []configir.Domain{{Name: "a.test"}},
			TLS:               &configir.TLSOptions{MinimumVersion: "1.3"},
			ClientCertificate: &configir.ClientCertificate{Mode: configir.ClientCertRequired, CAPEM: ca, Depth: 2},
		}
	}
	contextOf := func(site configir.Site) string {
		t.Helper()
		p := &configir.Plan{Certificates: refs, Sites: []configir.Site{site}}
		if err := a.attachCertificates(p); err != nil {
			t.Fatal(err)
		}
		return p.Sites[0].TLSSessionContext
	}
	got := contextOf(base())
	caSum := sha256.Sum256([]byte(ca))
	want := sha256.Sum256([]byte("edgeweir-tls-v1\x00s1\x001.3\x00required\x00" + hex.EncodeToString(caSum[:]) + "\x002\x00" + ec.Fingerprint + "," + rsaCert.Fingerprint))
	if got != hex.EncodeToString(want[:]) {
		t.Fatalf("context %s, want %x", got, want)
	}
	// Without TLS options and client certificates: version 1.2, mode off.
	plain := base()
	plain.TLS, plain.ClientCertificate, plain.AdditionalCertificateIDs = nil, nil, nil
	want = sha256.Sum256([]byte("edgeweir-tls-v1\x00s1\x001.2\x00off\x00\x000\x00" + ec.Fingerprint))
	if got := contextOf(plain); got != hex.EncodeToString(want[:]) {
		t.Fatalf("plain context %s, want %x", got, want)
	}
	seen := map[string]string{got: "base"}
	for name, change := range map[string]func(*configir.Site){
		"site":          func(s *configir.Site) { s.ID = "s2" },
		"minimum":       func(s *configir.Site) { s.TLS.MinimumVersion = "1.2" },
		"mode":          func(s *configir.Site) { s.ClientCertificate.Mode = configir.ClientCertOptional },
		"ca":            func(s *configir.Site) { s.ClientCertificate.CAPEM += "\n" },
		"depth":         func(s *configir.Site) { s.ClientCertificate.Depth = 3 },
		"off":           func(s *configir.Site) { s.ClientCertificate = nil },
		"one":           func(s *configir.Site) { s.AdditionalCertificateIDs = nil },
		"order":         func(s *configir.Site) { s.CertificateID, s.AdditionalCertificateIDs = "rsa", []string{"ec"} },
		"no header fwd": func(s *configir.Site) { s.ClientCertificate.ForwardHeaders = true },
	} {
		s := base()
		change(&s)
		c := contextOf(s)
		if name == "no header fwd" {
			// Forwarding headers is a request matter: same sessions.
			if c != got {
				t.Errorf("%s changes the context", name)
			}
			continue
		}
		if prev, dup := seen[c]; dup {
			t.Errorf("%s gives the context of %s", name, prev)
		}
		seen[c] = name
		if len(c) != 64 {
			t.Errorf("%s: context %q", name, c)
		}
	}
}
