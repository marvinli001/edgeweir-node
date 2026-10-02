package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

// testCertificate is a self-signed certificate for names.
func testCertificate(t *testing.T, names ...string) configir.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
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

func TestAttachCertificatesSkipsDomainsWaitingForIt(t *testing.T) {
	cert := testCertificate(t, "a.test")
	a := &Agent{certificates: map[string]configir.Certificate{"cert-a/" + cert.Fingerprint: cert}}
	plan := func(pending bool) *configir.Plan {
		return &configir.Plan{
			Certificates: map[string]string{"cert-a": cert.Fingerprint},
			Sites: []configir.Site{{ID: "a", CertificateID: "cert-a", Domains: []configir.Domain{
				{Name: "a.test"}, {Name: "new.a.test", TLSPending: pending}, {Name: "b.test", Wildcard: true, TLSPending: pending},
			}}},
		}
	}
	waiting := plan(true)
	if err := a.attachCertificates(waiting); err != nil {
		t.Fatal(err)
	}
	if waiting.Sites[0].Certificate == nil {
		t.Fatal("the certificate was not attached")
	}
	// Without the flag the certificate must cover every domain.
	if err := a.attachCertificates(plan(false)); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("err = %v", err)
	}
}
