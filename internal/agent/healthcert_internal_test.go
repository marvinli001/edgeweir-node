package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/probe"
)

func TestEnsureHealthCertificate(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	first, err := ensureHealthCertificate(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{HealthCertFile, HealthKeyFile} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", name, st.Mode().Perm())
		}
	}
	block, _ := pem.Decode([]byte(first.ChainPEM))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("key %T, want ECDSA P-256", leaf.PublicKey)
	}
	if leaf.Subject.CommonName != probe.HealthHost || leaf.VerifyHostname(probe.HealthHost) != nil {
		t.Fatalf("subject %v, names %v", leaf.Subject, leaf.DNSNames)
	}
	if leaf.NotAfter.Before(now.Add(9*365*24*time.Hour)) || leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) != nil {
		t.Fatalf("not a long-lived self-signed certificate: %v .. %v", leaf.NotBefore, leaf.NotAfter)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || leaf.IsCA {
		t.Fatalf("usage %v CA %v", leaf.ExtKeyUsage, leaf.IsCA)
	}
	if first.Fingerprint == "" || first.PrivateKeyPEM == "" {
		t.Fatalf("material %+v", first)
	}

	// Kept across restarts.
	again, err := ensureHealthCertificate(dir, now.Add(time.Hour))
	if err != nil || again.Fingerprint != first.Fingerprint {
		t.Fatalf("restart replaced the certificate: %v", err)
	}
	// Replaced close to its end, when damaged or when the pair does not match.
	soon, err := ensureHealthCertificate(dir, leaf.NotAfter.Add(-24*time.Hour))
	if err != nil || soon.Fingerprint == first.Fingerprint {
		t.Fatalf("expiring certificate kept: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, HealthCertFile), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	repaired, err := ensureHealthCertificate(dir, now)
	if err != nil || repaired.Fingerprint == soon.Fingerprint {
		t.Fatalf("damaged certificate kept: %v", err)
	}
	other := t.TempDir()
	if _, err := ensureHealthCertificate(other, now); err != nil {
		t.Fatal(err)
	}
	key, _ := os.ReadFile(filepath.Join(other, HealthKeyFile))
	if err := os.WriteFile(filepath.Join(dir, HealthKeyFile), key, 0o600); err != nil {
		t.Fatal(err)
	}
	mismatch, err := ensureHealthCertificate(dir, now)
	if err != nil || mismatch.Fingerprint == repaired.Fingerprint {
		t.Fatalf("mismatched pair kept: %v", err)
	}
}
