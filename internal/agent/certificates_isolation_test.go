package agent_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

// material returns a self-signed certificate for name as the console hands
// it out.
func material(t *testing.T, id, name string) *nodev1.CertificateMaterial {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	return &nodev1.CertificateMaterial{Id: id, Sha256Fingerprint: hex.EncodeToString(sum[:]),
		ChainPem:      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		PrivateKeyPem: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))}
}

// TestAgentIsolatesUnloadableCertificate: a revision with an EC
// certificate whose public key spells out its curve (testdata, the
// console's EXPLICIT_EC_FIXTURE.certificate; Go does not load it) applies
// except for that certificate, which the status report names
// (certificate-isolation-v1); its site gets no certificate at all.
func TestAgentIsolatesUnloadableCertificate(t *testing.T) {
	console, err := fakeconsole.New(fakeconsole.Options{
		NodeID: "node-9", ClusterID: "cl-1", NodeName: "edge-9",
		ReportInterval: 1, KeepaliveInterval: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	root := t.TempDir()
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}

	good := material(t, "cert-good", "a.test")
	chain, err := os.ReadFile(filepath.Join("testdata", "explicit-curve.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(chain)
	sum := sha256.Sum256(block.Bytes)
	// The chain does not load whatever the key: one of another certificate.
	bad := &nodev1.CertificateMaterial{Id: "cert-bad", ChainPem: string(chain),
		PrivateKeyPem: material(t, "unused", "explicit.test").GetPrivateKeyPem(), Sha256Fingerprint: hex.EncodeToString(sum[:])}
	console.SetCertificate(good)
	console.SetCertificate(bad)
	siteA, siteB := demoSite("site-a", "a.test"), demoSite("site-b", "explicit.test")
	siteA.CertificateId, siteB.CertificateId = "cert-good", "cert-bad"
	cfg := baseConfig(siteA, siteB)
	cfg.Listeners = append(cfg.Listeners, &nodev1.Listener{Port: 443, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTPS})
	cfg.Certificates = []*nodev1.CertificateRef{
		{Id: "cert-bad", Names: []string{"explicit.test"}, Sha256Fingerprint: bad.GetSha256Fingerprint()},
		{Id: "cert-good", Names: []string{"a.test"}, Sha256Fingerprint: good.GetSha256Fingerprint()},
	}
	rev := console.Publish(cfg)
	dp := fakedataplane.Start(t)
	startAgent(t, h.agentConfig(dp.Socket), newFakeEngine(), dataplane.NewClient(dp.Socket))
	console.AddToken("secret-token")
	if _, err := enroll.Run(context.Background(), enroll.Options{
		ServerURL: srv.URL, Token: "secret-token", CASHA256: console.CA.Pin(),
		StateDir: h.stateDir, Logger: testLogger(t),
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the revision applied without the certificate", func() bool {
		s := console.LastStatus()
		return statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED)() && len(s.GetCertificateFailures()) == 1
	})
	st := console.LastStatus()
	f := st.GetCertificateFailures()[0]
	if f.GetCertificateId() != "cert-bad" || f.GetReason() != "invalid_material" || f.GetSha256Fingerprint() != bad.GetSha256Fingerprint() ||
		f.GetServingFingerprint() != "" || f.GetMessage() == "" {
		t.Fatalf("failure %v", f)
	}
	if !strings.Contains(st.GetMessage(), "cert-bad") {
		t.Fatalf("status message %q", st.GetMessage())
	}
	if !slices.Contains(st.GetInfo().GetSupportedFeatures(), "certificate-isolation-v1") {
		t.Fatalf("features %v", st.GetInfo().GetSupportedFeatures())
	}
	tb := dp.Table()
	if tb == nil || tb.Revision != rev || len(tb.Sites) != 2 {
		t.Fatalf("table %+v", tb)
	}
	for _, s := range tb.Sites {
		switch s.ID {
		case "site-a":
			if s.Certificate == nil || s.Certificate.Fingerprint != good.GetSha256Fingerprint() {
				t.Errorf("site-a certificate %+v", s.Certificate)
			}
		case "site-b":
			if s.Certificate != nil || s.Certificates != nil || s.TLSSessionContext != "" {
				t.Errorf("site-b has a certificate: %+v", s.Certificate)
			}
		}
	}

	// The certificate replaced with one that loads: no failure left.
	fixed := material(t, "cert-bad", "explicit.test")
	console.SetCertificate(fixed)
	cfg.Certificates[0].Sha256Fingerprint = fixed.GetSha256Fingerprint()
	rev2 := console.Publish(cfg)
	eventually(t, "the fixed certificate applied", func() bool {
		return statusWith(console, rev2, nodev1.ApplyState_APPLY_STATE_APPLIED)() && len(console.LastStatus().GetCertificateFailures()) == 0
	})
}
