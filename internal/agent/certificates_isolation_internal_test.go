package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// explicitCurve is a self-signed certificate for explicit.test whose EC
// public key spells out the P-256 parameters (LibreSSL's default
// encoding), which Go does not load: the console's
// EXPLICIT_EC_FIXTURE.certificate. Its chain fails to load whatever the
// key, so the material carries a key of another certificate.
func explicitCurve(t *testing.T) configir.Certificate {
	t.Helper()
	chain, err := os.ReadFile(filepath.Join("testdata", "explicit-curve.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(chain)
	sum := sha256.Sum256(block.Bytes)
	return configir.Certificate{ChainPEM: string(chain), PrivateKeyPEM: testCertificate(t, "explicit.test").PrivateKeyPEM,
		Fingerprint: hex.EncodeToString(sum[:])}
}

// TestAttachCertificatesIsolatesUnloadable: a certificate that does not
// load leaves its sites and layer-4 applications without one (their
// handshakes are refused, never answered with another certificate) and the
// rest of the plan as it was; earlier material for its id stands in.
func TestAttachCertificatesIsolatesUnloadable(t *testing.T) {
	good := testCertificate(t, "good.test")
	bad := explicitCurve(t)
	if err := validMaterial(bad); err == nil {
		t.Fatal("the explicit-curve fixture loads")
	}
	a := &Agent{certificates: map[string]configir.Certificate{
		"cert-good/" + good.Fingerprint: good,
		// Stored before the node checked it (a certificates.json of an earlier version).
		"cert-bad/" + bad.Fingerprint: bad,
	}}
	plan := func() *configir.Plan {
		return &configir.Plan{
			Certificates: map[string]string{"cert-good": good.Fingerprint, "cert-bad": bad.Fingerprint},
			Sites: []configir.Site{
				{ID: "good", CertificateID: "cert-good", Domains: []configir.Domain{{Name: "good.test"}}},
				{ID: "bad", CertificateID: "cert-bad", Domains: []configir.Domain{{Name: "explicit.test"}}},
			},
			UnknownHosts: &configir.UnknownHosts{UnknownHost: configir.UnknownHostSite, DefaultSiteID: "good", DefaultCertificate: true},
			L4Apps:       []configir.L4App{{ID: "tls", Protocol: configir.L4TCP, Port: 8443, CertificateID: "cert-bad", TLSMinimumVersion: "1.2"}},
		}
	}
	p := plan()
	use, err := a.attachCertificates(p, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c := p.Sites[0].Certificate; c == nil || c.Fingerprint != good.Fingerprint || p.Sites[0].TLSSessionContext == "" {
		t.Fatalf("good site %+v", p.Sites[0])
	}
	if s := p.Sites[1]; s.Certificate != nil || s.Certificates != nil || s.TLSSessionContext != "" {
		t.Fatalf("bad site keeps a certificate: %+v", s)
	}
	if app := p.L4Apps[0]; app.Certificate != nil || !app.CertificateUnavailable || app.CertificateNames != nil {
		t.Fatalf("application %+v", app)
	}
	f := use.failures["cert-bad"]
	if len(use.failures) != 1 || f.GetReason() != certInvalidMaterial || f.GetServingFingerprint() != "" ||
		f.GetSha256Fingerprint() != bad.Fingerprint || f.GetMessage() == "" || strings.Contains(f.GetMessage(), "PRIVATE KEY") {
		t.Fatalf("failures %v", use.failures)
	}
	if w := use.warnings(); len(w) != 1 || !strings.Contains(w[0], "cert-bad") || !strings.Contains(w[0], "refused") {
		t.Fatalf("warnings %v", w)
	}
	if r := use.report(); len(r) != 1 || r[0].GetCertificateId() != "cert-bad" {
		t.Fatalf("report %v", r)
	}
	if !use.serving["cert-good/"+good.Fingerprint] || use.serving["cert-bad/"+bad.Fingerprint] {
		t.Fatalf("serving %v", use.serving)
	}

	// The node still holds earlier material of cert-bad: it is served.
	earlier := testCertificate(t, "explicit.test")
	a.certificates["cert-bad/"+earlier.Fingerprint] = earlier
	p = plan()
	if use, err = a.attachCertificates(p, map[string]*nodev1.CertificateFailure{
		"cert-bad": {CertificateId: "cert-bad", Sha256Fingerprint: bad.Fingerprint, Reason: certInvalidMaterial, Message: "from the fetch"},
	}); err != nil {
		t.Fatal(err)
	}
	if c := p.Sites[1].Certificate; c == nil || c.Fingerprint != earlier.Fingerprint {
		t.Fatalf("bad site without its earlier material: %+v", p.Sites[1])
	}
	if app := p.L4Apps[0]; app.Certificate == nil || app.CertificateUnavailable || app.CertificateNames[0] != "explicit.test" {
		t.Fatalf("application %+v", app)
	}
	if f := use.failures["cert-bad"]; f.GetServingFingerprint() != earlier.Fingerprint || f.GetMessage() != "from the fetch" {
		t.Fatalf("failure %v", f)
	}
	if !use.serving["cert-bad/"+earlier.Fingerprint] || !strings.Contains(use.warnings()[0], "earlier material") {
		t.Fatalf("serving %v, warnings %v", use.serving, use.warnings())
	}

	// Earlier material that does not cover the site's domains: none.
	delete(a.certificates, "cert-bad/"+earlier.Fingerprint)
	other := testCertificate(t, "other.test")
	a.certificates["cert-bad/"+other.Fingerprint] = other
	p = plan()
	p.L4Apps = nil
	if use, err = a.attachCertificates(p, nil); err != nil {
		t.Fatal(err)
	}
	if p.Sites[1].Certificate != nil {
		t.Fatalf("uncovering earlier material served: %+v", p.Sites[1].Certificate)
	}
	// Nothing keeps it: reported as refused, not kept as served material.
	if f := use.failures["cert-bad"]; f.GetServingFingerprint() != "" || use.serving["cert-bad/"+other.Fingerprint] {
		t.Fatalf("failure %v, serving %v", f, use.serving)
	}
	// A site whose own loading certificates leave a domain uncovered still
	// fails the revision, as before.
	p = plan()
	p.Sites[0].Domains = append(p.Sites[0].Domains, configir.Domain{Name: "uncovered.test"})
	if _, err = a.attachCertificates(p, nil); err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("err = %v", err)
	}
}

// TestPruneKeepsServedEarlierMaterial: earlier material standing in for a
// certificate that does not load outlives the revisions that named it.
func TestPruneKeepsServedEarlierMaterial(t *testing.T) {
	earlier := testCertificate(t, "explicit.test")
	unused := testCertificate(t, "unused.test")
	a := &Agent{
		cfg: Config{StateDir: t.TempDir()},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		certificates: map[string]configir.Certificate{
			"cert-bad/" + earlier.Fingerprint: earlier,
			"cert-old/" + unused.Fingerprint:  unused,
		},
		creds:   map[string]configir.Credential{},
		certUse: certificateUse{serving: map[string]bool{"cert-bad/" + earlier.Fingerprint: true}},
	}
	cfg := &nodev1.NodeConfig{ClusterId: "c", Certificates: []*nodev1.CertificateRef{{Id: "cert-bad", Sha256Fingerprint: "ff"}}}
	a.pruneSecrets(cfg, nil)
	if _, ok := a.certificates["cert-bad/"+earlier.Fingerprint]; !ok {
		t.Fatal("served earlier material pruned")
	}
	if _, ok := a.certificates["cert-old/"+unused.Fingerprint]; ok {
		t.Fatal("unused material kept")
	}
}

// TestCertificateFailuresSurviveRestart: the LKG served at start reports
// the failures (and reasons) of its revision, not of another.
func TestCertificateFailuresSurviveRestart(t *testing.T) {
	a := &Agent{cfg: Config{StateDir: t.TempDir()}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	cfg := &nodev1.NodeConfig{Revision: 4, ContentHash: "abc"}
	a.saveCertificateFailures(cfg, certificateUse{failures: map[string]*nodev1.CertificateFailure{
		"cert-bad": {CertificateId: "cert-bad", Sha256Fingerprint: "ff", Reason: certInvalidMaterial, Message: "x509: unsupported elliptic curve", ServingFingerprint: "ee"},
	}})
	got := a.loadCertificateFailures(cfg)
	if f := got["cert-bad"]; len(got) != 1 || f.GetReason() != certInvalidMaterial || f.GetMessage() != "x509: unsupported elliptic curve" || f.GetServingFingerprint() != "" {
		t.Fatalf("loaded %v", got)
	}
	if got := a.loadCertificateFailures(&nodev1.NodeConfig{Revision: 5, ContentHash: "def"}); got != nil {
		t.Fatalf("another revision's failures: %v", got)
	}
}
