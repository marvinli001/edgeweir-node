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
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/pki/pkitest"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

// originClientMaterial issues a client certificate of ca as the console
// hands it out.
func originClientMaterial(t *testing.T, ca *pkitest.CA, id string) *nodev1.CertificateMaterial {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "cl-o"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	sum := sha256.Sum256(der)
	return &nodev1.CertificateMaterial{
		Id:                id,
		ChainPem:          string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		PrivateKeyPem:     string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})),
		Sha256Fingerprint: hex.EncodeToString(sum[:]),
	}
}

func originCAWithCRL(t *testing.T, ca *pkitest.CA, serials ...int64) *nodev1.OriginCa {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: big.NewInt(s), RevocationTime: time.Now()})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: big.NewInt(int64(len(serials) + 1)), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: ca.Cert.NotAfter,
		RevokedCertificateEntries: entries,
	}, ca.Cert, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	return &nodev1.OriginCa{CertificatePem: string(ca.PEM), CrlPem: string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))}
}

// protectedSiteConfig has site-o present the client certificate m (nil:
// none) and trust originCA (nil: the node's trust store).
func protectedSiteConfig(m *nodev1.CertificateMaterial, originCA *nodev1.OriginCa) *nodev1.NodeConfig {
	s := demoSite("site-o", "o.test")
	s.OriginPool.Origins[0].Scheme = nodev1.OriginScheme_ORIGIN_SCHEME_HTTPS
	s.OriginPool.Origins[0].Port = 443
	c := baseConfig(s)
	if m != nil {
		s.OriginPool.ClientCertificateId = m.GetId()
		c.OriginClientCertificates = []*nodev1.CertificateRef{{Id: m.GetId(), Sha256Fingerprint: m.GetSha256Fingerprint()}}
		c.RequiredFeatures = append(c.RequiredFeatures, configir.FeatureOriginMTLS)
	}
	if originCA != nil {
		s.OriginPool.TlsTrust = nodev1.OriginTlsTrust_ORIGIN_TLS_TRUST_ORIGIN_CA
		c.OriginCa = originCA
		c.RequiredFeatures = append(c.RequiredFeatures, configir.FeatureOriginCA)
	}
	return c
}

func dirFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

// TestOriginProtectionFiles: the agent fetches the client certificates
// sites present over mutual TLS, writes them (the key 0600) and the Origin
// CA with its CRL before the engine loads them, gives the data plane their
// paths, replaces them on rotation and removes what no configuration names.
func TestOriginProtectionFiles(t *testing.T) {
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-o", ClusterID: "cl-o", ReportInterval: 1, KeepaliveInterval: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	root := t.TempDir()
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}
	clientCA, err := pkitest.NewCA("Edgeweir Origin Client CA")
	if err != nil {
		t.Fatal(err)
	}
	originCA, err := pkitest.NewCA("Edgeweir Origin CA")
	if err != nil {
		t.Fatal(err)
	}
	first := originClientMaterial(t, clientCA, "occ-1")
	console.SetCertificate(first)
	rev := console.Publish(protectedSiteConfig(first, originCAWithCRL(t, originCA)))
	dp := fakedataplane.Start(t)
	cfg := h.agentConfig(dp.Socket)
	stop := startAgent(t, cfg, newFakeEngine(), dataplane.NewClient(dp.Socket))
	defer stop()
	console.AddToken("o-token")
	if _, err := enroll.Run(context.Background(), enroll.Options{
		ServerURL: srv.URL, Token: "o-token", CASHA256: console.CA.Pin(), StateDir: h.stateDir, Logger: testLogger(t),
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))

	clientDir := filepath.Join(cfg.Render.Prefix, "conf", "origin-client")
	caDir := filepath.Join(cfg.Render.Prefix, "conf", "origin-ca")
	base := "occ-1-" + first.GetSha256Fingerprint()[:16]
	if got := dirFiles(t, clientDir); !slices.Equal(got, []string{base + ".crt", base + ".key"}) {
		t.Fatalf("origin client files %v", got)
	}
	if m := mode(t, filepath.Join(clientDir, base+".key")); m != 0o600 {
		t.Fatalf("key mode %v", m)
	}
	if m := mode(t, filepath.Join(h.stateDir, "origin-client-certificates.json")); m != 0o600 {
		t.Fatalf("cache mode %v", m)
	}
	key, _ := os.ReadFile(filepath.Join(clientDir, base+".key"))
	if string(key) != first.GetPrivateKeyPem() {
		t.Fatal("the key file differs from the material")
	}
	caFiles := dirFiles(t, caDir)
	if len(caFiles) != 2 {
		t.Fatalf("Origin CA files %v", caFiles)
	}
	conf, _ := os.ReadFile(cfg.ConfPath)
	for _, f := range caFiles {
		if !strings.Contains(string(conf), filepath.Join(caDir, f)+";") {
			t.Errorf("nginx.conf does not name %s", f)
		}
	}
	table := dp.Table()
	if table == nil || len(table.Sites) != 1 {
		t.Fatalf("site table %+v", table)
	}
	s := table.Sites[0]
	if s.OriginTrust != configir.TrustOriginCA || s.OriginClientCert == nil ||
		s.OriginClientCert.Ref != "occ-1/"+first.GetSha256Fingerprint() ||
		s.OriginClientCert.CertPath != filepath.Join(clientDir, base+".crt") ||
		s.OriginClientCert.KeyPath != filepath.Join(clientDir, base+".key") {
		raw, _ := json.Marshal(s)
		t.Fatalf("site %s", raw)
	}

	// Rotation and a revocation: the new certificate and CRL replace the
	// old files once the configuration applied.
	second := originClientMaterial(t, clientCA, "occ-2")
	console.SetCertificate(second)
	rev = console.Publish(protectedSiteConfig(second, originCAWithCRL(t, originCA, 99)))
	eventually(t, "rotated", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	base2 := "occ-2-" + second.GetSha256Fingerprint()[:16]
	if got := dirFiles(t, clientDir); !slices.Equal(got, []string{base2 + ".crt", base2 + ".key"}) {
		t.Fatalf("origin client files after rotation %v", got)
	}
	if got := dirFiles(t, caDir); len(got) != 2 || slices.Equal(got, caFiles) {
		t.Fatalf("Origin CA files after the revocation %v (before %v)", got, caFiles)
	}

	// Material the console does not hand out fails the apply; the
	// configuration in place keeps serving.
	missing := originClientMaterial(t, clientCA, "occ-3")
	console.Publish(protectedSiteConfig(missing, nil))
	eventually(t, "refused", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_FAILED))
	if msg := console.LastStatus().GetMessage(); !strings.Contains(msg, "occ-3") {
		t.Fatalf("status message %q", msg)
	}
	if got := dirFiles(t, clientDir); !slices.Equal(got, []string{base2 + ".crt", base2 + ".key"}) {
		t.Fatalf("origin client files after a failed apply %v", got)
	}

	// Without origin protection no files stay.
	rev = console.Publish(protectedSiteConfig(nil, nil))
	eventually(t, "unprotected", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	if got := append(dirFiles(t, clientDir), dirFiles(t, caDir)...); len(got) != 0 {
		t.Fatalf("files left %v", got)
	}
	if s := dp.Table().Sites[0]; s.OriginClientCert != nil || s.OriginTrust != "" {
		t.Fatalf("site keeps origin protection: %+v", s)
	}
}
