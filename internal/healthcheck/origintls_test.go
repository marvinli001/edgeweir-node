package healthcheck

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/pki/pkitest"
)

// clientCertFiles issues a TLS client certificate of ca and writes its
// chain and PKCS#8 key the way the agent does.
func clientCertFiles(t *testing.T, ca *pkitest.CA) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "cluster", Organization: []string{"Edgeweir Origin Client"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// TestProbeOriginProtection: probes connect like the data plane: they
// present the pool's client certificate and verify the pools that trust
// the Origin CA against it alone, refusing the certificates it revoked.
func TestProbeOriginProtection(t *testing.T) {
	originCA, err := pkitest.NewCA("Edgeweir Origin CA")
	if err != nil {
		t.Fatal(err)
	}
	clientCA, err := pkitest.NewCA("Edgeweir Origin Client CA")
	if err != nil {
		t.Fatal(err)
	}
	system, err := pkitest.NewCA("public CA")
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := originCA.IssueServer([]string{"origin.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var presented []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range r.TLS.PeerCertificates {
			presented = append(presented, c.Subject.CommonName)
		}
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCA.Pool()}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the refused handshakes are expected
	srv.StartTLS()
	t.Cleanup(srv.Close)
	var asked []string
	c := New(Options{Dialer: to(srv.Listener.Addr().String(), &asked, &mu), RootCAs: system.Pool()})
	defer c.Close()
	certPath, keyPath := clientCertFiles(t, clientCA)
	ca := &configir.OriginCA{Certificate: originCA.Cert, Revoked: map[string]bool{}}
	setCA := func(ca *configir.OriginCA) {
		c.mu.Lock()
		c.originCA = ca
		c.mu.Unlock()
	}
	setCA(ca)
	o := origin("o", "93.184.216.34", 443)
	o.Scheme, o.SNI = configir.SchemeHTTPS, "origin.test"
	probe := func(trust string, withCert bool) result {
		s := site("s", &baseCheck, o)
		s.TLSVerify, s.OriginTrust = true, trust
		if withCert {
			s.OriginClientCert = &configir.OriginClientCert{Ref: "occ/1", CertPath: certPath, KeyPath: keyPath}
		}
		return c.probe(context.Background(), onlySpec(t, &configir.Plan{Sites: []configir.Site{s}}), policy())
	}

	if r := probe(configir.TrustOriginCA, true); !r.ok {
		t.Fatalf("Origin CA and client certificate: %+v", r)
	}
	mu.Lock()
	if strings.Join(presented, ",") != "cluster" {
		t.Errorf("the origin saw client certificates %v", presented)
	}
	mu.Unlock()
	if r := probe(configir.TrustOriginCA, false); r.ok {
		t.Fatal("an origin that requires a client certificate accepted a probe without one")
	}
	// The node's trust store does not know the Origin CA.
	if r := probe("", true); r.code != CodeTLSFailed || !strings.Contains(r.err, "unknown authority") {
		t.Fatalf("Origin CA certificate against the node's trust store: %+v", r)
	}
	ca.Revoked[serverCert.Leaf.SerialNumber.Text(16)] = true
	if r := probe(configir.TrustOriginCA, true); r.code != CodeTLSFailed || !strings.Contains(r.err, "revoked") {
		t.Fatalf("revoked certificate: %+v", r)
	}
	setCA(nil)
	if r := probe(configir.TrustOriginCA, true); r.code != CodeTLSFailed {
		t.Fatalf("without the Origin CA: %+v", r)
	}
	missing := o
	missing.ID = "o2"
	s := site("s", &baseCheck, missing)
	s.TLSVerify = false
	s.OriginClientCert = &configir.OriginClientCert{Ref: "occ/2", CertPath: certPath + ".gone", KeyPath: keyPath}
	if r := c.probe(context.Background(), onlySpec(t, &configir.Plan{Sites: []configir.Site{s}}), policy()); r.code != CodeTLSFailed || !strings.Contains(r.err, "client certificate") {
		t.Fatalf("unreadable client certificate: %+v", r)
	}
}

// TestSpecsOriginProtection: the trust and the client certificate are part
// of a check's spec (a change restarts it); S3 and plain HTTP origins
// present no certificate, like the data plane.
func TestSpecsOriginProtection(t *testing.T) {
	https := origin("o", "origin.test", 443)
	https.Scheme = configir.SchemeHTTPS
	plain := origin("p", "origin.test", 80)
	s := site("s", &baseCheck, https, plain)
	s.TLSVerify, s.OriginTrust = true, configir.TrustOriginCA
	s.OriginClientCert = &configir.OriginClientCert{Ref: "occ/1", CertPath: "/c.crt", KeyPath: "/c.key"}
	got := specs(&configir.Plan{Sites: []configir.Site{s}})
	h := got[Key{SiteID: "s", OriginID: "o"}]
	if !h.originCA || h.certRef != "occ/1" || h.certPath != "/c.crt" || h.keyPath != "/c.key" {
		t.Fatalf("HTTPS spec %+v", h)
	}
	if p := got[Key{SiteID: "s", OriginID: "p"}]; p.certPath != "" {
		t.Fatalf("plain HTTP presents a certificate: %+v", p)
	}
	rotated := s
	rotated.OriginClientCert = &configir.OriginClientCert{Ref: "occ/2", CertPath: "/d.crt", KeyPath: "/d.key"}
	if specs(&configir.Plan{Sites: []configir.Site{rotated}})[Key{SiteID: "s", OriginID: "o"}] == h {
		t.Fatal("a new client certificate keeps the spec")
	}
	unverified := s
	unverified.TLSVerify = false
	if specs(&configir.Plan{Sites: []configir.Site{unverified}})[Key{SiteID: "s", OriginID: "o"}].originCA {
		t.Fatal("the Origin CA trusted without verification")
	}
}
