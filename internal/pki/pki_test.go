package pki_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/edgeweir/edgeweir-node/internal/pki"
	"github.com/edgeweir/edgeweir-node/internal/pki/pkitest"
)

func TestNormalizePin(t *testing.T) {
	const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := map[string]string{
		hex:                            hex,
		strings.ToUpper(hex):           hex,
		"sha256:" + hex:                hex,
		"  " + hex + "\n":              hex,
		colonize(strings.ToUpper(hex)): hex,
	}
	for in, want := range cases {
		got, err := pki.NormalizePin(in)
		if err != nil {
			t.Errorf("NormalizePin(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizePin(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "abc", hex + "00", strings.Replace(hex, "0", "g", 1)} {
		if _, err := pki.NormalizePin(bad); err == nil {
			t.Errorf("NormalizePin(%q) succeeded, want error", bad)
		}
	}
}

func colonize(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(s[i : i+2])
	}
	return b.String()
}

func TestKeyAndCSR(t *testing.T) {
	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if key.Curve != elliptic.P256() {
		t.Fatalf("curve = %v, want P-256", key.Curve.Params().Name)
	}

	keyPEM, err := pki.MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(keyPEM), "-----BEGIN PRIVATE KEY-----") {
		t.Fatalf("key PEM has unexpected header: %q", keyPEM[:40])
	}
	parsed, err := pki.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.(*ecdsa.PrivateKey).Equal(key) {
		t.Fatal("round-tripped key differs")
	}

	csrPEM, err := pki.CreateCSR(key, "node-host-1")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("CSR PEM block = %v", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature: %v", err)
	}
	if csr.Subject.CommonName != "node-host-1" {
		t.Fatalf("CSR CN = %q", csr.Subject.CommonName)
	}
	if !csr.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("CSR public key differs from generated key")
	}
	// The CSR must never contain private key material.
	if strings.Contains(string(csrPEM), "PRIVATE") {
		t.Fatal("CSR contains private key material")
	}
}

func TestVerifyNodeCertificate(t *testing.T) {
	ca := mustCA(t)
	key, _ := pki.GenerateKey()
	csr, _ := pki.CreateCSR(key, "host")
	certPEM, _, err := ca.SignCSR(csr, "node-123", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := pki.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.VerifyNodeCertificate(cert, ca.Cert, key, time.Now()); err != nil {
		t.Fatalf("valid certificate rejected: %v", err)
	}

	otherKey, _ := pki.GenerateKey()
	if err := pki.VerifyNodeCertificate(cert, ca.Cert, otherKey, time.Now()); err == nil {
		t.Fatal("certificate accepted for a different key")
	}
	otherCA := mustCA(t)
	if err := pki.VerifyNodeCertificate(cert, otherCA.Cert, key, time.Now()); err == nil {
		t.Fatal("certificate accepted against a different CA")
	}
}

func TestNeedsRenewal(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := &x509.Certificate{NotBefore: start, NotAfter: start.Add(90 * time.Hour)}
	if pki.NeedsRenewal(c, start.Add(10*time.Hour)) {
		t.Fatal("fresh certificate flagged for renewal")
	}
	if pki.NeedsRenewal(c, start.Add(59*time.Hour)) {
		t.Fatal("certificate with >1/3 lifetime left flagged for renewal")
	}
	if !pki.NeedsRenewal(c, start.Add(61*time.Hour)) {
		t.Fatal("certificate with <1/3 lifetime left not flagged")
	}
}

// pinnedServer starts an HTTPS server whose certificate chain is issued by
// ca for 127.0.0.1 and "console.test".
func pinnedServer(t *testing.T, ca *pkitest.CA, includeCA bool) *httptest.Server {
	t.Helper()
	cert, err := ca.IssueServer([]string{"console.test"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	if !includeCA {
		cert.Certificate = cert.Certificate[:1]
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, srv *httptest.Server, cfg *tls.Config) error {
	t.Helper()
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true},
	}
	defer client.CloseIdleConnections()
	resp, err := client.Get(srv.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Errorf("negotiated %s, want HTTP/2", resp.Proto)
	}
	return nil
}

func TestPinnedTLSConfig(t *testing.T) {
	ca := mustCA(t)
	srv := pinnedServer(t, ca, true)
	host := mustHost(t, srv.URL)

	t.Run("pin match", func(t *testing.T) {
		if err := get(t, srv, pki.PinnedTLSConfig(ca.Pin(), host)); err != nil {
			t.Fatalf("request with correct pin failed: %v", err)
		}
	})

	t.Run("pin match with server name override", func(t *testing.T) {
		if err := get(t, srv, pki.PinnedTLSConfig(ca.Pin(), "console.test")); err != nil {
			t.Fatalf("request with --server-name failed: %v", err)
		}
	})

	t.Run("pin mismatch", func(t *testing.T) {
		other := mustCA(t)
		err := get(t, srv, pki.PinnedTLSConfig(other.Pin(), host))
		if err == nil {
			t.Fatal("request with wrong pin succeeded")
		}
		if !errors.Is(err, pki.ErrPinMismatch) {
			t.Fatalf("error = %v, want ErrPinMismatch", err)
		}
	})

	t.Run("hostname mismatch", func(t *testing.T) {
		err := get(t, srv, pki.PinnedTLSConfig(ca.Pin(), "evil.test"))
		if err == nil {
			t.Fatal("request with wrong server name succeeded")
		}
		var hostErr x509.HostnameError
		if !errors.As(err, &hostErr) {
			t.Fatalf("error = %v, want x509.HostnameError", err)
		}
	})

	t.Run("chain without CA", func(t *testing.T) {
		leafOnly := pinnedServer(t, ca, false)
		err := get(t, leafOnly, pki.PinnedTLSConfig(ca.Pin(), host))
		if !errors.Is(err, pki.ErrPinMismatch) {
			t.Fatalf("error = %v, want ErrPinMismatch", err)
		}
	})

	t.Run("pinned CA did not issue leaf", func(t *testing.T) {
		// A server that includes the pinned CA certificate in its chain but
		// presents a leaf from another CA must be rejected.
		other := mustCA(t)
		cert, err := other.IssueServer(nil, []net.IP{net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		cert.Certificate = [][]byte{cert.Certificate[0], ca.Cert.Raw}
		srv := httptest.NewUnstartedServer(http.NotFoundHandler())
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		srv.StartTLS()
		defer srv.Close()
		if err := get(t, srv, pki.PinnedTLSConfig(ca.Pin(), host)); err == nil {
			t.Fatal("leaf from a different CA accepted")
		}
	})
}

func TestMTLSConfigRequiresCA(t *testing.T) {
	ca := mustCA(t)
	srv := pinnedServer(t, ca, true)
	host := mustHost(t, srv.URL)
	noCert := func() *tls.Certificate { return nil }

	if err := get(t, srv, pki.MTLSConfig(ca.Pool(), host, noCert)); err != nil {
		t.Fatalf("mTLS config rejected the internal CA: %v", err)
	}
	other := mustCA(t)
	if err := get(t, srv, pki.MTLSConfig(other.Pool(), host, noCert)); err == nil {
		t.Fatal("mTLS config accepted a server from another CA")
	}
}

func mustCA(t *testing.T) *pkitest.CA {
	t.Helper()
	ca, err := pkitest.NewCA("Edgeweir Test CA")
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func mustHost(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname()
}
