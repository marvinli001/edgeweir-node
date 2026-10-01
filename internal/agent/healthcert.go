package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	"github.com/marvinli001/edgeweir-node/internal/probe"
)

// The health certificate (feature probe-health-v1): TLS listeners answer
// SNI health.edgeweir.invalid, and handshakes without SNI, with a
// self-signed ECDSA P-256 certificate the agent generates for itself and
// keeps in the state directory (both files 0600). Like site certificates
// it reaches the data plane with every site table (health_certificate),
// never through nginx.conf. Probes do not verify it: it only lets the
// handshake complete so that GET /.edgeweir/health can be asked.
const (
	HealthCertFile = "health.crt"
	HealthKeyFile  = "health.key"

	healthCertLifetime = 10 * 365 * 24 * time.Hour
	// A certificate this close to its end is replaced at startup.
	healthCertRenewBefore = 30 * 24 * time.Hour
)

// loadHealthCertificate reads the health certificate, generating a new one
// when it is missing, damaged or about to expire.
func (a *Agent) loadHealthCertificate() error {
	cert, err := ensureHealthCertificate(a.cfg.StateDir, time.Now())
	if err != nil {
		return fmt.Errorf("health certificate: %w", err)
	}
	a.healthCert = cert
	return nil
}

func ensureHealthCertificate(dir string, now time.Time) (*configir.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, HealthCertFile), filepath.Join(dir, HealthKeyFile)
	certPEM, cerr := os.ReadFile(certPath)
	keyPEM, kerr := os.ReadFile(keyPath)
	if cerr == nil && kerr == nil {
		if c, err := healthMaterial(certPEM, keyPEM, now); err == nil {
			return c, nil
		}
	}
	certPEM, keyPEM, err := newHealthCertificate(now)
	if err != nil {
		return nil, err
	}
	// The key first: a crash in between leaves a pair that does not match,
	// which the next start replaces.
	if err := fsutil.WriteFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := fsutil.WriteFileAtomic(certPath, certPEM, 0o600); err != nil {
		return nil, err
	}
	return healthMaterial(certPEM, keyPEM, now)
}

// healthMaterial checks a stored pair and returns it as site table
// material.
func healthMaterial(certPEM, keyPEM []byte, now time.Time) (*configir.Certificate, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if leaf.Subject.CommonName != probe.HealthHost || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != probe.HealthHost {
		return nil, errors.New("not a health certificate")
	}
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
		return nil, errors.New("health certificate key is not ECDSA")
	}
	if now.Add(healthCertRenewBefore).After(leaf.NotAfter) {
		return nil, errors.New("health certificate expires soon")
	}
	sum := sha256.Sum256(pair.Certificate[0])
	return &configir.Certificate{ChainPEM: string(certPEM), PrivateKeyPEM: string(keyPEM), Fingerprint: hex.EncodeToString(sum[:])}, nil
}

func newHealthCertificate(now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: probe.HealthHost},
		DNSNames:              []string{probe.HealthHost},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(healthCertLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// siteTable is the site table of plan for this node: its CDN-Loop id and
// the health certificate.
func (a *Agent) siteTable(plan *configir.Plan) *dataplane.SiteTable {
	t := dataplane.FromPlan(plan)
	t.CDNID = a.cdnID()
	t.HealthCertificate = a.healthCert
	return t
}
