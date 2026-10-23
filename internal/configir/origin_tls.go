package configir

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// Features of origin protection (proto v1.3.0). FeatureOriginMTLS: a pool
// presents the cluster's origin client certificate to HTTPS origins that
// request one (OriginPool.client_certificate_id), in all three origin
// layers and in the active health checks. FeatureOriginCA: a pool verifies
// its HTTPS origins against the console's Origin CA alone and refuses the
// certificates its CRL lists (OriginPool.tls_trust, NodeConfig.origin_ca).
// FeatureOriginCARotation (proto v1.6.0): while the console rotates the
// Origin CA, those pools trust the previous one too, with its own CRL
// (NodeConfig.origin_ca_previous). The console requires them when a served
// site uses them.
const (
	FeatureOriginMTLS       = "origin-mtls-v1"
	FeatureOriginCA         = "origin-ca-v1"
	FeatureOriginCARotation = "origin-ca-rotation-v1"
)

// TrustOriginCA is Site.OriginTrust of a pool that trusts the Origin CA alone.
const TrustOriginCA = "origin_ca"

// OriginCA is the console's Origin CA: the only trust anchor of the pools
// that trust it, and the certificates its CRL revoked. During a rotation
// it is the current and the previous authority, each with its CRL.
type OriginCA struct {
	// CertificatePEM and CRLPEM are the files nginx reads: the current
	// authority's certificate and CRL, then the previous one's.
	CertificatePEM string
	CRLPEM         string
	// Authorities are the current one, then the previous one.
	Authorities []OriginAuthority
}

// OriginAuthority is one Origin CA and the serial numbers its CRL lists.
type OriginAuthority struct {
	Certificate *x509.Certificate
	Revoked     map[string]bool
}

// Certificates are the trusted authorities' certificates.
func (ca *OriginCA) Certificates() []*x509.Certificate {
	if ca == nil {
		return nil
	}
	out := make([]*x509.Certificate, 0, len(ca.Authorities))
	for _, a := range ca.Authorities {
		out = append(out, a.Certificate)
	}
	return out
}

// IsRevoked tells whether the CRL of the authority that signed the
// certificate lists it.
func (ca *OriginCA) IsRevoked(cert *x509.Certificate) bool {
	if ca == nil || cert == nil {
		return false
	}
	for _, a := range ca.Authorities {
		if bytes.Equal(cert.RawIssuer, a.Certificate.RawSubject) && cert.CheckSignatureFrom(a.Certificate) == nil {
			return a.Revoked[serialKey(cert.SerialNumber)]
		}
	}
	return false
}

func serialKey(n *big.Int) string { return n.Text(16) }

// OriginClientCert is the client certificate a site presents to its HTTPS
// origins (feature origin-mtls-v1). The agent writes the files and fills
// in their paths; the data plane reads them on each new connection.
type OriginClientCert struct {
	// Ref is "<id>/<sha256 fingerprint>": connections are reused only by
	// requests presenting the same certificate.
	Ref      string `json:"ref"`
	CertPath string `json:"crt"`
	KeyPath  string `json:"key"`
}

var fingerprintRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// buildOriginClientCertificates checks NodeConfig.origin_client_certificates
// and returns their fingerprints by id.
func buildOriginClientCertificates(c *nodev1.NodeConfig) (map[string]string, error) {
	out := map[string]string{}
	for _, ref := range c.GetOriginClientCertificates() {
		if !idRE.MatchString(ref.GetId()) || !fingerprintRE.MatchString(ref.GetSha256Fingerprint()) {
			return nil, fmt.Errorf("%w: invalid origin client certificate reference", ErrRejected)
		}
		if _, dup := out[ref.GetId()]; dup {
			return nil, fmt.Errorf("%w: duplicate origin client certificate %q", ErrRejected, ref.GetId())
		}
		out[ref.GetId()] = ref.GetSha256Fingerprint()
	}
	return out, nil
}

// buildOriginCA checks NodeConfig.origin_ca and, during a rotation,
// origin_ca_previous: each one CA certificate and a CRL it signed that is
// current (nginx refuses every origin while its CRL has expired; the
// console makes it valid until the authority expires).
func buildOriginCA(c *nodev1.NodeConfig, now time.Time) (*OriginCA, error) {
	in := c.GetOriginCa()
	if in == nil {
		if c.GetOriginCaPrevious() != nil {
			return nil, fmt.Errorf("%w: previous origin CA without the origin CA", ErrRejected)
		}
		return nil, nil
	}
	current, err := buildOriginAuthority(in, now)
	if err != nil {
		return nil, fmt.Errorf("%w: origin CA%v", ErrRejected, err)
	}
	ca := &OriginCA{CertificatePEM: in.GetCertificatePem(), CRLPEM: in.GetCrlPem(), Authorities: []OriginAuthority{current}}
	if prev := c.GetOriginCaPrevious(); prev != nil {
		previous, err := buildOriginAuthority(prev, now)
		if err != nil {
			return nil, fmt.Errorf("%w: previous origin CA%v", ErrRejected, err)
		}
		if previous.Certificate.Equal(current.Certificate) || bytes.Equal(previous.Certificate.RawSubject, current.Certificate.RawSubject) {
			return nil, fmt.Errorf("%w: previous origin CA has the same subject", ErrRejected)
		}
		ca.CertificatePEM = joinPEM(ca.CertificatePEM, prev.GetCertificatePem())
		ca.CRLPEM = joinPEM(ca.CRLPEM, prev.GetCrlPem())
		ca.Authorities = append(ca.Authorities, previous)
	}
	return ca, nil
}

// joinPEM concatenates PEM files, each on its own lines.
func joinPEM(a, b string) string {
	if a != "" && !strings.HasSuffix(a, "\n") {
		a += "\n"
	}
	return a + b
}

// buildOriginAuthority checks one Origin CA; errors start with ": ".
func buildOriginAuthority(in *nodev1.OriginCa, now time.Time) (OriginAuthority, error) {
	block, rest := pem.Decode([]byte(in.GetCertificatePem()))
	if block == nil || block.Type != "CERTIFICATE" {
		return OriginAuthority{}, errors.New(": no PEM certificate")
	}
	if extra, _ := pem.Decode(rest); extra != nil {
		return OriginAuthority{}, errors.New(": more than one certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return OriginAuthority{}, fmt.Errorf(": %v", err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return OriginAuthority{}, errors.New(": not a certificate authority")
	}
	crlBlock, _ := pem.Decode([]byte(in.GetCrlPem()))
	if crlBlock == nil || crlBlock.Type != "X509 CRL" {
		return OriginAuthority{}, errors.New(": no PEM CRL (X509 CRL)")
	}
	crl, err := x509.ParseRevocationList(crlBlock.Bytes)
	if err != nil {
		return OriginAuthority{}, fmt.Errorf(" CRL: %v", err)
	}
	if err := crl.CheckSignatureFrom(cert); err != nil {
		return OriginAuthority{}, fmt.Errorf(" CRL: %v", err)
	}
	if !crl.NextUpdate.IsZero() && crl.NextUpdate.Before(now) {
		return OriginAuthority{}, fmt.Errorf(" CRL expired %s", crl.NextUpdate.UTC().Format(time.RFC3339))
	}
	a := OriginAuthority{Certificate: cert, Revoked: map[string]bool{}}
	for _, entry := range crl.RevokedCertificateEntries {
		a.Revoked[serialKey(entry.SerialNumber)] = true
	}
	return a, nil
}

// buildOriginTLS checks a pool's trust and client certificate: the Origin
// CA as trust needs NodeConfig.origin_ca, verification and no S3 origin
// (their certificates are public); a client certificate must be one of
// NodeConfig.origin_client_certificates.
func buildOriginTLS(s *nodev1.Site, clientCerts map[string]string, ca *OriginCA) (trust, clientCertID string, err error) {
	pool := s.GetOriginPool()
	if pool.GetTlsTrust() == nodev1.OriginTlsTrust_ORIGIN_TLS_TRUST_ORIGIN_CA {
		switch {
		case ca == nil:
			return "", "", fmt.Errorf("%w: the pool trusts the origin CA, which the configuration lacks", ErrRejected)
		case pool.GetSkipTlsVerify():
			return "", "", fmt.Errorf("%w: the pool trusts the origin CA without verifying", ErrRejected)
		}
		for _, o := range pool.GetOrigins() {
			if o.GetS3() != nil {
				return "", "", fmt.Errorf("%w: S3 origin %q cannot trust the origin CA", ErrRejected, o.GetId())
			}
		}
		trust = TrustOriginCA
	}
	if id := pool.GetClientCertificateId(); id != "" {
		if _, ok := clientCerts[id]; !ok {
			return "", "", fmt.Errorf("%w: unknown origin client certificate %q", ErrRejected, id)
		}
		clientCertID = id
	}
	return trust, clientCertID, nil
}
