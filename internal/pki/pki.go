// Package pki implements the node side of the console's internal PKI: key
// and CSR generation, PEM handling, CA pinning during enrollment and the
// TLS configurations used for the node channel.
//
// The node private key is generated locally and never leaves the node; only
// the CSR (public key + subject) is sent to the console.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// PEM block types.
const (
	blockPrivateKey  = "PRIVATE KEY"
	blockCertificate = "CERTIFICATE"
	blockCSR         = "CERTIFICATE REQUEST"
)

// GenerateKey creates a new ECDSA P-256 private key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// MarshalPrivateKeyPEM encodes a private key as PKCS#8 PEM.
func MarshalPrivateKeyPEM(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: blockPrivateKey, Bytes: der}), nil
}

// ParsePrivateKeyPEM decodes a PKCS#8 (or SEC 1 "EC PRIVATE KEY") PEM key.
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("no private key found in PEM data")
		}
		switch block.Type {
		case blockPrivateKey:
			k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse PKCS#8 key: %w", err)
			}
			s, ok := k.(crypto.Signer)
			if !ok {
				return nil, fmt.Errorf("unsupported private key type %T", k)
			}
			return s, nil
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse EC key: %w", err)
			}
			return k, nil
		}
	}
}

// CreateCSR returns a PEM-encoded PKCS#10 certificate signing request for
// key with the given subject common name. The console overrides the CN with
// the node id when it signs the certificate.
func CreateCSR(key crypto.Signer, commonName string) ([]byte, error) {
	tpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: blockCSR, Bytes: der}), nil
}

// ParseCertificatesPEM decodes every CERTIFICATE block in data.
func ParseCertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != blockCertificate {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate found in PEM data")
	}
	return certs, nil
}

// ParseCertificatePEM decodes the first certificate in data.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	certs, err := ParseCertificatesPEM(data)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// EncodeCertificatePEM encodes a DER certificate as PEM.
func EncodeCertificatePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockCertificate, Bytes: der})
}

// Fingerprint returns the lowercase hex SHA-256 of the certificate DER. This
// is the format of the --ca-sha256 pin in the install command.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// NormalizePin validates a CA pin and returns it as 64 lowercase hex
// characters. It accepts an optional "sha256:" prefix (kubeadm style) and
// colon-separated bytes (openssl style).
func NormalizePin(pin string) (string, error) {
	p := strings.TrimSpace(pin)
	p = strings.TrimPrefix(strings.ToLower(p), "sha256:")
	p = strings.ReplaceAll(p, ":", "")
	if len(p) != sha256.Size*2 {
		return "", fmt.Errorf("invalid CA pin: want %d hex characters, got %d", sha256.Size*2, len(p))
	}
	if _, err := hex.DecodeString(p); err != nil {
		return "", fmt.Errorf("invalid CA pin: %w", err)
	}
	return p, nil
}

// SamePublicKey reports whether cert certifies the public half of key.
func SamePublicKey(cert *x509.Certificate, key crypto.Signer) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	pub, ok := cert.PublicKey.(equaler)
	return ok && pub.Equal(key.Public())
}

// VerifyNodeCertificate checks that cert was issued by ca for client
// authentication and certifies key's public key.
func VerifyNodeCertificate(cert, ca *x509.Certificate, key crypto.Signer, now time.Time) error {
	if !SamePublicKey(cert, key) {
		return errors.New("issued certificate does not match the local private key")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return fmt.Errorf("issued certificate does not chain to the internal CA: %w", err)
	}
	return nil
}

// NeedsRenewal reports whether less than a third of the certificate's
// lifetime is left.
func NeedsRenewal(cert *x509.Certificate, now time.Time) bool {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	if lifetime <= 0 {
		return true
	}
	return cert.NotAfter.Sub(now) < lifetime/3
}
