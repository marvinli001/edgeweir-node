package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// ErrPinMismatch is returned when no certificate presented by the server
// matches the pinned CA fingerprint.
var ErrPinMismatch = errors.New("CA pin mismatch")

// VerifyPinnedChain verifies a server certificate chain against a pinned CA
// (kubeadm-style discovery). It is used during enrollment, when the node
// does not yet have the internal CA certificate:
//
//  1. some certificate in the presented chain must have a DER SHA-256 equal
//     to pin (the console sends leaf + CA);
//  2. the leaf must verify against that certificate as the only root, be
//     valid for serverName and allow server authentication.
func VerifyPinnedChain(chain []*x509.Certificate, pin, serverName string, now time.Time) error {
	if len(chain) == 0 {
		return errors.New("server presented no certificate")
	}
	var anchor *x509.Certificate
	for _, c := range chain {
		if Fingerprint(c) == pin {
			anchor = c
			break
		}
	}
	if anchor == nil {
		return fmt.Errorf("%w: no certificate in the server chain has sha256 %s", ErrPinMismatch, pin)
	}
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		if c != anchor {
			intermediates.AddCert(c)
		}
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       serverName,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return fmt.Errorf("verify server certificate against pinned CA: %w", err)
	}
	return nil
}

// PinnedTLSConfig returns a client TLS configuration that trusts exactly
// the CA whose certificate DER hashes to pin. Standard verification is
// disabled because the CA is not known yet; VerifyConnection performs the
// complete verification (pin, chain, host name, EKU) instead.
func PinnedTLSConfig(pin, serverName string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		// Safe: every handshake is verified by VerifyConnection below, which
		// runs even when InsecureSkipVerify is set.
		InsecureSkipVerify: true, //nolint:gosec // replaced by pinned verification
		VerifyConnection: func(cs tls.ConnectionState) error {
			return VerifyPinnedChain(cs.PeerCertificates, pin, serverName, time.Now())
		},
	}
}

// MTLSConfig returns the client TLS configuration used after enrollment:
// the server must present a certificate issued by the internal CA for
// serverName, and the node authenticates with the certificate returned by
// getCert (read on every handshake so renewals take effect without a
// restart).
func MTLSConfig(roots *x509.CertPool, serverName string, getCert func() *tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: serverName,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c := getCert()
			if c == nil {
				return nil, errors.New("no client certificate loaded")
			}
			return c, nil
		},
	}
}
