package configir

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"strings"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// Features of proto v0.26.0. FeatureMultiCertificate: a site has further
// certificates after certificate_id (Site.additional_certificate_ids); the
// handshake picks one per ClientHello (edgeweir.tls). FeatureClientCert: a
// site asks visitors for client certificates (Site.client_certificate).
// The session ticket keys need no feature: older nodes ignore them and
// resume no sessions.
const (
	FeatureMultiCertificate = "multi-certificate-v1"
	FeatureClientCert       = "client-cert-v1"
)

// MaxAdditionalCertificates is how many certificates a site has after
// certificate_id (four in all).
const MaxAdditionalCertificates = 3

// Limits of a client certificate setting: the CA bundle (1-10 CA
// certificates, at most 64 KiB of PEM) and the verification depth.
const (
	MaxClientCAs       = 10
	MaxClientCABytes   = 65536
	MinClientCertDepth = 1
	MaxClientCertDepth = 5
)

// Client certificate modes as the site table names them (off: no setting).
const (
	ClientCertOptional = "optional"
	ClientCertRequired = "required"
)

// ClientCertificate is a site's client certificate (mutual TLS) setting:
// the handshake asks for a certificate and verifies it against CAPEM
// (ngx.ssl.verify_client), never aborting; Required answers requests
// without a valid one with 403 client-cert-required. ForwardHeaders sends
// X-Client-Verify, X-Client-Cert-SHA256, X-Client-Cert-Subject and
// X-Client-Cert-Serial to the origin.
type ClientCertificate struct {
	Mode           string `json:"mode"`
	CAPEM          string `json:"ca_pem"`
	Depth          uint32 `json:"depth"`
	ForwardHeaders bool   `json:"forward_headers,omitempty"`
}

// SessionTicketKeyRef names one TLS session ticket key of the cluster and
// its role (next, current or previous); the secret comes from
// GetSessionTicketKeys.
type SessionTicketKeyRef struct {
	ID   string
	Role string
}

// CertificateIDs returns the site's certificates in the site's order:
// certificate_id, then the additional ones (nil without a certificate).
func (s *Site) CertificateIDs() []string {
	if s.CertificateID == "" {
		return nil
	}
	return append([]string{s.CertificateID}, s.AdditionalCertificateIDs...)
}

// buildAdditionalCertificates validates a site's additional certificates:
// at most three, distinct, other than certificate_id (which they need),
// each one of the configuration's certificates.
func buildAdditionalCertificates(s *nodev1.Site, certificates map[string]string) ([]string, error) {
	ids := s.GetAdditionalCertificateIds()
	if len(ids) == 0 {
		return nil, nil
	}
	switch {
	case s.GetCertificateId() == "":
		return nil, fmt.Errorf("%w: additional certificates without a certificate", ErrRejected)
	case len(ids) > MaxAdditionalCertificates:
		return nil, fmt.Errorf("%w: more than %d additional certificates", ErrRejected, MaxAdditionalCertificates)
	}
	seen := map[string]bool{s.GetCertificateId(): true}
	for _, id := range ids {
		if seen[id] {
			return nil, fmt.Errorf("%w: certificate %q named twice", ErrRejected, id)
		}
		if certificates[id] == "" {
			return nil, fmt.Errorf("%w: missing certificate reference", ErrRejected)
		}
		seen[id] = true
	}
	return slices.Clone(ids), nil
}

// buildClientCertificate validates a site's client certificate setting
// (nil: off). Optional and required need the site's certificate, a CA
// bundle of 1-10 CA certificates (basicConstraints CA) in at most 64 KiB
// of PEM and a depth of 1-5, and exclude HTTP/3.
func buildClientCertificate(s *nodev1.Site) (*ClientCertificate, error) {
	cc := s.GetClientCertificate()
	var mode string
	switch cc.GetMode() {
	case nodev1.ClientCertificateMode_CLIENT_CERTIFICATE_MODE_UNSPECIFIED:
		return nil, nil
	case nodev1.ClientCertificateMode_CLIENT_CERTIFICATE_MODE_OPTIONAL:
		mode = ClientCertOptional
	case nodev1.ClientCertificateMode_CLIENT_CERTIFICATE_MODE_REQUIRED:
		mode = ClientCertRequired
	default:
		return nil, fmt.Errorf("%w: unsupported client certificate mode", ErrRejected)
	}
	switch {
	case s.GetCertificateId() == "":
		return nil, fmt.Errorf("%w: client certificates without a certificate", ErrRejected)
	case s.GetTls().GetHttp3():
		return nil, fmt.Errorf("%w: client certificates with HTTP/3", ErrRejected)
	case cc.GetDepth() < MinClientCertDepth || cc.GetDepth() > MaxClientCertDepth:
		return nil, fmt.Errorf("%w: client certificate depth %d is not within %d-%d", ErrRejected, cc.GetDepth(), MinClientCertDepth, MaxClientCertDepth)
	}
	if err := checkClientCAs(cc.GetCaPem()); err != nil {
		return nil, fmt.Errorf("%w: client certificate CA: %w", ErrRejected, err)
	}
	return &ClientCertificate{Mode: mode, CAPEM: cc.GetCaPem(), Depth: cc.GetDepth(), ForwardHeaders: cc.GetForwardHeaders()}, nil
}

// checkClientCAs checks a CA bundle: only CERTIFICATE blocks without
// headers, 1-10 of them, each a CA (basicConstraints CA:TRUE), at most
// MaxClientCABytes in all.
func checkClientCAs(bundle string) error {
	if len(bundle) > MaxClientCABytes {
		return fmt.Errorf("larger than %d bytes", MaxClientCABytes)
	}
	rest, n := []byte(bundle), 0
	for {
		block, next := pem.Decode(rest)
		if block == nil {
			if strings.TrimSpace(string(rest)) != "" {
				return fmt.Errorf("not PEM certificates")
			}
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) > 0 {
			return fmt.Errorf("a %s block", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("certificate %d: %w", n+1, err)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return fmt.Errorf("certificate %d is no CA", n+1)
		}
		if n++; n > MaxClientCAs {
			return fmt.Errorf("more than %d certificates", MaxClientCAs)
		}
		rest = next
	}
	if n == 0 {
		return fmt.Errorf("no certificate")
	}
	return nil
}

// buildSessionTicketKeys validates the session ticket key references: ids
// like other ids, the roles next, current and previous, each id and role
// at most once.
func buildSessionTicketKeys(keys []*nodev1.SessionTicketKeyRef) ([]SessionTicketKeyRef, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	ids, roles := map[string]bool{}, map[string]bool{}
	out := make([]SessionTicketKeyRef, 0, len(keys))
	for _, k := range keys {
		role := k.GetRole()
		switch {
		case !idRE.MatchString(k.GetId()) || ids[k.GetId()]:
			return nil, fmt.Errorf("%w: invalid or duplicate session ticket key id %q", ErrRejected, k.GetId())
		case role != KeyRoleNext && role != KeyRoleCurrent && role != KeyRolePrevious:
			return nil, fmt.Errorf("%w: unsupported session ticket key role %q", ErrRejected, role)
		case roles[role]:
			return nil, fmt.Errorf("%w: more than one %s session ticket key", ErrRejected, role)
		}
		ids[k.GetId()], roles[role] = true, true
		out = append(out, SessionTicketKeyRef{ID: k.GetId(), Role: role})
	}
	return out, nil
}

// SessionTicketKeyIDs returns the ids of the plan's session ticket keys in
// nginx's order: current (encrypts), previous, next (decrypt only).
func (p *Plan) SessionTicketKeyIDs() []string {
	var out []string
	for _, role := range []string{KeyRoleCurrent, KeyRolePrevious, KeyRoleNext} {
		for _, k := range p.SessionTicketKeys {
			if k.Role == role {
				out = append(out, k.ID)
			}
		}
	}
	return out
}
