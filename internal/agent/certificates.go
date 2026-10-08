package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func (a *Agent) loadCertificates() {
	data, err := os.ReadFile(filepath.Join(a.cfg.StateDir, "certificates.json"))
	if err != nil {
		return
	}
	var certs map[string]configir.Certificate
	if json.Unmarshal(data, &certs) != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for key, value := range certs {
		a.certificates[key] = value
	}
}

func validMaterial(cert configir.Certificate) error {
	pair, err := tls.X509KeyPair([]byte(cert.ChainPEM), []byte(cert.PrivateKeyPEM))
	if err != nil {
		return fmt.Errorf("invalid certificate material: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return fmt.Errorf("missing certificate")
	}
	sum := sha256.Sum256(pair.Certificate[0])
	if hex.EncodeToString(sum[:]) != cert.Fingerprint {
		return fmt.Errorf("certificate fingerprint mismatch")
	}
	return nil
}

func (a *Agent) ensureCertificates(ctx context.Context, plan *configir.Plan) error {
	if len(plan.Certificates) == 0 {
		return nil
	}
	var missing []string
	a.mu.Lock()
	for id, fingerprint := range plan.Certificates {
		if _, ok := a.certificates[id+"/"+fingerprint]; !ok {
			missing = append(missing, id)
		}
	}
	a.mu.Unlock()
	sort.Strings(missing)
	for len(missing) > 0 {
		n := min(len(missing), 100)
		if a.channel == nil {
			return fmt.Errorf("certificate material unavailable")
		}
		cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
		res, err := a.channel.Client().GetCertificates(cctx, connect.NewRequest(&nodev1.GetCertificatesRequest{Ids: missing[:n]}))
		cancel()
		if err != nil {
			return fmt.Errorf("fetch certificates: %w", err)
		}
		for _, c := range res.Msg.GetCertificates() {
			if plan.Certificates[c.GetId()] != c.GetSha256Fingerprint() {
				return fmt.Errorf("certificate changed during configuration fetch; retry")
			}
			cert := configir.Certificate{ChainPEM: c.GetChainPem(), PrivateKeyPEM: c.GetPrivateKeyPem(), Fingerprint: c.GetSha256Fingerprint()}
			if err := validMaterial(cert); err != nil {
				return err
			}
			a.mu.Lock()
			a.certificates[c.GetId()+"/"+cert.Fingerprint] = cert
			a.mu.Unlock()
		}
		missing = missing[n:]
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	data, err := json.Marshal(a.certificates)
	if err != nil {
		return err
	}
	// Keep the previous fingerprint until the new LKG is durably committed.
	return fsutil.WriteFileAtomic(filepath.Join(a.cfg.StateDir, "certificates.json"), data, 0o600)
}

func (a *Agent) attachCertificates(plan *configir.Plan) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Unknown names handed to the default site with its certificate
	// (unknown-host-v1): edgeweir.policy redirects them to HTTPS only where
	// the certificate names them.
	defaultSite := ""
	if u := plan.UnknownHosts; u != nil && u.UnknownHost == configir.UnknownHostSite && u.DefaultCertificate {
		defaultSite = u.DefaultSiteID
	}
	for i := range plan.Sites {
		site := &plan.Sites[i]
		ids := site.CertificateIDs()
		if len(ids) == 0 {
			continue
		}
		certs := make([]configir.Certificate, 0, len(ids))
		leaves := make([]*x509.Certificate, 0, len(ids))
		for _, id := range ids {
			cert, ok := a.certificates[id+"/"+plan.Certificates[id]]
			if !ok {
				return fmt.Errorf("missing certificate for site %s", site.ID)
			}
			if err := validMaterial(cert); err != nil {
				return err
			}
			pair, _ := tls.X509KeyPair([]byte(cert.ChainPEM), []byte(cert.PrivateKeyPEM))
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				return err
			}
			cert.KeyType, cert.Curve = keyType(leaf)
			certs = append(certs, cert)
			leaves = append(leaves, leaf)
		}
		matches, err := checkCoverage(site, leaves)
		if err != nil {
			return err
		}
		// The names of the leaves: for hosts of suffix and pattern domains,
		// the default site's handed names and, with more than one
		// certificate, the handshake's choice among those that name the SNI.
		if matches || site.ID == defaultSite || len(certs) > 1 {
			for j := range certs {
				certs[j].DNSNames = nil
				for _, name := range leaves[j].DNSNames {
					certs[j].DNSNames = append(certs[j].DNSNames, strings.ToLower(name))
				}
			}
		}
		site.Certificate = &certs[0]
		site.Certificates = nil
		if len(certs) > 1 {
			site.Certificates = certs
		}
		site.TLSSessionContext = sessionContext(site, certs)
	}
	// TCP applications that terminate TLS (l4-v2): any name of the
	// certificate is accepted (edgeweir.l4 checks the SNI against them).
	for i := range plan.L4Apps {
		app := &plan.L4Apps[i]
		if !app.TLS() {
			continue
		}
		cert, ok := a.certificates[app.CertificateID+"/"+plan.Certificates[app.CertificateID]]
		if !ok {
			return fmt.Errorf("missing certificate for layer-4 application %s", app.ID)
		}
		if err := validMaterial(cert); err != nil {
			return err
		}
		pair, _ := tls.X509KeyPair([]byte(cert.ChainPEM), []byte(cert.PrivateKeyPEM))
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return err
		}
		app.Certificate = &cert
		app.CertificateNames = nil
		for _, name := range leaf.DNSNames {
			app.CertificateNames = append(app.CertificateNames, strings.ToLower(name))
		}
	}
	return nil
}

// checkCoverage checks that the site's certificates together cover each of
// its domains (a domain waiting for a certificate aside): an exact name
// one of them verifies for, a wildcard one of them names as "*.<parent>".
// matches reports suffix and pattern domains, whose hosts the handshake
// checks against the certificates' names.
func checkCoverage(site *configir.Site, leaves []*x509.Certificate) (matches bool, err error) {
	for _, domain := range site.Domains {
		// Served over HTTP until a new certificate covers it.
		if domain.TLSPending {
			continue
		}
		// Suffix and pattern domains name no single host: each host they
		// match is checked at the handshake (edgeweir.tls).
		if domain.Match != "" {
			matches = true
			continue
		}
		covered := false
		for _, leaf := range leaves {
			if domain.Wildcard {
				covered = slices.Contains(leaf.DNSNames, "*."+domain.Name)
			} else {
				covered = leaf.VerifyHostname(domain.Name) == nil
			}
			if covered {
				break
			}
		}
		switch {
		case !covered && domain.Wildcard:
			return false, fmt.Errorf("certificate does not cover wildcard of site %s", site.ID)
		case !covered:
			return false, fmt.Errorf("certificate does not cover site %s", site.ID)
		}
	}
	return matches, nil
}

// keyType names the leaf's key for edgeweir.tls: "ec" with its curve, or
// "rsa"; other keys get "" (always offered, like RSA).
func keyType(leaf *x509.Certificate) (string, string) {
	switch key := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return "ec", key.Curve.Params().Name
	case *rsa.PublicKey:
		return "rsa", ""
	}
	return "", ""
}

// sessionContextPrefix starts every session id context: a site's (below)
// and the health certificate's, SHA-256("edgeweir-tls-v1\0health"), which
// edgeweir.tls computes itself.
const sessionContextPrefix = "edgeweir-tls-v1\x00"

// sessionContext is the site's TLS session id context (hex SHA-256):
// sessions resume only for the same site, minimum version, client
// certificate setting and certificates. Its input is
//
//	"edgeweir-tls-v1\0" site id "\0" minimum version "\0" client
//	certificate mode "\0" hex SHA-256 of the CA PEM "\0" depth "\0"
//	certificate fingerprints in the site's order, joined by ","
//
// with "1.2" for sites without TLS options and "off", "" and "0" without
// client certificates. Ids are [A-Za-z0-9_-], the other parts fixed words,
// numbers and hex, so the input is unambiguous.
func sessionContext(site *configir.Site, certs []configir.Certificate) string {
	minimum := "1.2"
	if site.TLS != nil && site.TLS.MinimumVersion != "" {
		minimum = site.TLS.MinimumVersion
	}
	mode, ca, depth := "off", "", "0"
	if cc := site.ClientCertificate; cc != nil {
		sum := sha256.Sum256([]byte(cc.CAPEM))
		mode, ca, depth = cc.Mode, hex.EncodeToString(sum[:]), strconv.FormatUint(uint64(cc.Depth), 10)
	}
	fingerprints := make([]string, len(certs))
	for i, c := range certs {
		fingerprints[i] = c.Fingerprint
	}
	sum := sha256.Sum256([]byte(sessionContextPrefix + site.ID + "\x00" + minimum + "\x00" + mode + "\x00" + ca + "\x00" + depth + "\x00" + strings.Join(fingerprints, ",")))
	return hex.EncodeToString(sum[:])
}

// The durable store retains current and previous configurations, so keep
// exactly their referenced secrets after a successful commit as well.
func (a *Agent) pruneSecrets(current, previous *nodev1.NodeConfig) {
	certs := map[string]bool{}
	credentials := map[string]bool{}
	for _, config := range []*nodev1.NodeConfig{current, previous} {
		if config == nil || config.GetClusterId() != current.GetClusterId() {
			continue
		}
		for _, cert := range config.GetCertificates() {
			certs[cert.GetId()+"/"+cert.GetSha256Fingerprint()] = true
		}
		for _, site := range config.GetSites() {
			// The keys of PURGE methods travel like S3 credentials.
			if purge := site.GetPurge(); purge != nil {
				credentials[purge.GetCredentialId()] = true
			}
			for _, origin := range site.GetOriginPool().GetOrigins() {
				if s3 := origin.GetS3(); s3 != nil {
					credentials[s3.GetCredentialId()] = true
				}
			}
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	changedCerts, changedCredentials := false, false
	for key := range a.certificates {
		if !certs[key] {
			delete(a.certificates, key)
			changedCerts = true
		}
	}
	for key := range a.creds {
		if !credentials[key] {
			delete(a.creds, key)
			changedCredentials = true
		}
	}
	if changedCerts {
		if data, err := json.Marshal(a.certificates); err == nil {
			if err = fsutil.WriteFileAtomic(filepath.Join(a.cfg.StateDir, "certificates.json"), data, 0o600); err != nil {
				a.log.Warn("certificate cache cleanup will retry")
			}
		}
	}
	if changedCredentials {
		if err := a.saveCredentialsLocked(); err != nil {
			a.log.Warn("origin credential cache cleanup will retry")
		}
	}
}

// nginx requires a static certificate while loading its TLS listener. Lua
// rejects unknown SNI and always replaces this bootstrap certificate before a
// successful handshake; it is never an issuer or a client trust anchor.
func (a *Agent) ensureBootstrapCertificate() error {
	dir := filepath.Join(a.cfg.Render.Prefix, "conf")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	certPath, keyPath := filepath.Join(dir, "bootstrap.crt"), filepath.Join(dir, "bootstrap.key")
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "unused.invalid"}, DNSNames: []string{"unused.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(3650 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
}
