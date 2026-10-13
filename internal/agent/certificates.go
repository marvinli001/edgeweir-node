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
	"errors"
	"fmt"
	"maps"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

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

// Reasons a certificate of a revision does not load
// (CertificateFailure.reason).
const (
	certInvalidMaterial     = "invalid_material"
	certFingerprintMismatch = "fingerprint_mismatch"
	certUnavailable         = "unavailable"
)

// maxCertificateFailures is how many failed certificates a status report
// names; maxCertificateMessage bounds each one's message (bytes).
const (
	maxCertificateFailures = 100
	maxCertificateMessage  = 256
)

var errFingerprintMismatch = errors.New("certificate fingerprint mismatch")

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
		return errFingerprintMismatch
	}
	return nil
}

// loadable checks material as the data plane gets it and returns its leaf.
func loadable(cert configir.Certificate) (*x509.Certificate, error) {
	if err := validMaterial(cert); err != nil {
		return nil, err
	}
	pair, _ := tls.X509KeyPair([]byte(cert.ChainPEM), []byte(cert.PrivateKeyPEM))
	return x509.ParseCertificate(pair.Certificate[0])
}

// certificateFailure describes a certificate that did not load; the
// message is the error's text (never key material), at most
// maxCertificateMessage bytes.
func certificateFailure(id, fingerprint string, err error) *nodev1.CertificateFailure {
	reason := certInvalidMaterial
	if errors.Is(err, errFingerprintMismatch) {
		reason = certFingerprintMismatch
	}
	msg := err.Error()
	if len(msg) > maxCertificateMessage {
		msg = strings.ToValidUTF8(msg[:maxCertificateMessage], "")
	}
	return &nodev1.CertificateFailure{CertificateId: id, Sha256Fingerprint: fingerprint, Reason: reason, Message: msg}
}

// ensureCertificates fetches the revision's certificates the node does not
// hold yet. One that does not load is left out and returned among the
// failures (feature certificate-isolation-v1): the rest of the revision
// applies. An error (the console unreachable, a certificate changed during
// the fetch) fails the apply; it is retried.
func (a *Agent) ensureCertificates(ctx context.Context, plan *configir.Plan) (map[string]*nodev1.CertificateFailure, error) {
	failures := map[string]*nodev1.CertificateFailure{}
	if len(plan.Certificates) == 0 {
		return failures, nil
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
			return nil, fmt.Errorf("certificate material unavailable")
		}
		cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
		res, err := a.channel.Client().GetCertificates(cctx, connect.NewRequest(&nodev1.GetCertificatesRequest{Ids: missing[:n]}))
		cancel()
		if err != nil {
			return nil, fmt.Errorf("fetch certificates: %w", err)
		}
		returned := map[string]bool{}
		for _, c := range res.Msg.GetCertificates() {
			if plan.Certificates[c.GetId()] != c.GetSha256Fingerprint() {
				return nil, fmt.Errorf("certificate changed during configuration fetch; retry")
			}
			returned[c.GetId()] = true
			cert := configir.Certificate{ChainPEM: c.GetChainPem(), PrivateKeyPEM: c.GetPrivateKeyPem(), Fingerprint: c.GetSha256Fingerprint()}
			if err := validMaterial(cert); err != nil {
				failures[c.GetId()] = certificateFailure(c.GetId(), cert.Fingerprint, err)
				a.log.Warn("certificate not loaded; the rest of the revision applies", "certificate_id", c.GetId(), "err", err)
				continue
			}
			a.mu.Lock()
			a.certificates[c.GetId()+"/"+cert.Fingerprint] = cert
			a.mu.Unlock()
		}
		for _, id := range missing[:n] {
			if !returned[id] {
				failures[id] = &nodev1.CertificateFailure{CertificateId: id, Sha256Fingerprint: plan.Certificates[id],
					Reason: certUnavailable, Message: "the console returned no material"}
			}
		}
		missing = missing[n:]
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	data, err := json.Marshal(a.certificates)
	if err != nil {
		return nil, err
	}
	// Keep the previous fingerprint until the new LKG is durably committed.
	return failures, fsutil.WriteFileAtomic(filepath.Join(a.cfg.StateDir, "certificates.json"), data, 0o600)
}

// certificateUse is what attaching a revision's certificates found: the
// certificates that did not load (by id; serving_fingerprint set where
// earlier material stands in) and the keys of a.certificates the plan
// serves.
type certificateUse struct {
	failures map[string]*nodev1.CertificateFailure
	serving  map[string]bool
}

// warnings returns one plan warning per failed certificate.
func (u certificateUse) warnings() []string {
	ids := slices.Sorted(maps.Keys(u.failures))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		f := u.failures[id]
		if f.GetServingFingerprint() != "" {
			out = append(out, fmt.Sprintf("certificate %s not loaded (%s): its earlier material is served", id, f.GetReason()))
		} else {
			out = append(out, fmt.Sprintf("certificate %s not loaded (%s): TLS handshakes it served are refused", id, f.GetReason()))
		}
	}
	return out
}

// report returns the failures as ReportStatusRequest.certificate_failures:
// sorted by id, at most maxCertificateFailures.
func (u certificateUse) report() []*nodev1.CertificateFailure {
	ids := slices.Sorted(maps.Keys(u.failures))
	out := make([]*nodev1.CertificateFailure, 0, min(len(ids), maxCertificateFailures))
	for _, id := range ids[:min(len(ids), maxCertificateFailures)] {
		out = append(out, proto.Clone(u.failures[id]).(*nodev1.CertificateFailure))
	}
	return out
}

// attachCertificates gives the plan's sites and layer-4 applications their
// certificates' material. failures are those ensureCertificates found (nil:
// none known, as when serving the LKG); material the node does not hold,
// or that does not load, fails too. A failed certificate gets the earlier
// material the node still holds for its id (the latest notAfter that
// loads), else none: a site left without certificates, or whose remaining
// ones no longer cover its domains, has none at all and an application
// none either (CertificateUnavailable), so their handshakes are refused,
// never answered with another certificate. A certificate the revision does
// not list, or a site whose own certificates do not cover it, is an error.
func (a *Agent) attachCertificates(plan *configir.Plan, failures map[string]*nodev1.CertificateFailure) (certificateUse, error) {
	use := certificateUse{failures: map[string]*nodev1.CertificateFailure{}, serving: map[string]bool{}}
	for id, f := range failures {
		use.failures[id] = proto.Clone(f).(*nodev1.CertificateFailure)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// standIns: the earlier material (key) found for a failed certificate,
	// served only where a site or application keeps it (kept).
	standIns, kept := map[string]string{}, map[string]bool{}
	// material returns the material id gets and its leaf; ok is false when
	// there is none.
	material := func(id string) (configir.Certificate, *x509.Certificate, bool) {
		key := id + "/" + plan.Certificates[id]
		if use.failures[id] == nil {
			cert, held := a.certificates[key]
			if !held {
				use.failures[id] = &nodev1.CertificateFailure{CertificateId: id, Sha256Fingerprint: plan.Certificates[id],
					Reason: certUnavailable, Message: "material not held by the node"}
			} else if leaf, err := loadable(cert); err != nil {
				use.failures[id] = certificateFailure(id, plan.Certificates[id], err)
			} else {
				use.serving[key] = true
				return cert, leaf, true
			}
		}
		var best configir.Certificate
		var bestLeaf *x509.Certificate
		bestKey := ""
		for k, cert := range a.certificates {
			if k == key || !strings.HasPrefix(k, id+"/") {
				continue
			}
			leaf, err := loadable(cert)
			if err == nil && (bestLeaf == nil || leaf.NotAfter.After(bestLeaf.NotAfter) || (leaf.NotAfter.Equal(bestLeaf.NotAfter) && k < bestKey)) {
				best, bestLeaf, bestKey = cert, leaf, k
			}
		}
		if bestLeaf == nil {
			return configir.Certificate{}, nil, false
		}
		standIns[id] = bestKey
		return best, bestLeaf, true
	}
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
		used := make([]string, 0, len(ids))
		lost := false
		for _, id := range ids {
			if plan.Certificates[id] == "" {
				return use, fmt.Errorf("missing certificate for site %s", site.ID)
			}
			cert, leaf, ok := material(id)
			if use.failures[id] != nil {
				lost = true
			}
			if !ok {
				continue
			}
			cert.KeyType, cert.Curve = keyType(leaf)
			certs = append(certs, cert)
			leaves = append(leaves, leaf)
			used = append(used, id)
		}
		matches := false
		if len(certs) > 0 {
			var err error
			if matches, err = checkCoverage(site, leaves); err != nil {
				if !lost {
					return use, err
				}
				certs = nil
			}
		}
		if len(certs) == 0 {
			// No certificate: edgeweir.tls refuses the site's handshakes.
			site.Certificate, site.Certificates, site.TLSSessionContext = nil, nil, ""
			continue
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
		for _, id := range used {
			kept[id] = true
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
		if plan.Certificates[app.CertificateID] == "" {
			return use, fmt.Errorf("missing certificate for layer-4 application %s", app.ID)
		}
		cert, leaf, ok := material(app.CertificateID)
		app.CertificateNames = nil
		if !ok {
			app.Certificate, app.CertificateUnavailable = nil, true
			continue
		}
		app.Certificate, app.CertificateUnavailable = &cert, false
		kept[app.CertificateID] = true
		for _, name := range leaf.DNSNames {
			app.CertificateNames = append(app.CertificateNames, strings.ToLower(name))
		}
	}
	// Earlier material counts as served (kept on disk, reported) only
	// where something uses it.
	for id, key := range standIns {
		if kept[id] {
			use.serving[key] = true
			use.failures[id].ServingFingerprint = a.certificates[key].Fingerprint
		}
	}
	return use, nil
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
		// Earlier material standing in for a certificate that did not load
		// stays while the applied plan serves it.
		if !certs[key] && !a.certUse.serving[key] {
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

// certificateFailuresFile keeps the applied revision's certificate failures
// for the LKG served before the console is reachable (their reasons).
const certificateFailuresFile = "certificate-failures.json"

type storedCertificateFailures struct {
	ContentHash string `json:"content_hash"`
	Failures    []struct {
		ID          string `json:"id"`
		Fingerprint string `json:"fingerprint"`
		Reason      string `json:"reason"`
		Message     string `json:"message"`
	} `json:"failures"`
}

// saveCertificateFailures stores the failures of the revision just applied
// (best effort: without the file the LKG's report says "unavailable").
func (a *Agent) saveCertificateFailures(cfg *nodev1.NodeConfig, use certificateUse) {
	stored := storedCertificateFailures{ContentHash: cfg.GetContentHash()}
	for _, f := range use.report() {
		stored.Failures = append(stored.Failures, struct {
			ID          string `json:"id"`
			Fingerprint string `json:"fingerprint"`
			Reason      string `json:"reason"`
			Message     string `json:"message"`
		}{f.GetCertificateId(), f.GetSha256Fingerprint(), f.GetReason(), f.GetMessage()})
	}
	data, err := json.Marshal(stored)
	if err == nil {
		err = fsutil.WriteFileAtomic(filepath.Join(a.cfg.StateDir, certificateFailuresFile), data, 0o600)
	}
	if err != nil {
		a.log.Warn("cannot store the certificate failures", "err", err)
	}
}

// loadCertificateFailures returns the stored failures of cfg (nil when the
// file holds another revision's).
func (a *Agent) loadCertificateFailures(cfg *nodev1.NodeConfig) map[string]*nodev1.CertificateFailure {
	data, err := os.ReadFile(filepath.Join(a.cfg.StateDir, certificateFailuresFile))
	if err != nil {
		return nil
	}
	var stored storedCertificateFailures
	if json.Unmarshal(data, &stored) != nil || stored.ContentHash != cfg.GetContentHash() {
		return nil
	}
	out := map[string]*nodev1.CertificateFailure{}
	for _, f := range stored.Failures {
		out[f.ID] = &nodev1.CertificateFailure{CertificateId: f.ID, Sha256Fingerprint: f.Fingerprint, Reason: f.Reason, Message: f.Message}
	}
	return out
}
