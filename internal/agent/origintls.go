package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"connectrpc.com/connect"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/render"
)

// originClientCertsFile caches the origin client certificates' material
// (0600), keyed "<id>/<fingerprint>" like certificates.json.
const originClientCertsFile = "origin-client-certificates.json"

func (a *Agent) loadOriginClientCertificates() {
	data, err := os.ReadFile(filepath.Join(a.cfg.StateDir, originClientCertsFile))
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
		a.originClientCerts[key] = value
	}
}

// validOriginClientMaterial checks material as the data plane gets it: a
// key pair with the referenced fingerprint whose leaf may authenticate a
// TLS client.
func validOriginClientMaterial(cert configir.Certificate) error {
	if err := validMaterial(cert); err != nil {
		return err
	}
	pair, _ := tls.X509KeyPair([]byte(cert.ChainPEM), []byte(cert.PrivateKeyPEM))
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if len(leaf.ExtKeyUsage) > 0 && !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) &&
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return errors.New("the certificate does not allow TLS client authentication")
	}
	return nil
}

// ensureOriginClientCertificates fetches the origin client certificates of
// the plan the node does not hold yet (GetCertificates, mutual TLS only).
// Unlike a site's certificate, one that does not load fails the apply: its
// sites would present nothing and their origins would refuse them, so the
// node keeps its last-known-good configuration and retries.
func (a *Agent) ensureOriginClientCertificates(ctx context.Context, plan *configir.Plan) error {
	if len(plan.OriginClientCertificates) == 0 {
		return nil
	}
	var missing []string
	a.mu.Lock()
	for id, fingerprint := range plan.OriginClientCertificates {
		if _, ok := a.originClientCerts[id+"/"+fingerprint]; !ok {
			missing = append(missing, id)
		}
	}
	a.mu.Unlock()
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	if a.channel == nil {
		return errors.New("origin client certificate material unavailable")
	}
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	res, err := a.channel.Client().GetCertificates(cctx, connect.NewRequest(&nodev1.GetCertificatesRequest{Ids: missing}))
	cancel()
	if err != nil {
		return fmt.Errorf("fetch origin client certificates: %w", err)
	}
	got := map[string]configir.Certificate{}
	for _, c := range res.Msg.GetCertificates() {
		fingerprint, wanted := plan.OriginClientCertificates[c.GetId()]
		if !wanted {
			continue
		}
		if c.GetSha256Fingerprint() != fingerprint {
			return errors.New("origin client certificate changed during configuration fetch; retry")
		}
		cert := configir.Certificate{ChainPEM: c.GetChainPem(), PrivateKeyPEM: c.GetPrivateKeyPem(), Fingerprint: fingerprint}
		if err := validOriginClientMaterial(cert); err != nil {
			return fmt.Errorf("origin client certificate %s: %w", c.GetId(), err)
		}
		got[c.GetId()+"/"+fingerprint] = cert
	}
	for _, id := range missing {
		if _, ok := got[id+"/"+plan.OriginClientCertificates[id]]; !ok {
			return fmt.Errorf("origin client certificate %s: the console returned no material", id)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for key, cert := range got {
		a.originClientCerts[key] = cert
	}
	return a.saveOriginClientCertificatesLocked()
}

func (a *Agent) saveOriginClientCertificatesLocked() error {
	data, err := json.Marshal(a.originClientCerts)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(a.cfg.StateDir, originClientCertsFile), data, 0o600)
}

// attachOriginClientCertificates gives the sites that present an origin
// client certificate the paths of its files (written by
// writeOriginTLSFiles).
func (a *Agent) attachOriginClientCertificates(plan *configir.Plan) {
	prefix := a.cfg.Render.Prefix
	for i := range plan.Sites {
		s := &plan.Sites[i]
		id := s.OriginClientCertID
		if id == "" {
			continue
		}
		fingerprint := plan.OriginClientCertificates[id]
		s.OriginClientCert = &configir.OriginClientCert{
			Ref:      id + "/" + fingerprint,
			CertPath: render.OriginClientCertPath(prefix, id, fingerprint),
			KeyPath:  render.OriginClientKeyPath(prefix, id, fingerprint),
		}
	}
}

// writeOriginTLSFiles writes what the plan's nginx.conf and sites name
// before `openresty -t`: each origin client certificate's chain (0644) and
// key (0600; owned by the nginx worker user, who reads them for new
// connections) and the Origin CA's certificate and CRL, which nginx reads
// when it loads a configuration. Files of the same name hold the same
// content: the names follow it.
func (a *Agent) writeOriginTLSFiles(plan *configir.Plan) error {
	prefix := a.cfg.Render.Prefix
	user := a.cfg.Render.User
	if len(plan.OriginClientCertificates) > 0 {
		dir := filepath.Join(prefix, render.OriginClientDir)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create origin client certificate directory: %w", err)
		}
		if err := chownToUser(user, dir); err != nil {
			return err
		}
		if err := letWorkersIn(user, dir); err != nil {
			return err
		}
		a.mu.Lock()
		material := map[string]configir.Certificate{}
		for id, fingerprint := range plan.OriginClientCertificates {
			material[id] = a.originClientCerts[id+"/"+fingerprint]
		}
		a.mu.Unlock()
		for id, fingerprint := range plan.OriginClientCertificates {
			cert := material[id]
			if cert.PrivateKeyPEM == "" {
				return fmt.Errorf("origin client certificate %s missing", id)
			}
			for _, f := range []struct {
				path string
				data string
				mode os.FileMode
			}{
				{render.OriginClientCertPath(prefix, id, fingerprint), cert.ChainPEM, 0o644},
				{render.OriginClientKeyPath(prefix, id, fingerprint), cert.PrivateKeyPEM, 0o600},
			} {
				if err := writeIfChanged(f.path, []byte(f.data), f.mode); err != nil {
					return fmt.Errorf("write origin client certificate: %w", err)
				}
				if err := chownToUser(user, f.path); err != nil {
					return err
				}
			}
		}
	}
	if ca := plan.OriginCA; ca != nil {
		if err := os.MkdirAll(filepath.Join(prefix, render.OriginCADir), 0o750); err != nil {
			return fmt.Errorf("create Origin CA directory: %w", err)
		}
		for path, data := range map[string]string{
			render.OriginCAPath(prefix, ca):  ca.CertificatePEM,
			render.OriginCRLPath(prefix, ca): ca.CRLPEM,
		} {
			if err := writeIfChanged(path, []byte(data), 0o644); err != nil {
				return fmt.Errorf("write Origin CA: %w", err)
			}
		}
	}
	return nil
}

// writeIfChanged writes data unless the file holds it already with mode.
func writeIfChanged(path string, data []byte, mode os.FileMode) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		if info, err := os.Stat(path); err == nil && info.Mode().Perm() == mode {
			return nil
		}
	}
	return fsutil.WriteFileAtomic(path, data, mode)
}

// removeStaleOriginTLSFiles deletes the origin client certificate and
// Origin CA files the installed configuration no longer names (after it
// loaded: until then a restored previous configuration still finds them).
func (a *Agent) removeStaleOriginTLSFiles(plan *configir.Plan) {
	keep := map[string]bool{}
	prefix := a.cfg.Render.Prefix
	for id, fingerprint := range plan.OriginClientCertificates {
		keep[render.OriginClientCertPath(prefix, id, fingerprint)] = true
		keep[render.OriginClientKeyPath(prefix, id, fingerprint)] = true
	}
	if ca := plan.OriginCA; ca != nil {
		keep[render.OriginCAPath(prefix, ca)] = true
		keep[render.OriginCRLPath(prefix, ca)] = true
	}
	for _, dir := range []string{render.OriginClientDir, render.OriginCADir} {
		entries, err := os.ReadDir(filepath.Join(prefix, dir))
		if err != nil {
			continue
		}
		for _, e := range entries {
			path := filepath.Join(prefix, dir, e.Name())
			if keep[path] {
				continue
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				a.log.Warn("cannot remove a stale origin TLS file", "file", path, "err", err)
			}
		}
	}
}

// pruneOriginClientCertificates forgets the material neither the current
// nor the previous configuration (of the same cluster) names.
func (a *Agent) pruneOriginClientCertificates(current, previous *nodev1.NodeConfig) {
	keep := map[string]bool{}
	for _, config := range []*nodev1.NodeConfig{current, previous} {
		if config == nil || config.GetClusterId() != current.GetClusterId() {
			continue
		}
		for _, ref := range config.GetOriginClientCertificates() {
			keep[ref.GetId()+"/"+ref.GetSha256Fingerprint()] = true
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	changed := false
	for key := range a.originClientCerts {
		if !keep[key] {
			delete(a.originClientCerts, key)
			changed = true
		}
	}
	if changed {
		if err := a.saveOriginClientCertificatesLocked(); err != nil {
			a.log.Warn("origin client certificate cache cleanup will retry")
		}
	}
}
