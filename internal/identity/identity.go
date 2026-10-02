// Package identity persists the node's enrollment result in the state
// directory:
//
//	node.key       ECDSA P-256 private key, PKCS#8 PEM, mode 0600
//	node.crt       node client certificate issued by the internal CA
//	ca.crt         internal CA certificate (verified against the pin)
//	identity.json  node id, cluster id, name and console address
//	run.lock       held (flock) by `edgeweir-node run` while it runs
//
// identity.json is written last and is the "enrolled" marker; the other
// files are always complete when it exists. Every file is replaced
// atomically (temp file, fsync, rename, fsync dir).
//
// A probe (`edgeweir-node probe`) keeps its identity in its own state
// directory with the same rules: probe.key (0600), probe.crt, ca.crt and
// probe.json (probe id, name, region and console address).
package identity

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	"github.com/marvinli001/edgeweir-node/internal/pki"
)

// File names inside the state directory.
const (
	KeyFile      = "node.key"
	CertFile     = "node.crt"
	CAFile       = "ca.crt"
	IdentityFile = "identity.json"
	// ConfigDir holds the last-known-good configuration (see configstore).
	ConfigDir = "config"
	// RunLockFile is locked by a running agent (LockRun).
	RunLockFile = "run.lock"

	// The probe layout (Store.Probe).
	ProbeKeyFile      = "probe.key"
	ProbeCertFile     = "probe.crt"
	ProbeIdentityFile = "probe.json"
)

// ErrNotEnrolled is returned by Load when identity.json does not exist.
var ErrNotEnrolled = errors.New("node is not enrolled")

// ErrProbeNotEnrolled is returned by Load when probe.json does not exist.
var ErrProbeNotEnrolled = errors.New("probe is not enrolled")

// ErrRunning is returned by LockRun when an agent already runs with the
// state directory.
var ErrRunning = errors.New("an edgeweir-node agent is running with this state directory")

// Identity is the non-secret enrollment metadata: the node fields for a
// node, the probe fields for a probe.
type Identity struct {
	NodeID    string `json:"node_id,omitempty"`
	ClusterID string `json:"cluster_id,omitempty"`
	NodeName  string `json:"node_name,omitempty"`
	ProbeID   string `json:"probe_id,omitempty"`
	ProbeName string `json:"probe_name,omitempty"`
	// RegionID is the region a probe measures from.
	RegionID   string    `json:"region_id,omitempty"`
	ServerURL  string    `json:"server_url"`
	ServerName string    `json:"server_name"`
	CASHA256   string    `json:"ca_sha256"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

// Loaded is a fully parsed identity ready to build TLS configurations.
type Loaded struct {
	Identity
	Key         crypto.Signer
	Certificate *x509.Certificate
	TLS         tls.Certificate
	CA          *x509.Certificate
	CAPool      *x509.CertPool
}

// Store reads and writes identity files in a state directory.
type Store struct {
	Dir string
	// Probe selects the probe layout (probe.key, probe.crt, probe.json).
	Probe bool
}

// Path returns the absolute path of a file in the state directory.
func (s Store) Path(name string) string { return filepath.Join(s.Dir, name) }

// KeyFile, CertFile and IdentityFile are the names of the store's layout.
func (s Store) KeyFile() string {
	if s.Probe {
		return ProbeKeyFile
	}
	return KeyFile
}

func (s Store) CertFile() string {
	if s.Probe {
		return ProbeCertFile
	}
	return CertFile
}

func (s Store) IdentityFile() string {
	if s.Probe {
		return ProbeIdentityFile
	}
	return IdentityFile
}

// EnsureDir creates the state directory with mode 0700 if missing.
func (s Store) EnsureDir() error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	return nil
}

// Enrolled reports whether identity.json (probe.json) exists.
func (s Store) Enrolled() bool { return fsutil.Exists(s.Path(s.IdentityFile())) }

// Save writes key, certificate, CA and identity (in that order, identity
// last) atomically.
func (s Store) Save(id Identity, keyPEM, certPEM, caPEM []byte) error {
	if err := s.EnsureDir(); err != nil {
		return err
	}
	meta, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	meta = append(meta, '\n')
	files := []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{s.KeyFile(), keyPEM, 0o600},
		{s.CertFile(), certPEM, 0o644},
		{CAFile, caPEM, 0o644},
		{s.IdentityFile(), meta, 0o644},
	}
	for _, f := range files {
		if err := fsutil.WriteFileAtomic(s.Path(f.name), f.data, f.perm); err != nil {
			return err
		}
	}
	return matchDirOwner(s.Dir, s.KeyFile(), s.CertFile(), CAFile, s.IdentityFile())
}

// Remove deletes the identity and the cached configuration (used by
// `enroll --force`). The identity marker is removed first.
func (s Store) Remove() error {
	key, cert := s.KeyFile(), s.CertFile()
	for _, name := range []string{s.IdentityFile(), cert, CAFile, key, cert + ".new", key + ".new"} {
		if err := os.Remove(s.Path(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.RemoveAll(s.Path(ConfigDir)); err != nil {
		return err
	}
	return fsutil.SyncDir(s.Dir)
}

// ReadIdentity reads only identity.json (probe.json) without keys or
// certificates.
func (s Store) ReadIdentity() (*Identity, error) {
	name := s.IdentityFile()
	raw, err := os.ReadFile(s.Path(name))
	if errors.Is(err, os.ErrNotExist) {
		if s.Probe {
			return nil, ErrProbeNotEnrolled
		}
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	var id Identity
	if err := json.Unmarshal(raw, &id); err != nil {
		return nil, fmt.Errorf("parse %s: %w", name, err)
	}
	if s.Probe && (id.ProbeID == "" || id.ServerURL == "") {
		return nil, fmt.Errorf("%s is incomplete (probe_id/server_url missing)", name)
	}
	if !s.Probe && (id.NodeID == "" || id.ServerURL == "") {
		return nil, fmt.Errorf("%s is incomplete (node_id/server_url missing)", name)
	}
	return &id, nil
}

// Load reads and validates the identity. A certificate swap interrupted by
// a crash (see SwapCertificate) is completed transparently.
func (s Store) Load() (*Loaded, error) {
	idp, err := s.ReadIdentity()
	if err != nil {
		return nil, err
	}
	id := *idp

	caPEM, err := os.ReadFile(s.Path(CAFile))
	if err != nil {
		return nil, err
	}
	ca, err := pki.ParseCertificatePEM(caPEM)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", CAFile, err)
	}
	if id.CASHA256 != "" && pki.Fingerprint(ca) != id.CASHA256 {
		return nil, fmt.Errorf("%s does not match the pinned CA fingerprint", CAFile)
	}

	key, cert, err := s.loadPair()
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &Loaded{
		Identity:    id,
		Key:         key,
		Certificate: cert,
		TLS:         tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert},
		CA:          ca,
		CAPool:      pool,
	}, nil
}

func (s Store) readPair(keyName, certName string) (crypto.Signer, *x509.Certificate, error) {
	keyPEM, err := os.ReadFile(s.Path(keyName))
	if err != nil {
		return nil, nil, err
	}
	certPEM, err := os.ReadFile(s.Path(certName))
	if err != nil {
		return nil, nil, err
	}
	key, err := pki.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", keyName, err)
	}
	cert, err := pki.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", certName, err)
	}
	if !pki.SamePublicKey(cert, key) {
		return nil, nil, fmt.Errorf("%s does not match %s", certName, keyName)
	}
	return key, cert, nil
}

func (s Store) loadPair() (crypto.Signer, *x509.Certificate, error) {
	keyFile, certFile := s.KeyFile(), s.CertFile()
	key, cert, err := s.readPair(keyFile, certFile)
	if err == nil {
		return key, cert, nil
	}
	// A crash between the two renames of SwapCertificate leaves the new key
	// in place with node.crt.new still pending: finish the swap.
	if k2, c2, err2 := s.readPair(keyFile, certFile+".new"); err2 == nil {
		if err := fsutil.Rename(s.Path(certFile+".new"), s.Path(certFile)); err != nil {
			return nil, nil, err
		}
		return k2, c2, nil
	}
	return nil, nil, err
}

// SwapCertificate installs a renewed key pair. Both files are staged as
// *.new first, then renamed key-first; Load repairs an interrupted swap.
func (s Store) SwapCertificate(keyPEM, certPEM []byte) error {
	keyFile, certFile := s.KeyFile(), s.CertFile()
	if err := fsutil.WriteFileAtomic(s.Path(keyFile+".new"), keyPEM, 0o600); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(s.Path(certFile+".new"), certPEM, 0o644); err != nil {
		return err
	}
	if err := fsutil.Rename(s.Path(keyFile+".new"), s.Path(keyFile)); err != nil {
		return err
	}
	if err := fsutil.Rename(s.Path(certFile+".new"), s.Path(certFile)); err != nil {
		return err
	}
	return matchDirOwner(s.Dir, keyFile, certFile)
}

// WaitForEnrollment blocks until identity.json appears or ctx is done.
func (s Store) WaitForEnrollment(ctx context.Context, interval time.Duration, log *slog.Logger) error {
	if s.Enrolled() {
		return nil
	}
	log.Info("node is not enrolled yet; waiting for `edgeweir-node enroll`",
		"state_dir", s.Dir, "poll_interval", interval.String())
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if s.Enrolled() {
				log.Info("enrollment detected", "state_dir", s.Dir)
				return nil
			}
		}
	}
}
