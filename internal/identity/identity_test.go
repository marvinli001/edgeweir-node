package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/pki"
	"github.com/marvinli001/edgeweir-node/internal/pki/pkitest"
)

func issue(t *testing.T, ca *pkitest.CA) (keyPEM, certPEM []byte) {
	t.Helper()
	key, err := pki.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.CreateCSR(key, "host")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err = ca.SignCSR(csr, "node-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err = pki.MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	return keyPEM, certPEM
}

func newStore(t *testing.T) (Store, *pkitest.CA) {
	t.Helper()
	ca, err := pkitest.NewCA("test")
	if err != nil {
		t.Fatal(err)
	}
	s := Store{Dir: t.TempDir()}
	keyPEM, certPEM := issue(t, ca)
	id := Identity{NodeID: "node-1", ClusterID: "c", ServerURL: "https://console:8443", CASHA256: ca.Pin()}
	if err := s.Save(id, keyPEM, certPEM, ca.PEM); err != nil {
		t.Fatal(err)
	}
	return s, ca
}

func TestSaveLoad(t *testing.T) {
	s, ca := newStore(t)
	l, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if l.NodeID != "node-1" || pki.Fingerprint(l.CA) != ca.Pin() || l.TLS.Leaf == nil {
		t.Fatalf("loaded = %+v", l.Identity)
	}
	if _, err := (Store{Dir: t.TempDir()}).Load(); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("empty dir: err = %v, want ErrNotEnrolled", err)
	}
}

func TestLoadRejectsTamperedCA(t *testing.T) {
	s, _ := newStore(t)
	other, _ := pkitest.NewCA("other")
	if err := os.WriteFile(s.Path(CAFile), other.PEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("CA not matching the pin was accepted")
	}
}

func TestSwapCertificateAndRecovery(t *testing.T) {
	s, ca := newStore(t)
	before, _ := s.Load()

	keyPEM, certPEM := issue(t, ca)
	if err := s.SwapCertificate(keyPEM, certPEM); err != nil {
		t.Fatal(err)
	}
	after, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if after.Certificate.SerialNumber.Cmp(before.Certificate.SerialNumber) == 0 {
		t.Fatal("certificate not swapped")
	}
	st, _ := os.Stat(s.Path(KeyFile))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("renewed key mode = %v", st.Mode().Perm())
	}

	// Simulate a crash after the key rename but before the cert rename.
	keyPEM2, certPEM2 := issue(t, ca)
	if err := os.WriteFile(s.Path(CertFile+".new"), certPEM2, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Path(KeyFile), keyPEM2, 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := s.Load()
	if err != nil {
		t.Fatalf("interrupted swap not recovered: %v", err)
	}
	if !pki.SamePublicKey(recovered.Certificate, recovered.Key) {
		t.Fatal("recovered pair mismatched")
	}
	if _, err := os.Stat(s.Path(CertFile + ".new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pending certificate not moved into place")
	}
}

func TestWaitForEnrollment(t *testing.T) {
	ca, _ := pkitest.NewCA("test")
	s := Store{Dir: t.TempDir()}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.WaitForEnrollment(ctx, 10*time.Millisecond, log); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want deadline exceeded", err)
	}

	done := make(chan error, 1)
	go func() { done <- s.WaitForEnrollment(context.Background(), 10*time.Millisecond, log) }()
	keyPEM, certPEM := issue(t, ca)
	if err := s.Save(Identity{NodeID: "n", ServerURL: "https://x"}, keyPEM, certPEM, ca.PEM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("enrollment not detected")
	}
}

// The probe layout keeps its own file names and requires a probe id; a node
// store in the same directory sees nothing.
func TestProbeLayout(t *testing.T) {
	ca, _ := pkitest.NewCA("test")
	dir := t.TempDir()
	s := Store{Dir: dir, Probe: true}
	keyPEM, certPEM := issue(t, ca)
	if err := s.Save(Identity{NodeID: "n"}, keyPEM, certPEM, ca.PEM); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "probe_id") {
		t.Fatalf("probe.json without probe id: %v", err)
	}
	id := Identity{ProbeID: "probe-1", ProbeName: "east", RegionID: "r1", ServerURL: "https://console:8443", CASHA256: ca.Pin()}
	if err := s.Save(id, keyPEM, certPEM, ca.PEM); err != nil {
		t.Fatal(err)
	}
	l, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if l.ProbeID != "probe-1" || l.RegionID != "r1" || l.TLS.Leaf == nil {
		t.Fatalf("loaded %+v", l.Identity)
	}
	for _, name := range []string{ProbeKeyFile, ProbeCertFile, CAFile, ProbeIdentityFile} {
		if _, err := os.Stat(s.Path(name)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if st, _ := os.Stat(s.Path(ProbeKeyFile)); st.Mode().Perm() != 0o600 {
		t.Fatalf("probe.key mode %v", st.Mode().Perm())
	}
	node := Store{Dir: dir}
	if node.Enrolled() {
		t.Fatal("node store sees the probe identity")
	}
	if _, err := node.Load(); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("node Load: %v", err)
	}
	if _, err := (Store{Dir: t.TempDir(), Probe: true}).Load(); !errors.Is(err, ErrProbeNotEnrolled) {
		t.Fatalf("empty probe dir: %v", err)
	}

	keyPEM2, certPEM2 := issue(t, ca)
	if err := s.SwapCertificate(keyPEM2, certPEM2); err != nil {
		t.Fatal(err)
	}
	after, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if after.Certificate.SerialNumber.Cmp(l.Certificate.SerialNumber) == 0 {
		t.Fatal("probe certificate not swapped")
	}
	if st, _ := os.Stat(s.Path(ProbeKeyFile)); st.Mode().Perm() != 0o600 {
		t.Fatalf("renewed probe.key mode %v", st.Mode().Perm())
	}
	if _, err := os.Stat(s.Path(KeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("renewal wrote node.key into the probe directory")
	}
}

// TestUpdateServer: only the console addresses change, atomically, and
// only for the enrollment the caller loaded.
func TestUpdateServer(t *testing.T) {
	s, _ := newStore(t)
	before, err := s.ReadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	keyBefore, _ := os.ReadFile(s.Path(KeyFile))
	at := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	got, err := s.UpdateServer(*before, func(next *Identity) {
		next.FallbackServerURL, next.FallbackServerName = next.ServerURL, next.ServerName
		next.ServerURL, next.ServerName = "wss://console.example.com", ""
		next.ServerSource, next.ServerChangedAt = ServerSourceConsole, at
	})
	if err != nil {
		t.Fatal(err)
	}
	read, err := s.ReadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if *read != *got || read.ServerURL != "wss://console.example.com" || read.FallbackServerURL != "https://console:8443" ||
		read.ServerSource != ServerSourceConsole || !read.ServerChangedAt.Equal(at) || !SameIdentity(*read, *before) {
		t.Fatalf("identity = %+v", read)
	}
	if keyAfter, _ := os.ReadFile(s.Path(KeyFile)); string(keyAfter) != string(keyBefore) {
		t.Fatal("the key changed")
	}
	if _, err := s.Load(); err != nil {
		t.Fatalf("load after the update: %v", err)
	}

	// Another enrollment meanwhile: nothing is written.
	other := *before
	other.EnrolledAt = before.EnrolledAt.Add(time.Second)
	if _, err := s.UpdateServer(other, func(next *Identity) { next.ServerURL = "https://elsewhere:8443" }); !errors.Is(err, ErrIdentityReplaced) {
		t.Fatalf("replaced identity: %v", err)
	}
	// The update may not touch the identity itself.
	if _, err := s.UpdateServer(*read, func(next *Identity) { next.NodeID = "node-2" }); err == nil {
		t.Fatal("the node id changed through UpdateServer")
	}
	if cur, _ := s.ReadIdentity(); cur.ServerURL != "wss://console.example.com" || cur.NodeID != "node-1" {
		t.Fatalf("identity after refused updates = %+v", cur)
	}
}

// TestIdentityFileReadByOlderAgents: an agent before channel-follow-v1
// (which knows only the enrollment fields) reads the changed address from
// the same file, so a downgrade keeps the address the node switched to.
func TestIdentityFileReadByOlderAgents(t *testing.T) {
	s, _ := newStore(t)
	before, _ := s.ReadIdentity()
	if _, err := s.UpdateServer(*before, func(next *Identity) {
		next.FallbackServerURL, next.ServerURL, next.ServerSource = next.ServerURL, "https://new.example.com:8443", ServerSourceCommand
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.Path(IdentityFile))
	if err != nil {
		t.Fatal(err)
	}
	var older struct {
		NodeID     string    `json:"node_id,omitempty"`
		ClusterID  string    `json:"cluster_id,omitempty"`
		NodeName   string    `json:"node_name,omitempty"`
		ServerURL  string    `json:"server_url"`
		ServerName string    `json:"server_name"`
		CASHA256   string    `json:"ca_sha256"`
		EnrolledAt time.Time `json:"enrolled_at"`
	}
	if err := json.Unmarshal(raw, &older); err != nil {
		t.Fatal(err)
	}
	if older.ServerURL != "https://new.example.com:8443" || older.NodeID != "node-1" {
		t.Fatalf("older agent reads %+v", older)
	}
	// An identity that never changed address carries none of the new fields.
	s2, _ := newStore(t)
	raw, _ = os.ReadFile(s2.Path(IdentityFile))
	for _, field := range []string{"fallback_server_url", "server_source", "server_changed_at"} {
		if strings.Contains(string(raw), field) {
			t.Errorf("%s written for an unchanged identity:\n%s", field, raw)
		}
	}
}

// TestUpdateServerWithAnotherUsersLock: the identity lock is opened
// read-only, so a lock file another user created (root running
// set-server, the service user running the agent) does not block it.
func TestUpdateServerWithAnotherUsersLock(t *testing.T) {
	s, _ := newStore(t)
	if err := os.WriteFile(s.Path(IdentityLockFile), nil, 0o444); err != nil {
		t.Fatal(err)
	}
	before, _ := s.ReadIdentity()
	if _, err := s.UpdateServer(*before, func(next *Identity) { next.ServerURL = "https://other.example.com:8443" }); err != nil {
		t.Fatalf("update with a read-only lock file: %v", err)
	}
	s2, _ := newStore(t)
	before2, _ := s2.ReadIdentity()
	if _, err := s2.UpdateServer(*before2, func(next *Identity) { next.ServerURL = "https://other.example.com:8443" }); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(s2.Path(IdentityLockFile)); err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("identity.lock: %v %v", st, err)
	}
}
