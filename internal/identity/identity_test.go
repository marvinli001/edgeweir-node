package identity

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
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
