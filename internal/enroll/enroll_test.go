package enroll_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"

	"github.com/marvinli001/edgeweir-node/internal/enroll"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/pki"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func setup(t *testing.T) (*fakeconsole.Console, string) {
	t.Helper()
	c, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-42", ClusterID: "cl-1", NodeName: "edge-a"})
	if err != nil {
		t.Fatal(err)
	}
	srv := c.StartTLS(t)
	return c, srv.URL
}

func opts(url, token, pin, dir string) enroll.Options {
	return enroll.Options{
		ServerURL: url,
		Token:     token,
		CASHA256:  pin,
		StateDir:  dir,
		Info:      &nodev1.NodeInfo{Hostname: "test-host"},
		Logger:    quietLogger(),
	}
}

func TestEnrollWritesIdentity(t *testing.T) {
	c, url := setup(t)
	c.AddToken("tok-1")
	dir := filepath.Join(t.TempDir(), "state")

	id, err := enroll.Run(context.Background(), opts(url, "tok-1", c.CA.Pin(), dir))
	if err != nil {
		t.Fatal(err)
	}
	if id.NodeID != "node-42" || id.ClusterID != "cl-1" || id.NodeName != "edge-a" {
		t.Fatalf("identity = %+v", id)
	}

	wantPerm := map[string]os.FileMode{
		identity.KeyFile:      0o600,
		identity.CertFile:     0o644,
		identity.CAFile:       0o644,
		identity.IdentityFile: 0o644,
	}
	for name, perm := range wantPerm {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Mode().Perm() != perm {
			t.Errorf("%s mode = %v, want %v", name, st.Mode().Perm(), perm)
		}
	}
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode = %v, want 0700", st.Mode().Perm())
	}

	raw, _ := os.ReadFile(filepath.Join(dir, identity.IdentityFile))
	var onDisk identity.Identity
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	if onDisk.ServerURL != url || onDisk.CASHA256 != c.CA.Pin() || onDisk.ServerName != "127.0.0.1" {
		t.Fatalf("identity.json = %+v", onDisk)
	}

	loaded, err := identity.Store{Dir: dir}.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Certificate.Subject.CommonName != "node-42" {
		t.Fatalf("certificate CN = %q", loaded.Certificate.Subject.CommonName)
	}
	if pki.Fingerprint(loaded.CA) != c.CA.Pin() {
		t.Fatal("stored CA does not match pin")
	}

	// Already enrolled: refuse without --force.
	c.AddToken("tok-2")
	if _, err := enroll.Run(context.Background(), opts(url, "tok-2", c.CA.Pin(), dir)); !errors.Is(err, enroll.ErrAlreadyEnrolled) {
		t.Fatalf("second enroll: err = %v, want ErrAlreadyEnrolled", err)
	}
	// With --force the identity is replaced with a new key.
	o := opts(url, "tok-2", c.CA.Pin(), dir)
	o.Force = true
	if _, err := enroll.Run(context.Background(), o); err != nil {
		t.Fatalf("forced enroll: %v", err)
	}
	reloaded, err := identity.Store{Dir: dir}.Load()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Certificate.SerialNumber.Cmp(loaded.Certificate.SerialNumber) == 0 {
		t.Fatal("forced enroll did not replace the certificate")
	}
}

func TestEnrollTokenIsSingleUse(t *testing.T) {
	c, url := setup(t)
	c.AddToken("once")
	if _, err := enroll.Run(context.Background(), opts(url, "once", c.CA.Pin(), t.TempDir())); err != nil {
		t.Fatal(err)
	}
	_, err := enroll.Run(context.Background(), opts(url, "once", c.CA.Pin(), t.TempDir()))
	if err == nil {
		t.Fatal("token reused successfully")
	}
	if code := connect.CodeOf(err); code != connect.CodePermissionDenied && code != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want permission_denied or unauthenticated (err %v)", code, err)
	}
}

func TestEnrollRejectsWrongPin(t *testing.T) {
	c, url := setup(t)
	c.AddToken("tok")
	dir := t.TempDir()
	other, err := fakeconsole.New(fakeconsole.Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = enroll.Run(context.Background(), opts(url, "tok", other.CA.Pin(), dir))
	if !errors.Is(err, pki.ErrPinMismatch) {
		t.Fatalf("err = %v, want ErrPinMismatch", err)
	}
	if (identity.Store{Dir: dir}).Enrolled() {
		t.Fatal("identity written despite pin mismatch")
	}
	// The token must not have been sent, so it is still usable.
	if _, err := enroll.Run(context.Background(), opts(url, "tok", c.CA.Pin(), dir)); err != nil {
		t.Fatalf("token was consumed by the rejected attempt: %v", err)
	}
}

func TestEnrollServerNameOverride(t *testing.T) {
	c, url := setup(t)
	c.AddToken("tok")
	o := opts(url, "tok", c.CA.Pin(), t.TempDir())
	o.ServerName = "wrong.test"
	if _, err := enroll.Run(context.Background(), o); err == nil {
		t.Fatal("enroll succeeded with a server name not in the certificate")
	}
	o.ServerName = "console.test"
	id, err := enroll.Run(context.Background(), o)
	if err != nil {
		t.Fatalf("enroll with --server-name console.test: %v", err)
	}
	if id.ServerName != "console.test" {
		t.Fatalf("server name = %q", id.ServerName)
	}
}

func TestEnrollValidatesInput(t *testing.T) {
	cases := []enroll.Options{
		{ServerURL: "https://x", CASHA256: "00", Token: "t"},
		{ServerURL: "http://x", CASHA256: string(make([]byte, 0)), Token: "t"},
		{ServerURL: "https://x", CASHA256: "0000000000000000000000000000000000000000000000000000000000000000"},
	}
	for i, o := range cases {
		o.StateDir = t.TempDir()
		o.Logger = quietLogger()
		if _, err := enroll.Run(context.Background(), o); err == nil {
			t.Errorf("case %d: invalid options accepted", i)
		}
	}
}
