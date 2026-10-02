package enroll_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
	// Not while an agent runs with the state directory (it holds the run
	// lock): the token is not used.
	o := opts(url, "tok-2", c.CA.Pin(), dir)
	o.Force = true
	unlock, err := identity.Store{Dir: dir}.LockRun()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enroll.Run(context.Background(), o); !errors.Is(err, enroll.ErrAgentRunning) {
		t.Fatalf("forced enroll with a running agent: err = %v, want ErrAgentRunning", err)
	}
	unlock()
	// With --force the identity is replaced with a new key.
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

func probeOpts(url, token, pin, dir string) enroll.ProbeOptions {
	return enroll.ProbeOptions{
		ServerURL: url,
		Token:     token,
		CASHA256:  pin,
		StateDir:  dir,
		Info:      &nodev1.ProbeInfo{Hostname: "probe-host", AgentVersion: "test"},
		Logger:    quietLogger(),
	}
}

// A probe enrolls with EnrollProbe into the probe layout of its own state
// directory: key 0600, certificate CN = probe id, no node files.
func TestEnrollProbe(t *testing.T) {
	c, err := fakeconsole.New(fakeconsole.Options{ProbeID: "probe-9", ProbeName: "east-1", RegionID: "region-east"})
	if err != nil {
		t.Fatal(err)
	}
	url := c.StartTLS(t).URL
	c.AddProbeToken("ptok")
	c.AddToken("ptok-node") // a node token is not a probe token
	dir := filepath.Join(t.TempDir(), "probe-state")
	if _, err := enroll.Probe(context.Background(), probeOpts(url, "ptok-node", c.CA.Pin(), dir)); err == nil {
		t.Fatal("probe enrolled with a node token")
	}

	id, err := enroll.Probe(context.Background(), probeOpts(url, "ptok", c.CA.Pin(), dir))
	if err != nil {
		t.Fatal(err)
	}
	if id.ProbeID != "probe-9" || id.ProbeName != "east-1" || id.RegionID != "region-east" || id.NodeID != "" {
		t.Fatalf("identity = %+v", id)
	}
	for name, perm := range map[string]os.FileMode{
		identity.ProbeKeyFile: 0o600, identity.ProbeCertFile: 0o644, identity.CAFile: 0o644, identity.ProbeIdentityFile: 0o644,
	} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if st.Mode().Perm() != perm {
			t.Errorf("%s mode = %v, want %v", name, st.Mode().Perm(), perm)
		}
	}
	for _, name := range []string{identity.KeyFile, identity.CertFile, identity.IdentityFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("node file %s written for a probe (%v)", name, err)
		}
	}
	if (identity.Store{Dir: dir}).Enrolled() {
		t.Fatal("probe state directory looks like an enrolled node")
	}
	loaded, err := identity.Store{Dir: dir, Probe: true}.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Certificate.Subject.CommonName != "probe-9" || loaded.ProbeID != "probe-9" || loaded.ServerURL != url ||
		loaded.CASHA256 != c.CA.Pin() || pki.Fingerprint(loaded.CA) != c.CA.Pin() {
		t.Fatalf("loaded probe identity: CN %q %+v", loaded.Certificate.Subject.CommonName, loaded.Identity)
	}
	raw, err := os.ReadFile(filepath.Join(dir, identity.ProbeIdentityFile))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "node_id") {
		t.Fatalf("probe.json has node fields: %s", raw)
	}

	// Enrolled: a second token is refused before anything is sent.
	c.AddProbeToken("ptok-2")
	if _, err := enroll.Probe(context.Background(), probeOpts(url, "ptok-2", c.CA.Pin(), dir)); !errors.Is(err, enroll.ErrProbeAlreadyEnrolled) {
		t.Fatalf("second enrollment: %v", err)
	}
	if n, _ := c.ProbeCounters(); n != 1 {
		t.Fatalf("probe enrollments = %d, want 1", n)
	}
	// The token was single use.
	if _, err := enroll.Probe(context.Background(), probeOpts(url, "ptok", c.CA.Pin(), t.TempDir())); err == nil {
		t.Fatal("probe token reused")
	}
}

// The CA pin is checked before the token leaves the probe.
func TestEnrollProbeRejectsWrongPin(t *testing.T) {
	c, url := setup(t)
	c.AddProbeToken("ptok")
	other, err := fakeconsole.New(fakeconsole.Options{})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if _, err := enroll.Probe(context.Background(), probeOpts(url, "ptok", other.CA.Pin(), dir)); !errors.Is(err, pki.ErrPinMismatch) {
		t.Fatalf("err = %v, want ErrPinMismatch", err)
	}
	if (identity.Store{Dir: dir, Probe: true}).Enrolled() {
		t.Fatal("identity written despite pin mismatch")
	}
	if _, err := enroll.Probe(context.Background(), probeOpts(url, "ptok", c.CA.Pin(), dir)); err != nil {
		t.Fatalf("token was consumed by the rejected attempt: %v", err)
	}
}
