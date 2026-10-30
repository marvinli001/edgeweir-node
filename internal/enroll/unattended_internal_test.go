package enroll

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/pki"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

func csrKey(t *testing.T, csrPEM []byte) string {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("no CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(der)
}

// An attempt whose answer is lost (the console may have issued the
// certificate) is retried with the same key, so that the console can
// answer with the node it already created; the pending key becomes
// node.key and is gone once an enrollment is saved.
func TestRetryReusesPendingKey(t *testing.T) {
	ca, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-7"})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "state")
	store := identity.Store{Dir: dir}
	c := common{serverURL: "https://console.test:8443", token: "tok", caSHA256: ca.CA.Pin(), kind: "node",
		log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	var keys []string
	lost := func(_ context.Context, _, _, _ string, csrPEM []byte) (*issued, error) {
		keys = append(keys, csrKey(t, csrPEM))
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("connection reset"))
	}
	for range 2 {
		if _, err := run(context.Background(), c, store, "host", lost); Outcome(err).Status != StatusUnreachable {
			t.Fatalf("lost answer: %v (%s)", err, Outcome(err).Status)
		}
	}
	if st, err := os.Stat(store.Path(identity.PendingKeyFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("pending key: %v %v", st, err)
	}
	ok := func(_ context.Context, _, _, _ string, csrPEM []byte) (*issued, error) {
		keys = append(keys, csrKey(t, csrPEM))
		certPEM, _, err := ca.CA.SignCSR(csrPEM, "node-7", time.Hour)
		if err != nil {
			return nil, err
		}
		return &issued{id: identity.Identity{NodeID: "node-7"}, subject: "node-7", certPEM: string(certPEM), caPEM: string(ca.CA.PEM)}, nil
	}
	if _, err := run(context.Background(), c, store, "host", ok); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 || keys[0] != keys[1] || keys[1] != keys[2] {
		t.Fatal("retries did not reuse the pending key")
	}
	if _, err := os.Stat(store.Path(identity.PendingKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending key left after the enrollment: %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(loaded.Certificate.PublicKey)
	if string(der) != keys[0] {
		t.Fatal("node.key is not the pending key")
	}
	// A forced enrollment later starts with a new key.
	c.force = true
	if _, err := run(context.Background(), c, store, "host", ok); err != nil {
		t.Fatal(err)
	}
	if keys[3] == keys[0] {
		t.Fatal("forced enrollment reused the enrolled key")
	}
}

// Two enrollments of one host at once: the second fails as busy before
// anything is sent.
func TestConcurrentEnrollmentIsBusy(t *testing.T) {
	dir := t.TempDir()
	store := identity.Store{Dir: dir}
	release, err := store.LockEnroll()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	sent := false
	c := common{serverURL: "https://console.test", token: "tok", caSHA256: strings.Repeat("ab", 32), kind: "node"}
	_, err = run(context.Background(), c, store, "host", func(context.Context, string, string, string, []byte) (*issued, error) {
		sent = true
		return nil, errors.New("unreachable")
	})
	if !errors.Is(err, ErrBusy) || sent {
		t.Fatalf("err = %v, sent = %v", err, sent)
	}
	if r := Outcome(err); r.Status != StatusBusy || r.Exit != ExitBusy || !r.Retry {
		t.Fatalf("outcome = %+v", r)
	}
}

func TestOutcome(t *testing.T) {
	for _, c := range []struct {
		err    error
		status string
		exit   int
		retry  bool
	}{
		{fmt.Errorf("%w: x", ErrInvalidOptions), StatusUsage, 2, false},
		{ErrAlreadyEnrolled, StatusAlreadyEnrolled, 10, false},
		{ErrEnrolledElsewhere, StatusEnrolledElsewhere, 11, false},
		{fmt.Errorf("%w: %w", ErrTokenRejected, connect.NewError(connect.CodePermissionDenied, errors.New("used"))), StatusTokenRejected, 12, false},
		{fmt.Errorf("enroll: %w", connect.NewError(connect.CodeUnavailable, errors.New("dial tcp: connection refused"))), StatusUnreachable, 13, true},
		{fmt.Errorf("enroll: %w", connect.NewError(connect.CodeDeadlineExceeded, context.DeadlineExceeded)), StatusUnreachable, 13, true},
		{fmt.Errorf("enroll: %w", connect.NewError(connect.CodeUnavailable, fmt.Errorf("tls: %w", pki.ErrPinMismatch))), StatusCAMismatch, 14, false},
		{fmt.Errorf("enroll: %w", connect.NewError(connect.CodeUnavailable, fmt.Errorf("%w: x509: certificate is valid for a, not b", pki.ErrServerCertificate))), StatusCAMismatch, 14, false},
		{responseError{fmt.Errorf("enroll response: %w: other CA", pki.ErrPinMismatch)}, StatusCAMismatch, 14, false},
		{fmt.Errorf("%w: read-only file system", ErrStateDir), StatusStateDir, 15, false},
		{ErrAgentRunning, StatusBusy, 16, false},
		{fmt.Errorf("enroll: %w", connect.NewError(connect.CodeInvalidArgument, errors.New("bad CSR"))), StatusConsoleError, 17, false},
		{fmt.Errorf("enroll: %w", connect.NewError(connect.CodeInternal, errors.New("db"))), StatusConsoleError, 17, true},
		{fmt.Errorf("enroll: %w", responseError{errors.New("enroll response: empty node_id")}), StatusConsoleError, 17, false},
		{errors.New("something else"), StatusError, 1, false},
	} {
		r := Outcome(c.err)
		if r.Status != c.status || r.Exit != c.exit || r.Retry != c.retry || r.Message != c.err.Error() {
			t.Errorf("Outcome(%v) = %+v, want %s/%d/%v", c.err, r, c.status, c.exit, c.retry)
		}
	}
}

func TestResultLine(t *testing.T) {
	var b bytes.Buffer
	if err := Succeeded(&identity.Identity{NodeID: "n1", NodeName: "edge", ClusterID: "c1"}, time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)).Write(&b); err != nil {
		t.Fatal(err)
	}
	line := b.String()
	if !strings.HasPrefix(line, ResultPrefix) || strings.Count(line, "\n") != 1 {
		t.Fatalf("line = %q", line)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, ResultPrefix)), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"v": 1.0, "step": "enroll", "status": "enrolled", "exit": 0.0, "retry": false,
		"node_id": "n1", "node_name": "edge", "cluster_id": "c1", "not_after": "2027-01-02T03:04:05Z"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("result = %v\nwant     %v", got, want)
	}
}

func TestExisting(t *testing.T) {
	dir := t.TempDir()
	pin := strings.Repeat("ab", 32)
	if _, err := Existing(dir, pin); !errors.Is(err, identity.ErrNotEnrolled) {
		t.Fatalf("not enrolled: %v", err)
	}
	if _, err := Existing(dir, "nope"); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("bad pin: %v", err)
	}
	raw, _ := json.Marshal(identity.Identity{NodeID: "n1", ServerURL: "https://console.test", CASHA256: pin})
	if err := os.WriteFile(filepath.Join(dir, identity.IdentityFile), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if id, err := Existing(dir, strings.ToUpper(pin)); err != nil || id.NodeID != "n1" {
		t.Fatalf("same console: %v %v", id, err)
	}
	if id, err := Existing(dir, strings.Repeat("cd", 32)); !errors.Is(err, ErrEnrolledElsewhere) || id.CASHA256 != pin {
		t.Fatalf("other console: %v %v", id, err)
	}
}
