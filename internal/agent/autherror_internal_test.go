package agent

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/marvinli001/edgeweir-node/internal/controlplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

// TestLogRPCErrorNamesAnExpiredCertificate: when the console refuses the
// node and the identity certificate is past its NotAfter, the log says so
// (and how to recover) instead of guessing between deletion, revocation and
// expiry.
func TestLogRPCErrorNamesAnExpiredCertificate(t *testing.T) {
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-exp", ClusterID: "cl-exp", CertLifetime: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	dir := filepath.Join(t.TempDir(), "state")
	console.AddToken("exp-token")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := enroll.Run(ctx, enroll.Options{ServerURL: srv.URL, Token: "exp-token", CASHA256: console.CA.Pin(), StateDir: dir}); err != nil {
		t.Fatal(err)
	}
	ch, err := controlplane.NewChannel(identity.Store{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()

	notAfter := ch.Identity().Certificate.NotAfter
	if _, expired := identityExpired(ch, notAfter.Add(-time.Second)); expired {
		t.Fatal("a valid certificate counted as expired")
	}
	if got, expired := identityExpired(ch, notAfter.Add(time.Second)); !expired || !got.Equal(notAfter) {
		t.Fatalf("identityExpired after NotAfter = %v, %v", got, expired)
	}
	if _, expired := identityExpired(nil, time.Now()); expired {
		t.Fatal("no channel counted as expired")
	}

	var buf bytes.Buffer
	a := &Agent{log: slog.New(slog.NewTextHandler(&buf, nil))}
	refused := connect.NewError(connect.CodeUnauthenticated, errors.New("client certificate has expired (CERT_HAS_EXPIRED)"))
	generic := "the console rejected this node's credentials"

	// Before the channel opens, and while the certificate is valid: the generic hint.
	a.logRPCError("ReportStatus failed", refused)
	a.connectedCh.Store(ch)
	a.logRPCError("ReportStatus failed", refused)
	if got := strings.Count(buf.String(), generic); got != 2 {
		t.Fatalf("generic hints = %d, log:\n%s", got, buf.String())
	}

	time.Sleep(time.Until(notAfter) + 100*time.Millisecond)
	buf.Reset()
	a.logRPCError("ReportStatus failed", refused)
	out := buf.String()
	for _, want := range []string{"level=ERROR", "client certificate expired at " + notAfter.UTC().Format(time.RFC3339), "edgeweir-node enroll --force"} {
		if !strings.Contains(out, want) {
			t.Errorf("log lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, generic) {
		t.Errorf("expired certificate logged with the generic hint:\n%s", out)
	}

	// Other errors stay warnings.
	buf.Reset()
	a.logRPCError("ReportStatus failed", connect.NewError(connect.CodeUnavailable, errors.New("down")))
	if !strings.Contains(buf.String(), "level=WARN") || strings.Contains(buf.String(), "expired") {
		t.Fatalf("unavailable console logged as:\n%s", buf.String())
	}
}
