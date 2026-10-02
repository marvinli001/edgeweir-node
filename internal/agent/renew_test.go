package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/agent"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

// TestRenewWhileDisabled: the console refuses a disabled node's heartbeats,
// and the node still renews a certificate that is due, so the certificate
// has not expired when the node is enabled again.
func TestRenewWhileDisabled(t *testing.T) {
	// Less than a third of the lifetime is left as soon as it is issued.
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-r", ClusterID: "cl-r", ReportInterval: 1, CertLifetime: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	console.RefuseReports(true)
	srv := console.StartTLS(t)
	root := t.TempDir()
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}
	console.Publish(baseConfig(demoSite("site-r", "r.test")))
	dp := fakedataplane.Start(t)
	startAgent(t, h.agentConfig(dp.Socket), newFakeEngine(), dataplane.NewClient(dp.Socket))
	console.AddToken("r-token")
	if _, err := enroll.Run(context.Background(), enroll.Options{
		ServerURL: srv.URL, Token: "r-token", CASHA256: console.CA.Pin(), StateDir: h.stateDir, Logger: testLogger(t),
	}); err != nil {
		t.Fatal(err)
	}
	enrolled, err := identity.Store{Dir: h.stateDir}.Load()
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "certificate renewed while heartbeats are refused", func() bool {
		after, err := identity.Store{Dir: h.stateDir}.Load()
		return err == nil && after.Certificate.SerialNumber.Cmp(enrolled.Certificate.SerialNumber) != 0
	})
	if n := len(console.Statuses()); n != 0 {
		t.Fatalf("%d heartbeats accepted while refused", n)
	}
	console.RefuseReports(false)
	eventually(t, "heartbeats resume once enabled", func() bool { return len(console.Statuses()) > 0 })
}

// rewriteIdentity changes the node id in identity.json behind the agent's
// back, like an older `enroll --force` or a copied state directory.
func rewriteIdentity(t *testing.T, dir, nodeID string) {
	t.Helper()
	id, err := identity.Store{Dir: dir}.ReadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	id.NodeID = nodeID
	raw, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, identity.IdentityFile), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestAgentStopsOnANewIdentity (P1-61): `enroll --force` is refused while
// the agent runs; an identity.json that names another node all the same
// stops the agent (errIdentityChanged), so that it starts again with it.
func TestAgentStopsOnANewIdentity(t *testing.T) {
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-i", ClusterID: "cl-i", ReportInterval: 1})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	root := t.TempDir()
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}
	rev := console.Publish(baseConfig(demoSite("site-i", "i.test")))
	dp := fakedataplane.Start(t)
	cfg := h.agentConfig(dp.Socket)
	cfg.IdentityInterval = 50 * time.Millisecond
	eng := newFakeEngine()
	eng.confPath, eng.dp = cfg.ConfPath, fakedataplane.Lookup(dp.Socket)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- agent.New(cfg, eng, dataplane.NewClient(dp.Socket), testLogger(t)).Run(ctx) }()
	opts := enroll.Options{ServerURL: srv.URL, Token: "i-token", CASHA256: console.CA.Pin(), StateDir: h.stateDir, Logger: testLogger(t)}
	console.AddToken("i-token")
	if _, err := enroll.Run(context.Background(), opts); err != nil {
		t.Fatalf("the first enrollment while the agent waits: %v", err)
	}
	eventually(t, "configuration applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	console.AddToken("i-token-2")
	opts.Token, opts.Force = "i-token-2", true
	if _, err := enroll.Run(context.Background(), opts); !errors.Is(err, enroll.ErrAgentRunning) {
		t.Fatalf("enroll --force while running: %v", err)
	}
	rewriteIdentity(t, h.stateDir, "node-other")
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "identity changed") {
			t.Fatalf("Run = %v, want the identity change", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the agent kept running with the old identity")
	}
}

// TestRenewalKeepsANewIdentity (P1-61): a renewal that completes after the
// node was enrolled again does not write the old node's certificate and
// key over the new identity.
func TestRenewalKeepsANewIdentity(t *testing.T) {
	e := startEnrolled(t, "renew-id", func(c *agent.Config) { c.IdentityInterval = time.Hour }, demoSite("site-a", "site-a.test"))
	key, err := os.ReadFile(filepath.Join(e.h.stateDir, identity.KeyFile))
	if err != nil {
		t.Fatal(err)
	}
	rewriteIdentity(t, e.h.stateDir, "node-other")
	renewals := func() int { _, n, _, _ := e.console.Counters(); return n }
	before := renewals()
	e.console.RequestRenewal()
	eventually(t, "renewal requested", func() bool { return renewals() > before })
	time.Sleep(200 * time.Millisecond)
	if after, err := os.ReadFile(filepath.Join(e.h.stateDir, identity.KeyFile)); err != nil || !bytes.Equal(after, key) {
		t.Fatalf("node.key replaced after the identity changed (%v)", err)
	}
}
