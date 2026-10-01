package agent_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
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
