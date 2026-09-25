package agent_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/edgeweir/edgeweir-node/internal/agent"
	nodev1 "github.com/edgeweir/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// TestAgentReportsFailedReload (N-L): after SIGHUP the agent waits for
// workers running the new nginx.conf; when nginx keeps the old workers
// (failed reload) the revision is reported as failed, the previous file is
// put back and the last-known-good configuration keeps serving.
func TestAgentReportsFailedReload(t *testing.T) {
	e := startEnrolled(t, "reload", func(c *agent.Config) { c.ReloadTimeout = 500 * time.Millisecond },
		demoSite("site-a", "site-a.test"))
	before, err := os.ReadFile(e.cfg.ConfPath)
	if err != nil {
		t.Fatal(err)
	}
	e.eng.mu.Lock()
	e.eng.ignoreReloads = true
	e.eng.mu.Unlock()

	cfg2 := baseConfig(demoSite("site-a", "site-a.test"), demoSite("site-b", "site-b.test"))
	cfg2.Listeners = append(cfg2.Listeners, &nodev1.Listener{Port: 8080, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTP})
	e.console.Publish(cfg2)
	eventually(t, "revision 2 reported as failed", statusWith(e.console, e.rev, nodev1.ApplyState_APPLY_STATE_FAILED))
	if msg := e.console.LastStatus().GetMessage(); !strings.Contains(msg, "did not load the new configuration") {
		t.Fatalf("message = %q", msg)
	}
	after, _ := os.ReadFile(e.cfg.ConfPath)
	if string(after) != string(before) {
		t.Fatal("the rejected nginx.conf stayed installed")
	}
	if tb := e.dp.Table(); tb.Revision != e.rev || len(tb.Sites) != 1 {
		t.Fatalf("data plane moved to the failed revision: %+v", tb)
	}

	// nginx accepts reloads again: the next revision applies.
	e.eng.mu.Lock()
	e.eng.ignoreReloads = false
	e.eng.mu.Unlock()
	cfg3 := baseConfig(demoSite("site-a", "site-a.test"), demoSite("site-b", "site-b.test"))
	cfg3.Listeners = append(cfg3.Listeners, &nodev1.Listener{Port: 8081, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTP})
	rev3 := e.console.Publish(cfg3)
	eventually(t, "revision 3 applied", statusWith(e.console, rev3, nodev1.ApplyState_APPLY_STATE_APPLIED))
	if conf, _ := os.ReadFile(e.cfg.ConfPath); !strings.Contains(string(conf), "listen 8081 default_server;") {
		t.Fatal("new nginx.conf not installed")
	}
}
