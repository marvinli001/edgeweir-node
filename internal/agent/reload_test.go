package agent_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/agent"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func TestUnknownEnumKeepsLastKnownGood(t *testing.T) {
	e := startEnrolled(t, "unknown-enum", nil, demoSite("site-a", "site-a.test"))
	next := baseConfig(demoSite("site-b", "site-b.test"))
	next.Listeners[0].Protocol = 999
	e.console.Publish(next)
	eventually(t, "unknown enum rejected", statusWith(e.console, e.rev, nodev1.ApplyState_APPLY_STATE_FAILED))
	if table := e.dp.Table(); table.Revision != e.rev || table.Sites[0].ID != "site-a" {
		t.Fatalf("unknown semantics replaced LKG: %+v", table)
	}
}

func TestPersistenceFailureDoesNotReportNewRevisionApplied(t *testing.T) {
	e := startEnrolled(t, "persist-failure", func(c *agent.Config) { c.PollInterval = 40 * time.Millisecond }, demoSite("site-a", "site-a.test"))
	current := filepath.Join(e.cfg.StateDir, "config", "current.binpb")
	if err := os.Remove(current); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(current, 0o700); err != nil {
		t.Fatal(err)
	}
	e.console.Publish(baseConfig(demoSite("site-b", "site-b.test")))
	eventually(t, "persistence failure reported", statusWith(e.console, e.rev, nodev1.ApplyState_APPLY_STATE_FAILED))
	if table := e.dp.Table(); table.Revision != e.rev || table.Sites[0].ID != "site-a" {
		t.Fatalf("uncommitted configuration stayed active: %+v", table)
	}
	// Poll retries must not keep reactivating the revision that cannot be saved.
	for range 20 {
		time.Sleep(20 * time.Millisecond)
		if table := e.dp.Table(); table.Revision != e.rev {
			t.Fatalf("retry reactivated unsaved revision: %d", table.Revision)
		}
	}
}

func TestRejectedTableRestoresReloadedListeners(t *testing.T) {
	e := startEnrolled(t, "activation", nil, demoSite("site-a", "site-a.test"))
	before, err := os.ReadFile(e.cfg.ConfPath)
	if err != nil {
		t.Fatal(err)
	}
	e.dp.RejectRevision(e.rev + 1)
	next := baseConfig(demoSite("site-a", "site-a.test"), demoSite("site-b", "site-b.test"))
	next.Listeners = append(next.Listeners, &nodev1.Listener{Port: 8443, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTPS})
	e.console.Publish(next)
	eventually(t, "table rejection reported", statusWith(e.console, e.rev, nodev1.ApplyState_APPLY_STATE_FAILED))
	after, err := os.ReadFile(e.cfg.ConfPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed activation left new listeners installed")
	}
	time.Sleep(300 * time.Millisecond)
	if table := e.dp.Table(); table.Revision != e.rev || len(table.Sites) != 1 {
		t.Fatalf("reconciliation activated failed table: %+v", table)
	}
}

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

// TestAgentIgnoresOlderRevisions: a console that serves an older revision
// than the applied one (e.g. restored from a backup) never makes the node
// go back; the node keeps its last-known-good configuration and reports
// it as applied.
func TestAgentIgnoresOlderRevisions(t *testing.T) {
	e := startEnrolled(t, "stale", func(c *agent.Config) { c.PollInterval = 100 * time.Millisecond },
		demoSite("site-a", "site-a.test"))
	rev2 := e.console.Publish(baseConfig(demoSite("site-a", "site-a.test"), demoSite("site-b", "site-b.test")))
	eventually(t, "revision 2 applied", statusWith(e.console, rev2, nodev1.ApplyState_APPLY_STATE_APPLIED))
	e.console.PinLatest(e.rev)
	calls := len(e.console.GetConfigCalls())
	eventually(t, "older revision served a few times", func() bool {
		n := 0
		for _, c := range e.console.GetConfigCalls()[calls:] {
			if c.Revision == e.rev && c.Snapshot {
				n++
			}
		}
		return n >= 3
	})
	eventually(t, "a fresh report", func() bool { return len(e.console.Statuses()) > 0 })
	if st := e.console.LastStatus(); st.GetAppliedRevision() != rev2 || st.GetState() != nodev1.ApplyState_APPLY_STATE_APPLIED {
		t.Fatalf("status = %v, want revision %d applied", st, rev2)
	}
	if tb := e.dp.Table(); tb.Revision != rev2 || len(tb.Sites) != 2 {
		t.Fatalf("data plane went back to %+v", tb)
	}
}

// TestAgentDoesNotRetryRejectedRevision: a revision rejected for a
// deterministic reason (here `nginx -t`) is not tried again on every poll;
// a new revision is.
func TestAgentDoesNotRetryRejectedRevision(t *testing.T) {
	e := startEnrolled(t, "reject", func(c *agent.Config) { c.PollInterval = 100 * time.Millisecond },
		demoSite("site-a", "site-a.test"))
	e.eng.mu.Lock()
	e.eng.failTests = true
	e.eng.mu.Unlock()
	structural := func(port uint32) *nodev1.NodeConfig {
		c := baseConfig(demoSite("site-a", "site-a.test"))
		c.Listeners = append(c.Listeners, &nodev1.Listener{Port: port, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTP})
		return c
	}
	e.console.Publish(structural(8080))
	eventually(t, "revision 2 rejected", statusWith(e.console, e.rev, nodev1.ApplyState_APPLY_STATE_FAILED))
	if msg := e.console.LastStatus().GetMessage(); !strings.Contains(msg, "injected configuration test failure") {
		t.Fatalf("message = %q", msg)
	}
	tests, _, _ := e.eng.counts()
	calls := len(e.console.GetConfigCalls())
	eventually(t, "more polls", func() bool { return len(e.console.GetConfigCalls()) >= calls+5 })
	if again, _, _ := e.eng.counts(); again != tests {
		t.Fatalf("rejected revision tested again: %d -> %d nginx -t runs", tests, again)
	}
	e.console.Publish(structural(8081))
	eventually(t, "the next revision is tried", func() bool { n, _, _ := e.eng.counts(); return n > tests })
}

// TestAgentRetriesAnInterruptedTest (P1-60): `nginx -t` cut short by its
// timeout says nothing about the configuration: the revision is retried
// with the next poll instead of being rejected for five minutes.
func TestAgentRetriesAnInterruptedTest(t *testing.T) {
	e := startEnrolled(t, "interrupted", func(c *agent.Config) {
		c.PollInterval = 100 * time.Millisecond
		c.TestTimeout = 100 * time.Millisecond
	}, demoSite("site-a", "site-a.test"))
	e.eng.mu.Lock()
	e.eng.hangTests = true
	e.eng.mu.Unlock()
	c := baseConfig(demoSite("site-a", "site-a.test"))
	c.Listeners = append(c.Listeners, &nodev1.Listener{Port: 8080, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTP})
	rev := e.console.Publish(c)
	eventually(t, "revision 2 failed", statusWith(e.console, e.rev, nodev1.ApplyState_APPLY_STATE_FAILED))
	if msg := e.console.LastStatus().GetMessage(); !strings.Contains(msg, "interrupted: context deadline exceeded") {
		t.Fatalf("message = %q", msg)
	}
	tests, _, _ := e.eng.counts()
	eventually(t, "tested again", func() bool { n, _, _ := e.eng.counts(); return n >= tests+2 })
	e.eng.mu.Lock()
	e.eng.hangTests = false
	e.eng.mu.Unlock()
	eventually(t, "revision 2 applied", statusWith(e.console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
}

// TestAgentDoesNotRetryATableThatDoesNotFit (P1-62): a site table the data
// plane has no room for (507) fails like a rejected one, naming the flag
// to raise, instead of being pushed again and again.
func TestAgentDoesNotRetryATableThatDoesNotFit(t *testing.T) {
	e := startEnrolled(t, "toolarge", func(c *agent.Config) { c.PollInterval = 100 * time.Millisecond },
		demoSite("site-a", "site-a.test"))
	e.dp.TooLarge(e.rev + 1)
	e.console.Publish(baseConfig(demoSite("site-a", "site-a.test"), demoSite("site-b", "site-b.test")))
	eventually(t, "revision 2 failed", statusWith(e.console, e.rev, nodev1.ApplyState_APPLY_STATE_FAILED))
	if msg := e.console.LastStatus().GetMessage(); !strings.Contains(msg, "does not fit the data plane's site store (--sites-dict-mb 64)") {
		t.Fatalf("message = %q", msg)
	}
	puts := e.dp.PutCalls()
	calls := len(e.console.GetConfigCalls())
	eventually(t, "more polls", func() bool { return len(e.console.GetConfigCalls()) >= calls+5 })
	// The previous table may be pushed back once; the new one is not retried.
	if n := e.dp.PutCalls(); n > puts+1 {
		t.Fatalf("site table pushed %d more times", n-puts)
	}
}
