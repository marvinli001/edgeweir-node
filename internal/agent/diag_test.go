package agent_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/agent"
	"github.com/marvinli001/edgeweir-node/internal/diag"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

// shortDir is a directory for unix sockets (t.TempDir can exceed their
// path limit on macOS).
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ewd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// The heartbeats measure the clock against the console's console_time and
// report it from the next one on; the diagnostics socket shows the agent's
// view and serves profiles.
func TestHeartbeatsReportClockOffsetAndDiagnostics(t *testing.T) {
	sock := filepath.Join(shortDir(t), "diag.sock")
	// The console's clock is 40 s behind: the node is 40 s ahead.
	e := startEnrolledPrepared(t, "clk", func(c *agent.Config) { c.DiagSocket = sock },
		func(c *fakeconsole.Console, _ *fakedataplane.Server) { c.SetClock(-40 * time.Second) },
		baseConfig(demoSite("site-a", "a.test")))
	near := func(ms, want int64) bool { return ms > want-2000 && ms < want+2000 }
	eventually(t, "clock offset reported", func() bool {
		v := e.console.LastStatus().ClockOffsetMillis
		return v != nil && near(*v, 40_000)
	})
	if first := e.console.Statuses()[0]; first.ClockOffsetMillis != nil {
		t.Fatalf("first heartbeat carries an offset before any measurement: %d", *first.ClockOffsetMillis)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := diag.Fetch(ctx, sock)
	if err != nil {
		t.Fatal(err)
	}
	if st.NodeID != "node-clk" || st.ClusterID != "cl-clk" || st.Console == nil || st.Console.URL != e.h.url {
		t.Fatalf("identity / console = %+v %+v", st, st.Console)
	}
	if st.Config.AppliedRevision != e.rev || st.Config.LatestRevision != e.rev || st.Config.State != "applied" || !st.Config.DataPlaneHealthy {
		t.Fatalf("config = %+v", st.Config)
	}
	if st.Clock == nil || !near(st.Clock.OffsetMillis, 40_000) || st.Clock.RTTMillis < 0 {
		t.Fatalf("clock = %+v", st.Clock)
	}
	if time.Since(st.Report.LastOK) > 10*time.Second || st.Report.IntervalSeconds != 1 || st.CertificateNotAfter.IsZero() {
		t.Fatalf("report = %+v, certificate %v", st.Report, st.CertificateNotAfter)
	}
	if info, err := os.Stat(sock); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", info.Mode(), err)
	}

	var heap bytes.Buffer
	if err := diag.Profile(ctx, sock, "heap", 0, &heap); err != nil {
		t.Fatal(err)
	}
	if b := heap.Bytes(); len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		t.Fatalf("heap profile is not gzipped protobuf: %d bytes", len(b))
	}
	if err := diag.Profile(ctx, sock, "profile", diag.MaxSeconds+1, &heap); err == nil {
		t.Fatal("a CPU profile longer than MaxSeconds was accepted")
	}
	if err := diag.Profile(ctx, sock, "cmdline", 0, &heap); err == nil {
		t.Fatal("an unknown profile was accepted")
	}

	// Back in sync: the next measurement replaces the offset.
	e.console.SetClock(0)
	eventually(t, "offset back near zero", func() bool {
		v := e.console.LastStatus().ClockOffsetMillis
		return v != nil && near(*v, 0)
	})
}
