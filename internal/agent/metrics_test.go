package agent_test

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/metrics"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

// copyProc installs a /proc fixture of the metrics package under root.
func copyProc(t *testing.T, fixture, root string) {
	t.Helper()
	for _, name := range []string{"stat", "loadavg", "meminfo", filepath.Join("net", "dev")} {
		b, err := os.ReadFile(filepath.Join("..", "metrics", "testdata", fixture, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		// Replaced atomically: the agent may read it at any time.
		tmp := filepath.Join(root, name+".tmp")
		if err := os.WriteFile(tmp, b, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
}

// Every heartbeat carries the host metrics and the data plane's active
// connections; rates appear from the second one on.
func TestHeartbeatsCarryMetrics(t *testing.T) {
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-m", ReportInterval: 1, KeepaliveInterval: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	root := t.TempDir()
	proc := filepath.Join(root, "proc")
	copyProc(t, "first", proc)
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}
	rev := console.Publish(baseConfig(demoSite("site-a", "a.test")))
	dp := fakedataplane.Start(t)
	dp.SetConnections(42)
	cfg := h.agentConfig(dp.Socket)
	cfg.Metrics = &metrics.Collector{Root: proc, Loopback: func(n string) bool { return n == "lo" }}
	startAgent(t, cfg, newFakeEngine(), dataplane.NewClient(dp.Socket))
	console.AddToken("tok")
	if _, err := enroll.Run(context.Background(), enroll.Options{ServerURL: srv.URL, Token: "tok", CASHA256: console.CA.Pin(), StateDir: h.stateDir, Logger: testLogger(t)}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "revision applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	st := console.LastStatus()
	m := st.GetMetrics()
	if m == nil || m.GetLoad1() != 0.52 || m.GetLoad15() != 0.40 || m.GetMemoryTotalBytes() != 8000000*1024 ||
		m.GetMemoryUsedBytes() != 2000000*1024 || m.GetActiveConnections() != 42 {
		t.Fatalf("metrics = %v", m)
	}
	if !slices.Contains(st.GetInfo().GetSupportedFeatures(), configir.FeatureMetrics) {
		t.Fatalf("metrics-v1 not announced: %v", st.GetInfo().GetSupportedFeatures())
	}

	copyProc(t, "second", proc)
	// The files change one after another: a heartbeat may see the new
	// CPU times and the next one the new interface counters.
	eventually(t, "rates between two heartbeats", func() bool {
		cpu, egress := false, false
		for _, st := range console.Statuses() {
			m := st.GetMetrics()
			cpu = cpu || math.Abs(m.GetCpuPercent()-25) < 1e-9
			egress = egress || m.GetEgressBps() > 0
		}
		return cpu && egress && console.LastStatus().GetMetrics().GetLoad1() == 1.25
	})
}

// Without a collector (other platforms) heartbeats carry no metrics and
// do not announce metrics-v1.
func TestHeartbeatsWithoutMetrics(t *testing.T) {
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-n", ReportInterval: 1, KeepaliveInterval: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	root := t.TempDir()
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}
	rev := console.Publish(baseConfig(demoSite("site-a", "a.test")))
	dp := fakedataplane.Start(t)
	cfg := h.agentConfig(dp.Socket)
	cfg.Metrics = &metrics.Collector{} // disabled
	startAgent(t, cfg, newFakeEngine(), dataplane.NewClient(dp.Socket))
	console.AddToken("tok")
	if _, err := enroll.Run(context.Background(), enroll.Options{ServerURL: srv.URL, Token: "tok", CASHA256: console.CA.Pin(), StateDir: h.stateDir, Logger: testLogger(t)}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "revision applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	st := console.LastStatus()
	if st.GetMetrics() != nil || slices.Contains(st.GetInfo().GetSupportedFeatures(), configir.FeatureMetrics) {
		t.Fatalf("metrics %v, features %v", st.GetMetrics(), st.GetInfo().GetSupportedFeatures())
	}
}
