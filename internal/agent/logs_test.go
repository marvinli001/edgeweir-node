package agent_test

import (
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"os"
	"path/filepath"
	"testing"
)

func TestLogsRetryAndRestartUseDurableSequences(t *testing.T) {
	e := startEnrolled(t, "logs-retry", nil, demoSite("site-a", "site-a.test"))
	e.console.FailLogsAcknowledgements(1)
	e.dp.AddLog("site-a")
	eventually(t, "retry acknowledged", func() bool { return len(e.console.LogsSequences()) >= 2 })
	sequences := e.console.LogsSequences()
	if sequences[0] != sequences[1] {
		t.Fatalf("retry changed sequence: %v", sequences)
	}
	if stats := e.console.Logs(); len(stats) != 1 || stats[0].Path != "/hello" {
		t.Fatalf("retry double counted: %v", stats)
	}
	e.stop()
	info, err := os.Stat(filepath.Join(e.cfg.StateDir, "logs-spool.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("access logs spool is not private")
	}
	stop := startAgent(t, e.cfg, e.eng, dataplane.NewClient(e.dp.Socket))
	defer stop()
	e.dp.AddLog("site-a")
	eventually(t, "next batch after restart", func() bool { return len(e.console.Logs()) == 2 })
	sequences = e.console.LogsSequences()
	if sequences[len(sequences)-1] <= sequences[0] {
		t.Fatalf("sequence regressed after restart: %v", sequences)
	}
}
