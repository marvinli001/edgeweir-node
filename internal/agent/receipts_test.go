package agent_test

import (
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"os"
	"path/filepath"
	"testing"
)

func TestRevisionReceiptPersistsAcrossRestart(t *testing.T) {
	e := startEnrolled(t, "revision-receipt", nil, demoSite("site-a", "site-a.test"))
	eventually(t, "issued receipt in heartbeat", func() bool {
		r := e.console.LastStatus()
		return r != nil && r.AppliedRevision == 1 && r.RevisionReceipt == "test-receipt/1"
	})
	e.stop()
	path := filepath.Join(e.cfg.StateDir, "config", "receipts.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("receipt file is not private")
	}
	before := len(e.console.Statuses())
	stop := startAgent(t, e.cfg, e.eng, dataplane.NewClient(e.dp.Socket))
	defer stop()
	eventually(t, "receipt recovered from disk", func() bool {
		for _, r := range e.console.Statuses()[before:] {
			if r.AppliedRevision == 1 && r.RevisionReceipt == "test-receipt/1" {
				return true
			}
		}
		return false
	})
}
