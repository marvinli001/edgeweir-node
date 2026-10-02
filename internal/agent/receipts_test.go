package agent_test

import (
	"github.com/marvinli001/edgeweir-node/internal/agent"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// TestRevisionReceiptsAreNotRewrittenUnchanged: every poll of an
// up-to-date node fetches the same receipt; receipts.json is written only
// when its content changes.
func TestRevisionReceiptsAreNotRewrittenUnchanged(t *testing.T) {
	e := startEnrolled(t, "receipt-unchanged", func(c *agent.Config) { c.PollInterval = 50 * time.Millisecond },
		demoSite("site-a", "site-a.test"))
	path := filepath.Join(e.cfg.StateDir, "config", "receipts.json")
	var before os.FileInfo
	eventually(t, "receipt of the applied revision", func() bool {
		raw, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(raw), `"active":{"revision":1,`) {
			return false
		}
		before, err = os.Stat(path)
		return err == nil
	})
	calls := len(e.console.GetConfigCalls())
	eventually(t, "more polls", func() bool { return len(e.console.GetConfigCalls()) >= calls+5 })
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("receipts.json rewritten with the same content")
	}
	e.console.Publish(baseConfig(demoSite("site-a", "site-a.test"), demoSite("site-b", "site-b.test")))
	eventually(t, "receipt of the next revision", func() bool {
		raw, err := os.ReadFile(path)
		return err == nil && strings.Contains(string(raw), `"token":"test-receipt/2"`)
	})
}
