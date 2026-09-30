package agent_test

import (
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStatsRetryAndRestartUseDurableSequences(t *testing.T) {
	e := startEnrolled(t, "stats-retry", nil, demoSite("site-a", "site-a.test"))
	e.console.FailStatsAcknowledgements(1)
	e.dp.AddStats(dataplane.MinuteStats{Minute: time.Now().Add(-time.Minute).Unix(), SiteID: "site-a", Requests: 7, TopURLs: map[string]uint64{"/test": 7}})
	eventually(t, "retry acknowledged", func() bool { return len(e.console.StatsSequences()) >= 2 })
	sequences := e.console.StatsSequences()
	if sequences[0] != sequences[1] {
		t.Fatalf("retry changed sequence: %v", sequences)
	}
	if stats := e.console.Stats(); len(stats) != 1 || stats[0].Requests != 7 || len(stats[0].TopUrls) != 1 {
		t.Fatalf("retry double counted: %v", stats)
	}
	e.stop()
	info, err := os.Stat(filepath.Join(e.cfg.StateDir, "traffic-spool.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("statistics spool is not private")
	}
	stop := startAgent(t, e.cfg, e.eng, dataplane.NewClient(e.dp.Socket))
	defer stop()
	e.dp.AddStats(dataplane.MinuteStats{Minute: time.Now().Add(-time.Minute).Unix(), SiteID: "site-a", Requests: 3})
	eventually(t, "next batch after restart", func() bool { return len(e.console.Stats()) == 2 })
	sequences = e.console.StatsSequences()
	if sequences[len(sequences)-1] <= sequences[0] {
		t.Fatalf("sequence regressed after restart: %v", sequences)
	}
}
func TestStatsRecoverCursorAfterLocalStateLoss(t *testing.T) {
	e := startEnrolled(t, "stats-cursor", nil, demoSite("site-a", "site-a.test"))
	e.dp.AddStats(dataplane.MinuteStats{Minute: time.Now().Add(-time.Minute).Unix(), SiteID: "site-a", Requests: 7})
	eventually(t, "first batch", func() bool { return len(e.console.Stats()) == 1 })
	e.stop()
	if err := os.Remove(filepath.Join(e.cfg.StateDir, "traffic-spool.json")); err != nil {
		t.Fatal(err)
	}
	stop := startAgent(t, e.cfg, e.eng, dataplane.NewClient(e.dp.Socket))
	defer stop()
	e.dp.AddStats(dataplane.MinuteStats{Minute: time.Now().Add(-time.Minute).Unix(), SiteID: "site-a", Requests: 3})
	eventually(t, "batch after lost state", func() bool { return len(e.console.Stats()) == 2 })
	seq := e.console.StatsSequences()
	if seq[len(seq)-1] <= seq[0] {
		t.Fatal("accepted cursor was reused")
	}
}

func TestStatsWatermarkFollowsAcknowledgedDrains(t *testing.T) {
	e := startEnrolled(t, "stats-watermark", nil, demoSite("site-a", "site-a.test"))
	minute := time.Now().Add(-time.Minute).Truncate(time.Minute)
	e.console.FailStatsAcknowledgements(1)
	e.dp.AddStats(dataplane.MinuteStats{Minute: minute.Unix(), SiteID: "site-a", Requests: 5})
	eventually(t, "watermark after the batch", func() bool {
		for _, w := range e.console.Watermarks() {
			if !w.CompleteUntil.After(minute) {
				continue
			}
			return true
		}
		return false
	})
	if stats := e.console.Stats(); len(stats) != 1 || stats[0].Requests != 5 {
		t.Fatalf("batch not delivered before the watermark: %v", stats)
	}
	previous := time.Time{}
	for _, w := range e.console.Watermarks() {
		if w.BatchSequence != 0 {
			t.Fatalf("watermark sent with batch %d, want an empty cursor query", w.BatchSequence)
		}
		if w.Acknowledged == 0 {
			t.Fatal("watermark reported before the batch was acknowledged")
		}
		if w.CompleteUntil.Before(previous) || !w.CompleteUntil.Equal(w.CompleteUntil.Truncate(time.Minute)) {
			t.Fatalf("watermarks must be whole minutes that never go back: %v", e.console.Watermarks())
		}
		if w.CompleteUntil.After(time.Now()) {
			t.Fatalf("watermark %v is in the future", w.CompleteUntil)
		}
		previous = w.CompleteUntil
	}
}
