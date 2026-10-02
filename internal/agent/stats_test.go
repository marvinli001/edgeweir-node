package agent_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/agent"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
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
	// The bucket and the lost acknowledgement are in place before the
	// agent starts, so its first drain returns the bucket. Queued later,
	// the bucket could follow a drain that found nothing; that drain's
	// watermark rightly covers the bucket's minute and would end the wait
	// below before the batch exists.
	minute := time.Now().Add(-time.Minute).Truncate(time.Minute)
	e := startEnrolledPrepared(t, "stats-watermark", nil, func(c *fakeconsole.Console, dp *fakedataplane.Server) {
		c.FailStatsAcknowledgements(1)
		dp.AddStats(dataplane.MinuteStats{Minute: minute.Unix(), SiteID: "site-a", Requests: 5})
	}, baseConfig(demoSite("site-a", "site-a.test")))
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

// TestStatsDrainedBeforeTheConsoleAnswers: while the console does not
// answer the cursor query the data plane is still drained (it keeps
// counters for two hours only) into the spool; the buckets are numbered and
// sent once it answers.
func TestStatsDrainedBeforeTheConsoleAnswers(t *testing.T) {
	e := startEnrolledPrepared(t, "stats-early", nil, func(c *fakeconsole.Console, dp *fakedataplane.Server) {
		c.FailStatsQueries(1 << 30)
		dp.AddStats(dataplane.MinuteStats{Minute: time.Now().Add(-time.Minute).Unix(), SiteID: "site-a", Requests: 4})
	}, baseConfig(demoSite("site-a", "site-a.test")))
	spool := filepath.Join(e.cfg.StateDir, "traffic-spool.json")
	eventually(t, "bucket kept on disk", func() bool {
		raw, err := os.ReadFile(spool)
		return err == nil && strings.Contains(string(raw), `"loose":[{"sequence":0,"stats":[{`)
	})
	if len(e.console.Stats()) != 0 {
		t.Fatal("statistics sent without a cursor")
	}
	e.console.FailStatsQueries(0)
	eventually(t, "bucket sent once the console answers", func() bool {
		stats := e.console.Stats()
		return len(stats) == 1 && stats[0].Requests == 4
	})
	if seq := e.console.StatsSequences(); seq[len(seq)-1] == 0 {
		t.Fatalf("sequences %v", seq)
	}
}

// TestStatsSavedBeforeNginxStops: stopping drains every counter, the
// current minute's included, into the spool before nginx is stopped; the
// next start sends it.
func TestStatsSavedBeforeNginxStops(t *testing.T) {
	e := startEnrolled(t, "stats-stop", func(c *agent.Config) { c.StatsInterval = time.Hour }, demoSite("site-a", "site-a.test"))
	saved := make(chan bool, 1)
	e.eng.mu.Lock()
	e.eng.onStop = func() { saved <- slices.Contains(e.dp.Events(), "stats:drain-all") }
	e.eng.mu.Unlock()
	e.dp.AddStats(dataplane.MinuteStats{Minute: time.Now().Unix(), SiteID: "site-a", Requests: 6})
	e.stop()
	if !<-saved {
		t.Fatal("nginx stopped before its statistics were drained")
	}
	cfg := e.cfg
	cfg.StatsInterval = 100 * time.Millisecond
	stop := startAgent(t, cfg, newFakeEngine(), dataplane.NewClient(e.dp.Socket))
	defer stop()
	eventually(t, "saved bucket sent after the restart", func() bool {
		stats := e.console.Stats()
		return len(stats) == 1 && stats[0].Requests == 6
	})
}

// TestStatsWatermarkHoldsAtDroppedBuckets: buckets dropped for the spool
// limit hold the watermark at their first minute for a day.
func TestStatsWatermarkHoldsAtDroppedBuckets(t *testing.T) {
	old := time.Now().Add(-2 * time.Hour).Truncate(time.Minute)
	recent := time.Now().Add(-time.Minute).Truncate(time.Minute)
	e := startEnrolledPrepared(t, "stats-lost", nil, func(_ *fakeconsole.Console, dp *fakedataplane.Server) {
		// One more than the spool takes: the first batch (the oldest
		// buckets) is dropped.
		for i := range 10001 {
			minute := recent
			if i < 1000 {
				minute = old
			}
			dp.AddStats(dataplane.MinuteStats{Minute: minute.Unix(), SiteID: "site-a", Requests: 1})
		}
	}, baseConfig(demoSite("site-a", "site-a.test")))
	eventually(t, "watermark", func() bool { return len(e.console.Watermarks()) > 0 })
	eventually(t, "the rest sent", func() bool { return len(e.console.Stats()) == 9001 })
	time.Sleep(500 * time.Millisecond) // several more drains
	for _, w := range e.console.Watermarks() {
		if !w.CompleteUntil.Equal(old) {
			t.Fatalf("watermarks %v, want %v (the first dropped minute)", e.console.Watermarks(), old)
		}
	}
	e.stop()

	// A day later the hold ends.
	path := filepath.Join(e.cfg.StateDir, "traffic-spool.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), fmt.Sprintf(`"lost_from":%d`, old.Unix())) {
		t.Fatalf("spool %s", raw)
	}
	raw = []byte(strings.Replace(string(raw), fmt.Sprintf(`"lost_from":%d`, old.Unix()),
		fmt.Sprintf(`"lost_from":%d`, time.Now().Add(-25*time.Hour).Unix()), 1))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	stop := startAgent(t, e.cfg, newFakeEngine(), dataplane.NewClient(e.dp.Socket))
	defer stop()
	eventually(t, "watermark released", func() bool {
		w := e.console.Watermarks()
		return w[len(w)-1].CompleteUntil.After(recent)
	})
}
