package agent

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

func TestConvertL4Stats(t *testing.T) {
	out := convertL4Stats([]dataplane.L4MinuteStats{
		{Minute: 1800000000, AppID: "app-a", Connections: 3, Refused: 2, PeakConcurrent: 7, BytesReceived: 100, BytesSent: 4294967296},
		{Minute: 1800000000, AppID: "app|b", Connections: 1},
		{Minute: 0, AppID: "app-c", Connections: 1},
	})
	if len(out) != 1 {
		t.Fatalf("buckets %v", out)
	}
	b := out[0]
	if b.GetAppId() != "app-a" || b.GetMinute().AsTime() != time.Unix(1800000000, 0).UTC() || b.GetConnections() != 3 || b.GetRefused() != 2 ||
		b.GetPeakConcurrent() != 7 || b.GetBytesReceived() != 100 || b.GetBytesSent() != 4294967296 {
		t.Fatalf("bucket %v", b)
	}
}

func TestPackStats(t *testing.T) {
	sites := make([]*nodev1.MinuteStats, 1500)
	l4 := make([]*nodev1.L4MinuteStats, 700)
	batches, ok := packStats(41, sites, l4)
	if !ok || len(batches) != 3 {
		t.Fatalf("batches %d %v", len(batches), ok)
	}
	for i, want := range [][2]int{{1000, 0}, {500, 500}, {0, 200}} {
		b := batches[i]
		if b.Sequence != uint64(42+i) || len(b.Stats) != want[0] || len(b.L4) != want[1] || b.size() > statsBatchSize {
			t.Fatalf("batch %d: sequence %d, %d + %d buckets", i, b.Sequence, len(b.Stats), len(b.L4))
		}
	}
	if batches, ok := packStats(41, nil, nil); !ok || batches != nil {
		t.Fatal("nothing to pack")
	}
	if _, ok := packStats(9223372036854775807, nil, l4); ok {
		t.Fatal("sequence overflow accepted")
	}
}

// TestDrainStatsWaitsForBothDrains: the layer-4 minutes are drained while
// the plan has applications, and the watermark may only advance when both
// drains succeeded.
func TestDrainStatsWaitsForBothDrains(t *testing.T) {
	dp := fakedataplane.Start(t)
	a := &Agent{dp: dataplane.NewClient(dp.Socket), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	dp.AddL4Stats(dataplane.L4MinuteStats{Minute: 1800000000, AppID: "app-a", Connections: 1})
	ctx := context.Background()
	// No applications in the plan: no stream subsystem to drain.
	if _, l4, complete := a.drainStats(ctx, false); !complete || len(l4) != 0 {
		t.Fatalf("without applications: %v %v", l4, complete)
	}
	a.plan = &configir.Plan{L4Apps: []configir.L4App{{ID: "app-a"}}}
	dp.FailNextL4(1)
	if _, _, complete := a.drainStats(ctx, false); complete {
		t.Fatal("a failed layer-4 drain counts as complete")
	}
	dp.AddStats(dataplane.MinuteStats{Minute: 1800000000, SiteID: "site-a", Requests: 1})
	sites, l4, complete := a.drainStats(ctx, false)
	if !complete || len(sites) != 1 || len(l4) != 1 || l4[0].GetAppId() != "app-a" {
		t.Fatalf("drain: %v %v %v", sites, l4, complete)
	}
}
