package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// spoolAgent is an agent with a captured log that has announced its
// connection already (markConnected needs no channel then).
func spoolAgent(t *testing.T, dir string) (*Agent, *bytes.Buffer) {
	t.Helper()
	var out bytes.Buffer
	a := &Agent{cfg: Config{StateDir: dir}, log: slog.New(slog.NewTextHandler(&out, nil))}
	a.connectedOnce.Do(func() {})
	return a, &out
}

func copyFixture(t *testing.T, name, dir string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSpoolReadsFilesOfThePreviousVersion: testdata holds a statistics
// and an access logs spool written by the agent before the spools shared
// their code. They load as they were written, and saving them again gives
// the same bytes.
func TestSpoolReadsFilesOfThePreviousVersion(t *testing.T) {
	dir := t.TempDir()
	a, _ := spoolAgent(t, dir)
	copyFixture(t, "traffic-spool.json", dir)
	copyFixture(t, "logs-spool.json", dir)

	stats := a.statsSpool()
	sf, err := stats.load("node-a")
	if err != nil {
		t.Fatal(err)
	}
	if sf.Last != 42 || len(sf.Batches) != 2 || sf.Batches[0].Sequence != 41 || sf.Batches[1].Sequence != 42 ||
		len(sf.Loose) != 1 || sf.Loose[0].Sequence != 0 || sf.LostFrom != 1799999940 {
		t.Fatalf("statistics spool %+v", sf)
	}
	if m := sf.Batches[0].Stats[0]; m.GetSiteId() != "site-a" || m.GetRequests() != 7 || m.GetStatusCodes()[404] != 1 ||
		m.GetTopUrls()[0].GetValue() != "/a" || !m.GetMinute().AsTime().Equal(time.Unix(1800000000, 0)) {
		t.Fatalf("bucket %v", m)
	}
	if l4 := sf.Batches[1].L4[0]; l4.GetAppId() != "app-a" || l4.GetBytesSent() != 4294967296 {
		t.Fatalf("layer-4 bucket %v", l4)
	}
	logs := a.logsSpool()
	lf, err := logs.load("node-a")
	if err != nil {
		t.Fatal(err)
	}
	if lf.Last != 9 || len(lf.Batches) != 2 || lf.Batches[1].Sequence != 9 || len(lf.Loose) != 0 || lf.LostFrom != 0 {
		t.Fatalf("access logs spool %+v", lf)
	}
	if r := lf.Batches[1].Logs[0]; r.GetRequestId() != "r-1" || !r.GetWafBlocked() || !slices.Equal(r.GetWafRuleIds(), []uint32{942100}) {
		t.Fatalf("record %v", r)
	}

	if err := stats.save(sf); err != nil {
		t.Fatal(err)
	}
	if err := logs.save(lf); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"traffic-spool.json", "logs-spool.json"} {
		want, _ := os.ReadFile(filepath.Join("testdata", name))
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s saved as\n%s\nwant\n%s", name, got, want)
		}
	}
}

// TestSpoolLoadStartsOver: a missing, unreadable, oversized spool or one
// of another identity starts over.
func TestSpoolLoadStartsOver(t *testing.T) {
	dir := t.TempDir()
	a, out := spoolAgent(t, dir)
	sp := a.logsSpool()
	check := func(what, warning string) {
		t.Helper()
		f, err := sp.load("node-a")
		if err != nil || f.NodeID != "node-a" || f.Last != 0 || len(f.Batches) != 0 {
			t.Fatalf("%s: %+v %v", what, f, err)
		}
		if warning != "" && !strings.Contains(out.String(), warning) {
			t.Fatalf("%s: log %s", what, out)
		}
	}
	check("missing", "")
	copyFixture(t, "logs-spool.json", dir)
	if f, err := sp.load("node-b"); err != nil || f.NodeID != "node-b" || len(f.Batches) != 0 {
		t.Fatalf("another identity: %+v %v", f, err)
	}
	if !strings.Contains(out.String(), "discarding unreadable or previous-identity access logs spool") {
		t.Fatalf("log %s", out)
	}
	if err := os.WriteFile(sp.path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	check("unreadable", "discarding unreadable or previous-identity access logs spool")
	sp.maxBytes = 1
	copyFixture(t, "logs-spool.json", dir)
	check("oversized", "discarding an oversized access logs spool")
}

func minuteStats(minute int64, n int) []*nodev1.MinuteStats {
	out := make([]*nodev1.MinuteStats, n)
	for i := range out {
		out[i] = &nodev1.MinuteStats{Minute: timestamppb.New(time.Unix(minute, 0)), SiteId: "site-a", Requests: 1}
	}
	return out
}

// TestSpoolKeepsItsLimits: beyond maxPending buckets, and beyond maxBytes
// on disk, the oldest batches go (numbered before loose ones) and the
// statistics watermark holds at the first minute they had.
func TestSpoolKeepsItsLimits(t *testing.T) {
	dir := t.TempDir()
	a, out := spoolAgent(t, dir)
	sp := a.statsSpool()
	sp.maxPending, sp.batchSize = 5, 2
	f := &spoolFile[statsBatch]{NodeID: "node-a"}
	pack := func(minute int64, n int) func(uint64) ([]statsBatch, bool) {
		return func(last uint64) ([]statsBatch, bool) {
			return packStatsInto(last, minuteStats(minute, n), sp.batchSize)
		}
	}
	sp.add(f, false, pack(1800000000, 2))
	sp.add(f, true, pack(1800000060, 3))
	if len(f.Loose) != 1 || len(f.Batches) != 2 || f.Batches[0].Sequence != 1 || f.Last != 2 || f.LostFrom != 0 {
		t.Fatalf("spool %+v", f)
	}
	// Six buckets: the oldest numbered batch goes, not the older loose one.
	sp.add(f, true, pack(1800000120, 1))
	if len(f.Loose) != 1 || len(f.Batches) != 2 || f.Batches[0].Sequence != 2 || f.LostFrom != 1800000060 || f.pending() != 4 {
		t.Fatalf("spool %+v", f)
	}
	if !strings.Contains(out.String(), "dropping oldest unsent statistics batch: bucket limit") ||
		!strings.Contains(out.String(), "lost_from=2027-01-15T08:01:00.000Z") {
		t.Fatalf("log %s", out)
	}
	// The cursor acknowledged batch 2: batch 3 stays, the loose one
	// becomes 4.
	if err := sp.sync(f, 2); err != nil {
		t.Fatal(err)
	}
	if len(f.Loose) != 0 || len(f.Batches) != 2 || f.Batches[0].Sequence != 3 || f.Batches[1].Sequence != 4 || f.Last != 4 {
		t.Fatalf("spool %+v", f)
	}
	// Too large on disk: batches go until it fits, the earlier lost
	// minute stays.
	fits, err := json.Marshal(&spoolFile[statsBatch]{NodeID: f.NodeID, Last: f.Last, Batches: f.Batches[1:], LostFrom: f.LostFrom})
	if err != nil {
		t.Fatal(err)
	}
	sp.maxBytes = int64(len(fits))
	if err := sp.save(f); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(sp.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, fits) || len(f.Batches) != 1 || f.Batches[0].Sequence != 4 || f.LostFrom != 1800000060 {
		t.Fatalf("spool %s", raw)
	}
	if !strings.Contains(out.String(), "dropping oldest unsent statistics batch: spool size limit") {
		t.Fatalf("log %s", out)
	}
	// Access logs have no watermark.
	logs := a.logsSpool()
	logs.maxPending = 1
	lf := &spoolFile[logsBatch]{NodeID: "node-a"}
	logs.add(lf, true, func(last uint64) ([]logsBatch, bool) {
		return packLogs(last, []*nodev1.AccessLog{{SiteId: "site-a"}, {SiteId: "site-a"}})
	})
	if len(lf.Batches) != 0 || lf.LostFrom != 0 || lf.Last != 1 {
		t.Fatalf("access logs spool %+v", lf)
	}
}

// packStatsInto is packStats with another batch size.
func packStatsInto(last uint64, sites []*nodev1.MinuteStats, size int) (batches []statsBatch, ok bool) {
	for len(sites) > 0 {
		n := min(size, len(sites))
		b, ok := packStats(last, sites[:n], nil)
		if !ok {
			return nil, false
		}
		batches = append(batches, b...)
		last, sites = b[len(b)-1].Sequence, sites[n:]
	}
	return batches, true
}

// TestSpoolSyncRejectsABrokenFile: batches out of order, numbered beyond
// the last sequence or larger than a batch may be are not sent; a spool
// at the end of the sequence takes nothing more.
func TestSpoolSyncRejectsABrokenFile(t *testing.T) {
	a, out := spoolAgent(t, t.TempDir())
	sp := a.logsSpool()
	one := []*nodev1.AccessLog{{SiteId: "site-a"}}
	for _, f := range []*spoolFile[logsBatch]{
		{Last: 5, Batches: []logsBatch{{Sequence: 4, Logs: one}, {Sequence: 3, Logs: one}}},
		{Last: 5, Batches: []logsBatch{{Sequence: 6, Logs: one}}},
		{Last: 5, Batches: []logsBatch{{Sequence: 5, Logs: make([]*nodev1.AccessLog, logsBatchSize+1)}}},
	} {
		if err := sp.sync(f, 2); err == nil || err.Error() != "invalid access logs spool ordering" {
			t.Fatalf("%+v: %v", f, err)
		}
	}
	// A cursor ahead of the file (local state lost) moves the sequence on.
	f := &spoolFile[logsBatch]{Last: 5, Batches: []logsBatch{{Sequence: 5, Logs: one}}}
	if err := sp.sync(f, 7); err != nil || f.Last != 7 || len(f.Batches) != 0 {
		t.Fatalf("%+v: %v", f, err)
	}
	f.Last = maxSpoolSequence
	if sp.add(f, true, func(last uint64) ([]logsBatch, bool) { return packLogs(last, one) }) || len(f.Batches) != 0 {
		t.Fatalf("exhausted spool took a batch: %+v", f)
	}
	if !strings.Contains(out.String(), "access logs sequence exhausted") {
		t.Fatalf("log %s", out)
	}
	stats := a.statsSpool()
	sf := &spoolFile[statsBatch]{Last: maxSpoolSequence, Loose: []statsBatch{{Stats: minuteStats(1800000000, 1)}}}
	if err := stats.sync(sf, 0); err == nil || err.Error() != "statistics sequence exhausted" {
		t.Fatalf("%v", err)
	}
}

// TestSpoolUploadSavesEachAcknowledgement: batches go in order; each
// acknowledgement is on disk before the next batch is sent, and a failure
// or a wrong acknowledgement keeps the batch for the next round.
func TestSpoolUploadSavesEachAcknowledgement(t *testing.T) {
	a, out := spoolAgent(t, t.TempDir())
	sp := a.logsSpool()
	one := []*nodev1.AccessLog{{SiteId: "site-a"}}
	f := &spoolFile[logsBatch]{NodeID: "node-a", Last: 3, Batches: []logsBatch{{Sequence: 1, Logs: one}, {Sequence: 2, Logs: one}, {Sequence: 3, Logs: one}}}
	if err := sp.save(f); err != nil {
		t.Fatal(err)
	}
	var sent []uint64
	f = sp.upload(context.Background(), f, func(_ context.Context, b logsBatch) (uint64, error) {
		sent = append(sent, b.Sequence)
		if b.Sequence == 1 {
			if on, err := sp.load("node-a"); err != nil || on.Batches[0].Sequence != 1 {
				t.Fatalf("on disk while batch 1 is sent: %+v %v", on, err)
			}
			return 1, nil
		}
		if on, err := sp.load("node-a"); err != nil || on.Batches[0].Sequence != 2 {
			t.Fatalf("batch 1 acknowledged but not saved: %+v %v", on, err)
		}
		return 0, errors.New("unavailable")
	})
	if !slices.Equal(sent, []uint64{1, 2}) || len(f.Batches) != 2 || f.Batches[0].Sequence != 2 {
		t.Fatalf("sent %v, left %+v", sent, f)
	}
	if !strings.Contains(out.String(), "ReportLogs failed; will retry the same batch") {
		t.Fatalf("log %s", out)
	}
	f = sp.upload(context.Background(), f, func(context.Context, logsBatch) (uint64, error) { return 3, nil })
	if len(f.Batches) != 2 || !strings.Contains(out.String(), "access logs acknowledgement sequence mismatch") {
		t.Fatalf("left %+v, log %s", f, out)
	}
}
