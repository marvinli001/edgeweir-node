package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// TestLogsSpoolKeepsRuleIDs: the spool's batches keep the log rules that
// asked for a line (AccessLog.rule_ids, proto v0.29.0) across a restart.
func TestLogsSpoolKeepsRuleIDs(t *testing.T) {
	batches, ok := packLogs(4, []*nodev1.AccessLog{{SiteId: "s1", Path: "/", SampleRate: 10000, RuleIds: []string{"r1", "r2"}}, {SiteId: "s1"}})
	if !ok || len(batches) != 1 || batches[0].Sequence != 5 {
		t.Fatalf("batches = %v, %v", batches, ok)
	}
	raw, err := json.Marshal(batches[0])
	if err != nil {
		t.Fatal(err)
	}
	var back logsBatch
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Logs) != 2 || !slices.Equal(back.Logs[0].GetRuleIds(), []string{"r1", "r2"}) || back.Logs[1].GetRuleIds() != nil {
		t.Fatalf("spooled logs = %s", raw)
	}
}

// TestSpoolsKeepG16Fields: the spools keep the access log fields and the
// statistics dimensions of proto v0.30.0 across a restart.
func TestSpoolsKeepG16Fields(t *testing.T) {
	batches, _ := packLogs(0, []*nodev1.AccessLog{{SiteId: "s1", UserAgent: "curl/8", Country: "NZ", Asn: 64512, BlockReason: "rule",
		BlockRuleId: "r1", Query: "a=1", Headers: map[string]string{"x-trace-id": "t"}, PeerIp: "10.0.0.9", UpstreamStatus: 200}})
	raw, err := json.Marshal(batches[0])
	if err != nil {
		t.Fatal(err)
	}
	var back logsBatch
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	l := back.Logs[0]
	if l.GetUserAgent() != "curl/8" || l.GetCountry() != "NZ" || l.GetAsn() != 64512 || l.GetBlockReason() != "rule" || l.GetBlockRuleId() != "r1" ||
		l.GetQuery() != "a=1" || l.GetHeaders()["x-trace-id"] != "t" || l.GetPeerIp() != "10.0.0.9" || l.GetUpstreamStatus() != 200 {
		t.Fatalf("spooled log = %s", raw)
	}
	stats := statsBatch{Sequence: 1, Stats: []*nodev1.MinuteStats{{SiteId: "s1",
		Countries: []*nodev1.CountryCounter{{Country: "", Requests: 1, BytesSent: 2}}, Asns: []*nodev1.AsnCounter{{Asn: 64512, Name: "S", Requests: 1}},
		Referers: []*nodev1.TopCounter{{Value: "r.test", Count: 1}}, Browsers: map[string]uint64{"firefox": 1},
		BlockReasons: map[string]uint64{"rule": 1}, ChallengesIssued: 2, ChallengesPassed: 1}}}
	raw, err = json.Marshal(stats)
	if err != nil {
		t.Fatal(err)
	}
	var sb statsBatch
	if err := json.Unmarshal(raw, &sb); err != nil {
		t.Fatal(err)
	}
	m := sb.Stats[0]
	if len(m.GetCountries()) != 1 || m.GetCountries()[0].GetBytesSent() != 2 || m.GetAsns()[0].GetName() != "S" || m.GetReferers()[0].GetValue() != "r.test" ||
		m.GetBrowsers()["firefox"] != 1 || m.GetBlockReasons()["rule"] != 1 || m.GetChallengesIssued() != 2 || m.GetChallengesPassed() != 1 {
		t.Fatalf("spooled stats = %s", raw)
	}
}

// drainScript stands in for the data plane's POST /v1/logs/drain: each
// call returns the next count of records (none once they run out).
type drainScript struct {
	counts []int
	calls  int
}

func (d *drainScript) drain(context.Context) ([]*nodev1.AccessLog, error) {
	d.calls++
	if len(d.counts) == 0 {
		return nil, nil
	}
	n := d.counts[0]
	d.counts = d.counts[1:]
	out := make([]*nodev1.AccessLog, n)
	for i := range out {
		out[i] = &nodev1.AccessLog{SiteId: "s1", Path: "/"}
	}
	return out, nil
}

// uploads stands in for the console's ReportLogs: it acknowledges each
// batch unless fail is set, and records the batches it accepted.
type uploads struct {
	fail    bool
	batches []logsBatch
}

func (u *uploads) send(_ context.Context, b logsBatch) (uint64, error) {
	if u.fail {
		return 0, errors.New("console unavailable")
	}
	u.batches = append(u.batches, b)
	return b.Sequence, nil
}

func (u *uploads) records() int {
	n := 0
	for _, b := range u.batches {
		n += len(b.Logs)
	}
	return n
}

func fullDrains(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = logsDrainSize
	}
	return out
}

// TestLogsRoundDrainsAgainWhileFull: a drain that returns a full call
// leaves more lines in the data plane; the round drains again (uploading
// each call before the next) until a call comes back short, instead of
// leaving the rest for the next tick.
func TestLogsRoundDrainsAgainWhileFull(t *testing.T) {
	a, out := spoolAgent(t, t.TempDir())
	sp := a.logsSpool()
	state := &spoolFile[logsBatch]{NodeID: "n"}
	d := &drainScript{counts: []int{logsDrainSize, logsDrainSize, logsDrainSize, 500, logsDrainSize}}
	u := &uploads{}
	dirty := false
	state, ok := a.logsRound(context.Background(), sp, state, &dirty, d.drain, u.send)
	if !ok || d.calls != 4 || u.records() != 3500 || len(u.batches) != 4 || len(state.Batches) != 0 || dirty {
		t.Fatalf("calls %d, records %d in %d batches, unsent %d, dirty %v", d.calls, u.records(), len(u.batches), len(state.Batches), dirty)
	}
	for i, b := range u.batches {
		if b.Sequence != uint64(i+1) {
			t.Fatalf("batch %d has sequence %d", i, b.Sequence)
		}
	}
	// The next round starts where this one stopped.
	if state, ok = a.logsRound(context.Background(), sp, state, &dirty, d.drain, u.send); !ok || d.calls != 6 || u.records() != 4500 {
		t.Fatalf("second round: calls %d, records %d", d.calls, u.records())
	}
	if strings.Contains(out.String(), "dropping") {
		t.Fatalf("records dropped: %s", out)
	}
	// A short call ends the round at once.
	d = &drainScript{counts: []int{999, logsDrainSize}}
	if _, ok = a.logsRound(context.Background(), sp, state, &dirty, d.drain, u.send); !ok || d.calls != 1 {
		t.Fatalf("short call: %d calls", d.calls)
	}
}

// TestLogsRoundBoundsItsDrains: a data plane that keeps returning full
// calls gets at most maxLogsDrains calls a round; with the uploads keeping
// up, nothing is dropped for the spool's limits although a round moves
// more than maxLogsPending records.
func TestLogsRoundBoundsItsDrains(t *testing.T) {
	a, out := spoolAgent(t, t.TempDir())
	sp := a.logsSpool()
	state := &spoolFile[logsBatch]{NodeID: "n"}
	d := &drainScript{counts: fullDrains(maxLogsDrains + 5)}
	u := &uploads{}
	dirty := false
	state, ok := a.logsRound(context.Background(), sp, state, &dirty, d.drain, u.send)
	if !ok || d.calls != maxLogsDrains || u.records() != maxLogsDrains*logsDrainSize || len(state.Batches) != 0 {
		t.Fatalf("calls %d, records %d, unsent %d", d.calls, u.records(), len(state.Batches))
	}
	if maxLogsDrains*logsDrainSize <= maxLogsPending {
		t.Fatalf("the test needs a round larger than the spool's limit")
	}
	if strings.Contains(out.String(), "dropping") {
		t.Fatalf("records dropped: %s", out)
	}
	// The rest in the next round: five full calls and an empty one.
	if _, ok = a.logsRound(context.Background(), sp, state, &dirty, d.drain, u.send); !ok || d.calls != maxLogsDrains+6 ||
		u.records() != (maxLogsDrains+5)*logsDrainSize {
		t.Fatalf("second round: calls %d, records %d", d.calls, u.records())
	}
}

// TestLogsRoundStopsDrainingWhenUploadsFail: while the console does not
// acknowledge, a round drains once (as before) and keeps the batch in the
// spool; the lines left in the data plane wait there, within its own
// bound, instead of pushing older spooled batches out.
func TestLogsRoundStopsDrainingWhenUploadsFail(t *testing.T) {
	a, _ := spoolAgent(t, t.TempDir())
	sp := a.logsSpool()
	state := &spoolFile[logsBatch]{NodeID: "n"}
	d := &drainScript{counts: fullDrains(3)}
	u := &uploads{fail: true}
	dirty := false
	state, ok := a.logsRound(context.Background(), sp, state, &dirty, d.drain, u.send)
	if !ok || d.calls != 1 || len(state.Batches) != 1 || state.pending() != logsDrainSize {
		t.Fatalf("calls %d, unsent %d", d.calls, len(state.Batches))
	}
	u.fail = false
	if _, ok = a.logsRound(context.Background(), sp, state, &dirty, d.drain, u.send); !ok || d.calls != 4 || u.records() != 3*logsDrainSize {
		t.Fatalf("after recovery: calls %d, records %d", d.calls, u.records())
	}
	for i, b := range u.batches {
		if b.Sequence != uint64(i+1) {
			t.Fatalf("batch %d has sequence %d", i, b.Sequence)
		}
	}
}

// TestLogsRoundKeepsAnUnsavedBatch: a batch that could not be written to
// the spool is neither sent nor followed by another drain; the next round
// writes it first.
func TestLogsRoundKeepsAnUnsavedBatch(t *testing.T) {
	dir := t.TempDir()
	a, _ := spoolAgent(t, dir)
	sp := a.logsSpool()
	sp.path = filepath.Join(dir, "missing", "logs-spool.json")
	state := &spoolFile[logsBatch]{NodeID: "n"}
	d := &drainScript{counts: fullDrains(3)}
	u := &uploads{}
	dirty := false
	state, ok := a.logsRound(context.Background(), sp, state, &dirty, d.drain, u.send)
	if !ok || d.calls != 1 || !dirty || len(u.batches) != 0 {
		t.Fatalf("calls %d, dirty %v, sent %d", d.calls, dirty, len(u.batches))
	}
	if state, ok = a.logsRound(context.Background(), sp, state, &dirty, d.drain, u.send); !ok || d.calls != 1 || !dirty {
		t.Fatalf("still unwritable: calls %d, dirty %v", d.calls, dirty)
	}
	if err := os.Mkdir(filepath.Dir(sp.path), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, ok = a.logsRound(context.Background(), sp, state, &dirty, d.drain, u.send); !ok || d.calls != 1 || dirty || u.records() != logsDrainSize {
		t.Fatalf("written: calls %d, dirty %v, records %d", d.calls, dirty, u.records())
	}
}
