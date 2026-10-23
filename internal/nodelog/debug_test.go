package nodelog

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func TestRingKeepsTheNewestEntriesWithoutSecrets(t *testing.T) {
	if NewRing(0) != nil {
		t.Fatal("capacity 0 must turn the ring off")
	}
	var off *Ring
	off.Add(Entry{Level: LevelDebug, Source: SourceAgent, Message: "x"}) // nil ring: nothing
	if s := off.Snapshot(DebugFilter{}); len(s.Entries) != 0 {
		t.Fatal(s)
	}
	r := NewRing(3)
	base := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	for i, m := range []string{"one", "two", "three", "four"} {
		r.Add(Entry{Time: base.Add(time.Duration(i) * time.Second), Level: LevelDebug, Source: SourceAgent, Message: m})
	}
	r.Add(Entry{Level: "trace", Source: SourceAgent, Message: "unknown level"})
	r.Add(Entry{Level: LevelDebug, Source: "kernel", Message: "unknown source"})
	s := r.Snapshot(DebugFilter{})
	if len(s.Entries) != 3 || s.Entries[0].Message != "two" || s.Entries[2].Message != "four" || s.Overwritten != 1 ||
		!s.Oldest.Equal(base.Add(time.Second)) || s.Truncated {
		t.Fatalf("%+v", s)
	}
	// Secrets go before an entry is kept; other events become a field.
	r.Add(Entry{Time: base.Add(time.Minute), Level: LevelInfo, Source: SourceAgent, Event: "pulled",
		Message: "GET https://user:pw@origin.test/a?sig=x Authorization: Bearer abcdefghijkl",
		Fields:  map[string]string{"api_key": "k", "url": "/b?token=1"}})
	e := r.Snapshot(DebugFilter{Since: base.Add(time.Minute), Until: base.Add(time.Minute + time.Nanosecond)}).Entries
	if len(e) != 1 || strings.Contains(e[0].Message, "pw") || strings.Contains(e[0].Message, "sig=x") ||
		strings.Contains(e[0].Message, "abcdefghijkl") || e[0].Fields["api_key"] != Redacted ||
		e[0].Fields["url"] != "/b?"+Redacted || e[0].Event != "" || e[0].Fields[EventKey] != "pulled" {
		t.Fatalf("%+v", e)
	}
	// A whitelisted event stays one.
	r.Add(Entry{Level: LevelInfo, Source: SourceAgent, Event: EventConfigApplied})
	if all := r.Snapshot(DebugFilter{}).Entries; all[len(all)-1].Event != EventConfigApplied || all[len(all)-1].Time.IsZero() {
		t.Fatalf("%+v", all)
	}
}

func TestRingIsBoundedInBytes(t *testing.T) {
	r := NewRing(MaxDebugCapacity)
	big := strings.Repeat("x", MaxMessage)
	n := 2 * debugMaxBytes / MaxMessage
	for range n {
		r.Add(Entry{Level: LevelDebug, Source: SourceNginx, Message: big})
	}
	s := r.Snapshot(DebugFilter{})
	if r.bytes > debugMaxBytes || s.Overwritten == 0 || int(s.Overwritten)+r.size != n {
		t.Fatalf("bytes %d, kept %d, overwritten %d", r.bytes, r.size, s.Overwritten)
	}
	// The upload keeps the newest within its limit.
	if total := sizeOf(s.Entries); total > MaxDebugUploadBytes || !s.Truncated && len(s.Entries) != r.size {
		t.Fatalf("upload %d bytes, truncated %v", total, s.Truncated)
	}
}

func sizeOf(entries []Entry) int {
	n := 0
	for _, e := range entries {
		n += e.size()
	}
	return n
}

func TestDebugFilterAndLimits(t *testing.T) {
	base := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	r := NewRing(100)
	r.Add(Entry{Time: base, Level: LevelDebug, Source: SourceAgent, Component: "channel", Message: "a"})
	r.Add(Entry{Time: base.Add(time.Second), Level: LevelWarn, Source: SourceNginx, Message: "b"})
	r.Add(Entry{Time: base.Add(2 * time.Second), Level: LevelError, Source: SourceLua, Message: "c"})
	r.Add(Entry{Time: base.Add(3 * time.Second), Level: LevelInfo, Source: SourceAgent, Component: "tasks", Message: "d"})
	messages := func(f DebugFilter) string {
		var out []string
		for _, e := range r.Snapshot(f).Entries {
			out = append(out, e.Message)
		}
		return strings.Join(out, "")
	}
	for _, c := range []struct {
		f    DebugFilter
		want string
	}{
		{DebugFilter{}, "abcd"},
		{DebugFilter{Since: base.Add(time.Second), Until: base.Add(3 * time.Second)}, "bc"},
		{DebugFilter{Components: []string{"channel", "tasks"}}, "ad"},
		{DebugFilter{Sources: []Source{SourceNginx, SourceLua}}, "bc"},
		{DebugFilter{Sources: []Source{"unknown"}}, ""},
	} {
		if got := messages(c.f); got != c.want {
			t.Errorf("%+v: %q, want %q", c.f, got, c.want)
		}
	}
	many := make([]Entry, MaxDebugUpload+5)
	for i := range many {
		many[i] = Entry{Message: "m"}
	}
	kept, cut := LimitDebug(many)
	if len(kept) != MaxDebugUpload || !cut || &kept[0] != &many[5] {
		t.Fatalf("kept %d cut %v", len(kept), cut)
	}
	if kept, cut := LimitDebug(many[:3]); len(kept) != 3 || cut {
		t.Fatal("small upload cut")
	}
}

func TestMergeDebugOrdersByTime(t *testing.T) {
	base := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	a := DebugSnapshot{Entries: []Entry{{Time: base, Message: "a1"}, {Time: base.Add(2 * time.Second), Message: "a2"}},
		Oldest: base, Overwritten: 1}
	b := DebugSnapshot{Entries: []Entry{{Time: base.Add(time.Second), Message: "b1"}, {Time: base.Add(2 * time.Second), Message: "b2"}},
		Oldest: base.Add(-time.Minute), Overwritten: 2, Truncated: true}
	m := MergeDebug(a, b)
	var got []string
	for _, e := range m.Entries {
		got = append(got, e.Message)
	}
	if strings.Join(got, ",") != "a1,b1,a2,b2" || !m.Oldest.Equal(base.Add(-time.Minute)) || m.Overwritten != 3 || !m.Truncated {
		t.Fatalf("%v %+v", got, m)
	}
	if m := MergeDebug(DebugSnapshot{}, a); !m.Oldest.Equal(base) {
		t.Fatalf("oldest %v", m.Oldest)
	}
	if p := (Entry{Level: LevelDebug, Source: SourceLua}).Proto(); p.GetLevel() != nodev1.NodeLogLevel_NODE_LOG_LEVEL_DEBUG {
		t.Fatal(p)
	}
}

func TestHandlerFeedsTheRing(t *testing.T) {
	var entries, debug []Entry
	var out strings.Builder
	base := slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelWarn})
	h := NewHandler(base, func(e Entry) { entries = append(entries, e) }, SourceSupervisor).
		Debug(func(e Entry) { debug = append(debug, e) })
	log := slog.New(h).With("component", "tasks")
	if !h.Enabled(t.Context(), slog.LevelDebug) {
		t.Fatal("debug records must reach the ring")
	}
	log.Debug("pulled tasks", "count", 2)
	log.Info("task finished", EventKey, "custom")
	log.Warn("upload failed")
	log.With(Skip).Error("node logs upload failed")
	if len(debug) != 3 || debug[0].Level != LevelDebug || debug[0].Fields["count"] != "2" || debug[0].Component != "tasks" ||
		debug[0].Source != SourceSupervisor || debug[1].Level != LevelInfo || debug[1].Event != "custom" || debug[2].Level != LevelWarn {
		t.Fatalf("debug %+v", debug)
	}
	// The collector still gets warnings and events only; local output keeps its level.
	if len(entries) != 1 || entries[0].Message != "upload failed" {
		t.Fatalf("entries %+v", entries)
	}
	if strings.Contains(out.String(), "pulled tasks") || !strings.Contains(out.String(), "node logs upload failed") {
		t.Fatal(out.String())
	}
	// Without a ring debug records stay off unless the base wants them.
	if NewHandler(base, nil, SourceAgent).Enabled(t.Context(), slog.LevelDebug) {
		t.Fatal("enabled without a ring")
	}
}

func TestParseNginxDebug(t *testing.T) {
	now := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	e, ok := ParseNginxDebug("2026/10/23 10:00:00 [notice] 1#1: signal process started", now)
	if !ok || e.Level != LevelInfo || e.Fields["severity"] != "notice" || e.Message != "signal process started" {
		t.Fatalf("%+v %v", e, ok)
	}
	if _, ok := ParseNginx("2026/10/23 10:00:00 [notice] 1#1: signal process started", now); ok {
		t.Fatal("notice must not become a node log entry")
	}
	e, ok = ParseNginxDebug("2026/10/23 10:00:00 [debug] 7#7: *3 [lua] cache.lua:10: miss, client: 192.0.2.1, server: a.test", now)
	if !ok || e.Level != LevelDebug || e.Source != SourceLua || e.Fields["client"] != "192.0.2.1" {
		t.Fatalf("%+v %v", e, ok)
	}
	if _, ok := ParseNginxDebug("2026/10/23 10:00:00 [error] 7#7: *3 ModSecurity: Access denied with code 403", now); ok {
		t.Fatal("ModSecurity's denied lines stay out")
	}
}
