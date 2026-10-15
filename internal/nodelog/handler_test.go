package nodelog

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func newTestLogger(level slog.Level) (*slog.Logger, *bytes.Buffer, *[]Entry) {
	var out bytes.Buffer
	var entries []Entry
	base := slog.NewTextHandler(&out, &slog.HandlerOptions{Level: level})
	return slog.New(NewHandler(base, func(e Entry) { entries = append(entries, e) }, SourceAgent)), &out, &entries
}

func TestHandlerAddsWarningsAndEvents(t *testing.T) {
	log, out, entries := newTestLogger(slog.LevelWarn)
	log = log.With("component", "channel")
	log.Info("pushed site table", "revision", 3)
	log.Info("configuration applied", "revision", 4, EventKey, EventConfigApplied)
	log.Warn("report failed", "err", errors.New("unavailable"), slog.Group("retry", "in", "5s"))
	log.Error("cannot save", EventKey, EventConfigApplied)
	log.Debug("noise")
	if len(*entries) != 3 {
		t.Fatalf("%d entries: %+v", len(*entries), *entries)
	}
	ev, w, e := (*entries)[0], (*entries)[1], (*entries)[2]
	if ev.Level != LevelInfo || ev.Event != EventConfigApplied || ev.Fields["revision"] != "4" || ev.Component != "channel" {
		t.Fatalf("event %+v", ev)
	}
	if w.Level != LevelWarn || w.Fields["err"] != "unavailable" || w.Fields["retry.in"] != "5s" || w.Source != SourceAgent {
		t.Fatalf("warning %+v", w)
	}
	if e.Level != LevelError || e.Event != "" {
		t.Fatalf("error %+v", e)
	}
	// Local output keeps its own level.
	if strings.Contains(out.String(), "configuration applied") || !strings.Contains(out.String(), "report failed") {
		t.Fatalf("output %q", out.String())
	}
}

func TestHandlerGroups(t *testing.T) {
	log, _, entries := newTestLogger(slog.LevelInfo)
	log.WithGroup("upgrade").With("version", "1.3.0").Warn("rolled back", "task", "t1")
	if f := (*entries)[0].Fields; f["upgrade.version"] != "1.3.0" || f["upgrade.task"] != "t1" {
		t.Fatalf("%+v", f)
	}
}

func TestHandlerSkip(t *testing.T) {
	log, out, entries := newTestLogger(slog.LevelInfo)
	log.With(Skip).Warn("node logs upload failed")
	log.Warn("nginx line", Skip, "line", "x")
	if len(*entries) != 0 {
		t.Fatalf("%+v", *entries)
	}
	if strings.Contains(out.String(), skipKey) || !strings.Contains(out.String(), "nginx line") || !strings.Contains(out.String(), "line=x") {
		t.Fatalf("output %q", out.String())
	}
}
