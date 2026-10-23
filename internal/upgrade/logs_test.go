package upgrade

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/nodelog"
)

func logsCall(t *testing.T, s *Supervisor, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(method, target, strings.NewReader(body)))
	return w
}

func TestSupervisorServesLogs(t *testing.T) {
	logs := nodelog.NewCollector(nodelog.Options{Capacity: 2})
	s := &Supervisor{opts: Options{Logs: logs}, logInstance: "abc"}
	for _, m := range []string{"one", "two", "three"} {
		logs.Add(nodelog.Entry{Level: nodelog.LevelError, Source: nodelog.SourceNginx, Message: m})
	}
	var caps Capabilities
	if err := json.NewDecoder(logsCall(t, s, http.MethodGet, "/capabilities", "").Body).Decode(&caps); err != nil || !caps.Logs || caps.Engine {
		t.Fatalf("capabilities %+v %v", caps, err)
	}
	read := func(target string) LogsPage {
		w := logsCall(t, s, http.MethodGet, target, "")
		if w.Code != 200 {
			t.Fatalf("%s: %d", target, w.Code)
		}
		var page LogsPage
		if err := json.NewDecoder(w.Body).Decode(&page); err != nil {
			t.Fatal(err)
		}
		return page
	}
	// Another instance's numbers count for nothing: everything kept.
	page := read("/logs?instance=old&after=3")
	if page.Instance != "abc" || len(page.Entries) != 2 || page.Entries[0].Message != "two" || page.Last != 3 ||
		page.DroppedOverflow != 1 || page.OverflowMark != 1 {
		t.Fatalf("%+v", page)
	}
	if page := read("/logs?instance=abc&after=3"); len(page.Entries) != 0 || page.Last != 3 {
		t.Fatalf("%+v", page)
	}
	// An acknowledgement of another instance changes nothing.
	logsCall(t, s, http.MethodPost, "/logs/ack", `{"instance":"old","upto":3,"overflow_mark":1}`)
	if page := read("/logs?instance=abc&after=0"); len(page.Entries) != 2 || page.DroppedOverflow != 1 {
		t.Fatalf("%+v", page)
	}
	if w := logsCall(t, s, http.MethodPost, "/logs/ack", `{"instance":"abc","upto":3,"overflow_mark":1}`); w.Code != 200 {
		t.Fatalf("ack %d", w.Code)
	}
	if page := read("/logs?instance=abc&after=0"); len(page.Entries) != 0 || page.DroppedOverflow != 0 || page.OverflowMark != 1 {
		t.Fatalf("%+v", page)
	}
	if w := logsCall(t, s, http.MethodPut, "/logs", ""); w.Code != 405 {
		t.Fatalf("PUT %d", w.Code)
	}
	if w := logsCall(t, &Supervisor{}, http.MethodGet, "/logs", ""); w.Code != 404 {
		t.Fatalf("without logs %d", w.Code)
	}
}

func TestSupervisorServesDebugLogs(t *testing.T) {
	s := &Supervisor{}
	if w := logsCall(t, s, http.MethodGet, "/debug-logs", ""); w.Code != 404 {
		t.Fatalf("without a ring: %d", w.Code)
	}
	ring := nodelog.NewRing(10)
	s = &Supervisor{opts: Options{DebugLogs: ring}}
	base := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	ring.Add(nodelog.Entry{Time: base, Level: nodelog.LevelDebug, Source: nodelog.SourceSupervisor, Component: "upgrade", Message: "one"})
	ring.Add(nodelog.Entry{Time: base.Add(time.Second), Level: nodelog.LevelInfo, Source: nodelog.SourceNginx, Message: "two"})
	ring.Add(nodelog.Entry{Time: base.Add(2 * time.Second), Level: nodelog.LevelWarn, Source: nodelog.SourceLua, Message: "three"})
	var caps Capabilities
	if err := json.NewDecoder(logsCall(t, s, http.MethodGet, "/capabilities", "").Body).Decode(&caps); err != nil || !caps.DebugLogs || caps.Logs {
		t.Fatalf("capabilities %+v %v", caps, err)
	}
	if w := logsCall(t, s, http.MethodPost, "/debug-logs", ""); w.Code != 405 {
		t.Fatalf("POST: %d", w.Code)
	}
	if w := logsCall(t, s, http.MethodGet, "/debug-logs?since=yesterday", ""); w.Code != 400 {
		t.Fatalf("bad since: %d", w.Code)
	}
	f := nodelog.DebugFilter{Since: base.Add(time.Second), Sources: []nodelog.Source{nodelog.SourceNginx, nodelog.SourceLua}}
	w := logsCall(t, s, http.MethodGet, "/debug-logs?"+debugFilterQuery(f).Encode(), "")
	var snap nodelog.DebugSnapshot
	if err := json.NewDecoder(w.Body).Decode(&snap); err != nil || w.Code != 200 {
		t.Fatalf("%d %v", w.Code, err)
	}
	if len(snap.Entries) != 2 || snap.Entries[0].Message != "two" || snap.Entries[1].Level != nodelog.LevelWarn || !snap.Oldest.Equal(base) {
		t.Fatalf("%+v", snap)
	}
	got, err := parseDebugFilter(debugFilterQuery(nodelog.DebugFilter{Until: base, Components: []string{"a", "b"}}))
	if err != nil || !got.Until.Equal(base) || !got.Since.IsZero() || len(got.Components) != 2 || got.Sources != nil {
		t.Fatalf("%+v %v", got, err)
	}
}
