package upgrade

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
