package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

// syncBuffer is a bytes.Buffer safe for one writer and a reader.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestAccesslogTextLine(t *testing.T) {
	e := dataplane.TapEntry{Time: 1800000000.1234, SiteID: "s1", ClientIP: "203.0.113.7", Method: "GET", Host: "a.test",
		Path: "/a b\x1b[2J", Status: 403, BytesSent: 512, DurationMS: 12, CacheStatus: ""}
	e.BlockReason = "rule"
	if got, want := textLine(e), "2027-01-15T08:00:00.123Z 203.0.113.7 GET a.test /a%20b[2J 403 512 12ms - blocked=rule"; got != want {
		t.Errorf("text line\n got %q\nwant %q", got, want)
	}
	e = dataplane.TapEntry{Time: 1800000000, ClientIP: "2001:db8::1", Method: "HEAD", Host: "b.test", Path: "/", Status: 200, CacheStatus: "HIT"}
	if got, want := textLine(e), "2027-01-15T08:00:00.000Z 2001:db8::1 HEAD b.test / 200 0 0ms HIT"; got != want {
		t.Errorf("text line\n got %q\nwant %q", got, want)
	}
}

func TestAccesslogJSONLine(t *testing.T) {
	e := dataplane.TapEntry{Time: 1800000000.5, SiteID: "s1", ClientIP: "203.0.113.7", Method: "GET", Host: "a.test", Path: "/x", Status: 200, BytesSent: 10}
	e.Country, e.UserAgent, e.UpstreamStatus = "NZ", "curl/8", 200
	raw, err := json.Marshal(jsonLine(e))
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back["time"] != "2027-01-15T08:00:00.500Z" || back["site_id"] != "s1" || back["country"] != "NZ" || back["user_agent"] != "curl/8" ||
		back["upstream_status"] != float64(200) || back["status"] != float64(200) {
		t.Fatalf("json line %s", raw)
	}
	if _, ok := back["block_reason"]; ok {
		t.Errorf("empty fields are left out: %s", raw)
	}
}

// TestAccesslogTails: the command polls the control socket, prints new
// requests as text or JSON Lines, reports missed ones on stderr, rides out
// a failing call and stops cleanly when its context ends.
func TestAccesslogTails(t *testing.T) {
	for _, asJSON := range []bool{false, true} {
		srv := fakedataplane.Start(t)
		var stdout, stderr syncBuffer
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- tailAccessLog(ctx, dataplane.NewClient(srv.Socket), "s1", asJSON, 5*time.Millisecond, &stdout, &stderr)
		}()
		waitFor(t, "the first call", func() bool { return len(srv.TapCalls()) > 0 })
		srv.AddTapEntry(map[string]any{"site_id": "s1", "time": 1800000000, "client_ip": "203.0.113.7", "method": "GET", "host": "a.test",
			"path": "/one", "status": 200, "bytes_sent": 5, "duration_ms": 1, "cache_status": "MISS"})
		srv.AddTapEntry(nil)
		srv.AddTapEntry(map[string]any{"site_id": "s1", "time": 1800000001, "client_ip": "203.0.113.7", "method": "POST", "host": "a.test",
			"path": "/two", "status": 403, "block_reason": "rule"})
		waitFor(t, "two lines", func() bool { return strings.Count(stdout.String(), "\n") >= 2 })
		srv.SetTapDropped(4) // requests over the data plane's rate take no number
		waitFor(t, "the dropped requests reported", func() bool { return strings.Contains(stderr.String(), "4 requests missed") })
		srv.FailTap(2)
		waitFor(t, "the failure reported", func() bool { return strings.Contains(stderr.String(), "retrying") })
		srv.AddTapEntry(map[string]any{"site_id": "s1", "time": 1800000002, "path": "/three", "status": 200})
		waitFor(t, "a third line", func() bool { return strings.Count(stdout.String(), "\n") >= 3 })
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("tail: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("tail did not stop")
		}
		lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
		if len(lines) != 3 {
			t.Fatalf("lines %q", lines)
		}
		if asJSON {
			var e map[string]any
			if err := json.Unmarshal([]byte(lines[1]), &e); err != nil || e["path"] != "/two" || e["block_reason"] != "rule" {
				t.Errorf("JSON line %q: %v", lines[1], err)
			}
		} else if lines[0] != "2027-01-15T08:00:00.000Z 203.0.113.7 GET a.test /one 200 5 1ms MISS" ||
			!strings.HasSuffix(lines[1], " 403 0 0ms - blocked=rule") {
			t.Errorf("text lines %q", lines)
		}
		if !strings.Contains(stderr.String(), "1 requests missed") || !strings.Contains(stderr.String(), "answers again") ||
			strings.Count(stderr.String(), "requests missed") != 2 {
			t.Errorf("stderr %q", stderr.String())
		}
		for _, q := range srv.TapCalls() {
			if !strings.HasSuffix(q, "&site=s1") {
				t.Errorf("call %q without the site", q)
			}
		}
	}
}

// TestAccesslogMissedSince: a page's missed requests are the numbers it
// skipped plus the growth of the data plane's dropped total since the
// previous page; a total that went down (nginx restarted) counts in full.
func TestAccesslogMissedSince(t *testing.T) {
	for _, c := range []struct {
		missed, dropped, prev, want uint64
	}{
		{0, 0, 0, 0},
		{2, 0, 0, 2},
		{0, 7, 7, 0},
		{1, 10, 7, 4},
		{0, 3, 9, 3},
	} {
		if got := missedSince(&dataplane.TapPage{Missed: c.missed, Dropped: c.dropped}, c.prev); got != c.want {
			t.Errorf("missed %d, dropped %d after %d: got %d, want %d", c.missed, c.dropped, c.prev, got, c.want)
		}
	}
}

func TestAccesslogCommandErrors(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := realMain([]string{"accesslog", "--socket", filepath.Join(t.TempDir(), "none.sock")}, &out, &errOut); code != 1 ||
		!strings.Contains(errOut.String(), "accesslog:") {
		t.Errorf("missing socket: exit %d, %q", code, errOut.String())
	}
	errOut.Reset()
	if code := realMain([]string{"accesslog", "--site", "a/b"}, &out, &errOut); code != 2 {
		t.Errorf("invalid site: exit %d, %q", code, errOut.String())
	}
	errOut.Reset()
	if code := realMain([]string{"accesslog", "-h"}, &out, &errOut); code != 0 || !strings.Contains(errOut.String(), "-json") {
		t.Errorf("help: exit %d, %q", code, errOut.String())
	}
	out.Reset()
	realMain([]string{"help"}, &out, &errOut)
	if !strings.Contains(out.String(), "edgeweir-node accesslog [--site ID] [--json] [--socket PATH]") {
		t.Errorf("usage lacks accesslog: %s", out.String())
	}
}
