package agent_test

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/agent"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/nodelog"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
	"github.com/marvinli001/edgeweir-node/internal/upgrade"
)

func withNodeLogs(cfg *agent.Config) {
	cfg.NodeLogs = nodelog.NewCollector(nodelog.Options{})
	cfg.NodeLogsSealAfter = 100 * time.Millisecond
	cfg.NodeLogsUnsupportedRetry = 200 * time.Millisecond
}

func nodeLogEntries(c *fakeconsole.Console) []*nodev1.NodeLogEntry {
	entries, _, _ := c.NodeLogs()
	return entries
}

func findNodeLog(c *fakeconsole.Console, match func(*nodev1.NodeLogEntry) bool) *nodev1.NodeLogEntry {
	for _, e := range nodeLogEntries(c) {
		if match(e) {
			return e
		}
	}
	return nil
}

func byMessage(m string) func(*nodev1.NodeLogEntry) bool {
	return func(e *nodev1.NodeLogEntry) bool { return e.GetMessage() == m }
}

func TestNodeLogsReachTheConsole(t *testing.T) {
	e := startEnrolled(t, "nodelogs", withNodeLogs, demoSite("site-a", "site-a.test"))
	eventually(t, "configuration event", func() bool {
		return findNodeLog(e.console, func(l *nodev1.NodeLogEntry) bool { return l.GetEvent() == nodelog.EventConfigApplied }) != nil
	})
	ev := findNodeLog(e.console, func(l *nodev1.NodeLogEntry) bool { return l.GetEvent() == nodelog.EventConfigApplied })
	if ev.GetLevel() != nodev1.NodeLogLevel_NODE_LOG_LEVEL_INFO || ev.GetSource() != nodev1.NodeLogSource_NODE_LOG_SOURCE_AGENT ||
		ev.GetFields()["revision"] != strconv.FormatUint(e.rev, 10) {
		t.Fatalf("event %v", ev)
	}
	if !slices.Contains(e.console.LastStatus().GetInfo().GetSupportedFeatures(), nodelog.Feature) {
		t.Fatal("node-logs-v1 not reported")
	}
	e.cfg.NodeLogs.Add(nodelog.Entry{Level: nodelog.LevelWarn, Source: nodelog.SourceAgent,
		Message: `Get "https://origin.test/a?X-Amz-Signature=secret": timeout`, Fields: map[string]string{"token": "secret"}})
	eventually(t, "warning", func() bool {
		return findNodeLog(e.console, byMessage(`Get "https://origin.test/a?[redacted]": timeout`)) != nil
	})
	w := findNodeLog(e.console, byMessage(`Get "https://origin.test/a?[redacted]": timeout`))
	if w.GetFields()["token"] != nodelog.Redacted || w.GetLevel() != nodev1.NodeLogLevel_NODE_LOG_LEVEL_WARN {
		t.Fatalf("warning %v", w)
	}
	// Info records without an event and the upload's own messages stay local.
	for _, l := range nodeLogEntries(e.console) {
		if l.GetLevel() == nodev1.NodeLogLevel_NODE_LOG_LEVEL_INFO && l.GetEvent() == "" {
			t.Fatalf("info entry without event: %v", l)
		}
		if strings.Contains(l.GetMessage(), "node logs") || strings.Contains(l.GetMessage(), "ReportNodeLogs") {
			t.Fatalf("upload message uploaded: %v", l)
		}
	}
}

func TestNodeLogsRetryAndRestartUseDurableSequences(t *testing.T) {
	e := startEnrolled(t, "nodelogs-retry", withNodeLogs, demoSite("site-a", "site-a.test"))
	eventually(t, "first batch", func() bool { _, seqs, _ := e.console.NodeLogs(); return len(seqs) > 0 })
	e.console.FailNodeLogsAcknowledgements(1)
	e.cfg.NodeLogs.Add(nodelog.Entry{Level: nodelog.LevelError, Source: nodelog.SourceAgent, Message: "retried"})
	eventually(t, "retry acknowledged", func() bool {
		_, seqs, _ := e.console.NodeLogs()
		n := len(seqs)
		return n >= 2 && seqs[n-1] == seqs[n-2]
	})
	count := func(msg string) (n int) {
		for _, l := range nodeLogEntries(e.console) {
			if l.GetMessage() == msg {
				n++
			}
		}
		return n
	}
	if count("retried") != 1 {
		t.Fatalf("retry stored %d times", count("retried"))
	}
	e.stop()
	info, err := os.Stat(filepath.Join(e.cfg.StateDir, "nodelogs-spool.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("node logs spool is not private")
	}
	_, before, _ := e.console.NodeLogs()
	cfg := e.cfg
	withNodeLogs(&cfg)
	stop := startAgent(t, cfg, e.eng, dataplane.NewClient(e.dp.Socket))
	defer stop()
	cfg.NodeLogs.Add(nodelog.Entry{Level: nodelog.LevelWarn, Source: nodelog.SourceAgent, Message: "after restart"})
	eventually(t, "entry after restart", func() bool { return count("after restart") == 1 })
	_, after, _ := e.console.NodeLogs()
	if after[len(after)-1] <= before[len(before)-1] {
		t.Fatalf("sequence regressed after restart: %v then %v", before, after)
	}
}

func TestNodeLogsWaitForANewerConsole(t *testing.T) {
	e := startEnrolledPrepared(t, "nodelogs-old", withNodeLogs,
		func(c *fakeconsole.Console, _ *fakedataplane.Server) { c.SetNodeLogsUnsupported(true) }, baseConfig(demoSite("site-a", "site-a.test")))
	e.cfg.NodeLogs.Add(nodelog.Entry{Level: nodelog.LevelWarn, Source: nodelog.SourceAgent, Message: "kept"})
	time.Sleep(time.Second)
	if len(nodeLogEntries(e.console)) != 0 {
		t.Fatal("entries stored by a console without node logs")
	}
	e.console.SetNodeLogsUnsupported(false)
	eventually(t, "kept entry", func() bool { return findNodeLog(e.console, byMessage("kept")) != nil })
}

// fakeSupervisor serves the supervisor's /capabilities, /logs and
// /logs/ack from a collector.
type fakeSupervisor struct {
	logs  *nodelog.Collector
	mu    sync.Mutex
	acked [2]uint64
	acks  []upgrade.LogsAck
}

func startFakeSupervisor(t *testing.T, logs *nodelog.Collector) (*fakeSupervisor, string) {
	t.Helper()
	dir, err := os.MkdirTemp("", "sup")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSupervisor{logs: logs}
	srv := &http.Server{Handler: f}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return f, sock
}

func (f *fakeSupervisor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/capabilities":
		_ = json.NewEncoder(w).Encode(upgrade.Capabilities{Engine: true, Logs: true})
	case "/logs":
		after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		if r.URL.Query().Get("instance") != "i1" {
			after = 0
		}
		entries, last := f.logs.Read(after, 200)
		limited, overflow := f.logs.Dropped()
		f.mu.Lock()
		acked := f.acked
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(upgrade.LogsPage{Instance: "i1", Entries: entries, Last: last,
			DroppedRateLimited: limited - acked[0], DroppedOverflow: overflow - acked[1], RateLimitedMark: limited, OverflowMark: overflow})
	case "/logs/ack":
		var ack upgrade.LogsAck
		_ = json.NewDecoder(r.Body).Decode(&ack)
		f.logs.Discard(ack.Upto)
		f.mu.Lock()
		f.acked = [2]uint64{ack.RateLimitedMark, ack.OverflowMark}
		f.acks = append(f.acks, ack)
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	default:
		http.NotFound(w, r)
	}
}

func TestNodeLogsFromTheSupervisor(t *testing.T) {
	supLogs := nodelog.NewCollector(nodelog.Options{Capacity: 2})
	// Three entries in a buffer of two: one dropped before the agent reads.
	for _, m := range []string{"first", "second", "third"} {
		supLogs.Add(nodelog.Entry{Level: nodelog.LevelError, Source: nodelog.SourceNginx, Message: "upstream " + m})
	}
	sup, sock := startFakeSupervisor(t, supLogs)
	e := startEnrolled(t, "nodelogs-sup", func(cfg *agent.Config) {
		withNodeLogs(cfg)
		cfg.SupervisorSocket = sock
	}, demoSite("site-a", "site-a.test"))
	eventually(t, "supervisor entries", func() bool {
		return findNodeLog(e.console, byMessage("upstream third")) != nil
	})
	if findNodeLog(e.console, byMessage("upstream first")) != nil || findNodeLog(e.console, byMessage("upstream second")) == nil {
		t.Fatal("wrong entries")
	}
	if l := findNodeLog(e.console, byMessage("upstream third")); l.GetSource() != nodev1.NodeLogSource_NODE_LOG_SOURCE_NGINX {
		t.Fatalf("source %v", l.GetSource())
	}
	eventually(t, "acknowledged", func() bool {
		got, _ := supLogs.Read(0, 10)
		return len(got) == 0
	})
	_, _, dropped := e.console.NodeLogs()
	if dropped[1] != 1 {
		t.Fatalf("dropped %v", dropped)
	}
	// A restarted agent neither uploads them again nor counts the drop twice.
	e.stop()
	cfg := e.cfg
	withNodeLogs(&cfg)
	stop := startAgent(t, cfg, e.eng, dataplane.NewClient(e.dp.Socket))
	defer stop()
	supLogs.Add(nodelog.Entry{Level: nodelog.LevelWarn, Source: nodelog.SourceLua, Message: "later"})
	eventually(t, "later entry", func() bool { return findNodeLog(e.console, byMessage("later")) != nil })
	n := 0
	for _, l := range nodeLogEntries(e.console) {
		if l.GetMessage() == "upstream third" {
			n++
		}
	}
	_, _, dropped = e.console.NodeLogs()
	if n != 1 || dropped[1] != 1 {
		t.Fatalf("after restart: %d copies, dropped %v", n, dropped)
	}
	sup.mu.Lock()
	defer sup.mu.Unlock()
	if len(sup.acks) == 0 || sup.acks[0].Instance != "i1" {
		t.Fatalf("acks %v", sup.acks)
	}
}
