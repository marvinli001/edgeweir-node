package agent_test

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marvinli001/edgeweir-node/internal/agent"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/nodelog"
	"github.com/marvinli001/edgeweir-node/internal/upgrade"
)

func debugLogsTask(id string, t *nodev1.DebugLogsTask) *nodev1.NodeTask {
	return &nodev1.NodeTask{Id: id, CreatedAt: timestamppb.Now(), Kind: &nodev1.NodeTask_DebugLogs{DebugLogs: t}}
}

// startDebugSupervisor serves a supervisor's /capabilities and, with a
// ring, /debug-logs (sources filtered as the real one does).
func startDebugSupervisor(t *testing.T, ring *nodelog.Ring) string {
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
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/capabilities":
			_ = json.NewEncoder(w).Encode(upgrade.Capabilities{Engine: true, DebugLogs: ring != nil})
		case "/debug-logs":
			var f nodelog.DebugFilter
			for _, s := range r.URL.Query()["source"] {
				f.Sources = append(f.Sources, nodelog.Source(s))
			}
			_ = json.NewEncoder(w).Encode(ring.Snapshot(f))
		default:
			http.NotFound(w, r)
		}
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func TestDebugLogsTaskUploadsBothRings(t *testing.T) {
	base := time.Now().Add(-time.Minute)
	supRing := nodelog.NewRing(10)
	supRing.Add(nodelog.Entry{Time: base.Add(time.Second), Level: nodelog.LevelInfo, Source: nodelog.SourceNginx, Message: "signal process started"})
	supRing.Add(nodelog.Entry{Time: base.Add(3 * time.Second), Level: nodelog.LevelDebug, Source: nodelog.SourceSupervisor, Message: "child healthy"})
	sock := startDebugSupervisor(t, supRing)
	e := startEnrolled(t, "debuglogs", func(cfg *agent.Config) {
		cfg.DebugLogs = nodelog.NewRing(10)
		cfg.SupervisorSocket = sock
	}, demoSite("site-a", "site-a.test"))
	e.cfg.DebugLogs.Add(nodelog.Entry{Time: base, Level: nodelog.LevelDebug, Source: nodelog.SourceAgent, Component: "tasks",
		Message: "pulled https://origin.test/a?token=secret", Fields: map[string]string{"password": "hunter2"}})
	e.cfg.DebugLogs.Add(nodelog.Entry{Time: base.Add(2 * time.Second), Level: nodelog.LevelWarn, Source: nodelog.SourceLua, Message: "lua warning"})
	eventually(t, "debug-logs-v1 reported", func() bool {
		return slices.Contains(e.console.LastStatus().GetInfo().GetSupportedFeatures(), nodelog.DebugFeature)
	})

	e.console.AddTask(debugLogsTask("d1", &nodev1.DebugLogsTask{}), false)
	res := waitResults(t, e.console, 1)
	if res[0].GetTaskId() != "d1" || res[0].GetState() != nodev1.TaskState_TASK_STATE_SUCCEEDED || res[0].GetSucceeded() != 4 {
		t.Fatalf("result %v", res[0])
	}
	up := e.console.DebugLogUploads()
	if len(up) != 1 || up[0].GetTaskId() != "d1" || up[0].GetSupervisorMissing() || !up[0].GetBufferSince().AsTime().Equal(base) {
		t.Fatalf("upload %v", up)
	}
	// Oldest first across both rings, secrets removed.
	var got []string
	for _, l := range up[0].GetEntries() {
		got = append(got, l.GetMessage())
	}
	if strings.Join(got, "|") != "pulled https://origin.test/a?[redacted]|signal process started|lua warning|child healthy" {
		t.Fatalf("entries %q", got)
	}
	first := up[0].GetEntries()[0]
	if first.GetLevel() != nodev1.NodeLogLevel_NODE_LOG_LEVEL_DEBUG || first.GetFields()["password"] != nodelog.Redacted || first.GetComponent() != "tasks" {
		t.Fatalf("first %v", first)
	}

	// Filters apply to both rings.
	e.console.AddTask(debugLogsTask("d2", &nodev1.DebugLogsTask{
		Sources: []nodev1.NodeLogSource{nodev1.NodeLogSource_NODE_LOG_SOURCE_NGINX, nodev1.NodeLogSource_NODE_LOG_SOURCE_LUA},
	}), false)
	waitResults(t, e.console, 2)
	up = e.console.DebugLogUploads()
	if len(up) != 2 || len(up[1].GetEntries()) != 2 || up[1].GetEntries()[0].GetMessage() != "signal process started" {
		t.Fatalf("filtered upload %v", up[1])
	}
}

func TestDebugLogsTaskFailures(t *testing.T) {
	// No ring: the task fails and the capability is not reported.
	e := startEnrolled(t, "debuglogs-off", nil, demoSite("site-a", "site-a.test"))
	e.console.AddTask(debugLogsTask("off", &nodev1.DebugLogsTask{}), false)
	res := waitResults(t, e.console, 1)
	if res[0].GetState() != nodev1.TaskState_TASK_STATE_FAILED || res[0].GetErrorCode() != "debug_logs_failed" ||
		res[0].GetErrorParams()["reason"] != "disabled" {
		t.Fatalf("result %v", res[0])
	}
	if slices.Contains(e.console.LastStatus().GetInfo().GetSupportedFeatures(), nodelog.DebugFeature) {
		t.Fatal("debug-logs-v1 reported without a ring")
	}

	// An older supervisor keeps no ring; a failed upload fails the task.
	sock := startDebugSupervisor(t, nil)
	e = startEnrolled(t, "debuglogs-old-sup", func(cfg *agent.Config) {
		cfg.DebugLogs = nodelog.NewRing(10)
		cfg.SupervisorSocket = sock
	}, demoSite("site-a", "site-a.test"))
	e.console.FailDebugLogUploads(1)
	e.console.AddTask(debugLogsTask("lost", &nodev1.DebugLogsTask{}), false)
	res = waitResults(t, e.console, 1)
	if res[0].GetState() != nodev1.TaskState_TASK_STATE_FAILED || res[0].GetErrorParams()["reason"] != "upload_failed" {
		t.Fatalf("result %v", res[0])
	}
	e.console.AddTask(debugLogsTask("ok", &nodev1.DebugLogsTask{}), false)
	waitResults(t, e.console, 2)
	if up := e.console.DebugLogUploads(); len(up) != 1 || !up[0].GetSupervisorMissing() {
		t.Fatalf("upload %v", up)
	}
}
