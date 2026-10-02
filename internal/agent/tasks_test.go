package agent_test

import (
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marvinli001/edgeweir-node/internal/agent"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// slowEdge imitates the node's local edge listener for prefetches,
// answering after delay; it returns the socket and a request counter.
func slowEdge(t *testing.T, delay time.Duration) (string, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	path := listenEdge(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		if strings.HasPrefix(r.URL.Path, "/status/") {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_, _ = w.Write([]byte("body"))
	}), nil)
	return path, &n
}

func prefetchTask(id string, urls ...string) *nodev1.NodeTask {
	p := &nodev1.PrefetchTask{}
	for _, u := range urls {
		p.Targets = append(p.Targets, &nodev1.PrefetchTarget{SiteId: "site-a", Url: u})
	}
	return &nodev1.NodeTask{Id: id, CreatedAt: timestamppb.Now(), Kind: &nodev1.NodeTask_Prefetch{Prefetch: p}}
}

func edgeConfig() *nodev1.NodeConfig {
	return baseConfig(demoSite("site-a", "site-a.test"))
}

// TestAgentRunsPurgesBeforePrefetches (N-M7): in one pulled batch the
// purge runs first although the slow prefetch was queued before it.
func TestAgentRunsPurgesBeforePrefetches(t *testing.T) {
	edge, _ := slowEdge(t, 300*time.Millisecond)
	e := startEnrolledConfig(t, "order", atEdge(edge, "", func(c *agent.Config) {
		c.TaskPollInterval = time.Hour
		c.PrefetchConcurrency = 1
	}), edgeConfig())
	e.console.AddTasks(true,
		prefetchTask("prefetch-1", "http://site-a.test/1", "http://site-a.test/2"),
		purgeTask("purge-1", time.Now(), urlTarget("site-a", "/x")))
	// Both are found through the heartbeat (tasks_pending): the purge runs
	// on its own lane, or first in a shared batch.
	res := waitResults(t, e.console, 2)
	if res[0].GetTaskId() != "purge-1" || res[1].GetTaskId() != "prefetch-1" {
		t.Fatalf("results in order %s, %s; want the purge first", res[0].GetTaskId(), res[1].GetTaskId())
	}
	if res[1].GetState() != nodev1.TaskState_TASK_STATE_SUCCEEDED || res[1].GetSucceeded() != 2 {
		t.Fatalf("prefetch = %v", res[1])
	}
}

// TestAgentPurgesDoNotWaitForPrefetches (P1-62): a purge created while an
// earlier batch of prefetches still runs is pulled on the purge lane
// (purge_only) and done long before the prefetches end.
func TestAgentPurgesDoNotWaitForPrefetches(t *testing.T) {
	edge, requests := slowEdge(t, 2*time.Second)
	e := startEnrolledConfig(t, "lane", atEdge(edge, "", func(c *agent.Config) {
		c.TaskPollInterval = time.Hour
		c.PrefetchConcurrency = 1
	}), edgeConfig())
	e.console.AddTask(prefetchTask("prefetch-slow", "http://site-a.test/1", "http://site-a.test/2"), false)
	eventually(t, "prefetch started", func() bool { return requests.Load() == 1 })
	start := time.Now()
	e.console.AddTask(purgeTask("purge-late", time.Now(), urlTarget("site-a", "/x")), false)
	res := waitResults(t, e.console, 1)[0]
	if res.GetTaskId() != "purge-late" || time.Since(start) > time.Second {
		t.Fatalf("first result %s after %v; want the purge at once", res.GetTaskId(), time.Since(start))
	}
	if !slices.Contains(e.console.TaskPulls(), true) {
		t.Fatalf("no purge_only pull: %v", e.console.TaskPulls())
	}
	if r := waitResults(t, e.console, 2)[1]; r.GetTaskId() != "prefetch-slow" || r.GetState() != nodev1.TaskState_TASK_STATE_SUCCEEDED {
		t.Fatalf("prefetch = %v", r)
	}
}

// TestAgentPrefetchTimeBudget (N-M7): a prefetch stops when the batch's
// budget runs out and reports the URLs it did not finish as failed.
func TestAgentPrefetchTimeBudget(t *testing.T) {
	edge, requests := slowEdge(t, 2*time.Second)
	e := startEnrolledConfig(t, "budget", atEdge(edge, "", func(c *agent.Config) {
		c.PrefetchBudget = 400 * time.Millisecond
		c.PrefetchConcurrency = 1
	}), edgeConfig())
	start := time.Now()
	e.console.AddTask(prefetchTask("prefetch-slow", "http://site-a.test/1", "http://site-a.test/2", "http://site-a.test/3"), false)
	res := waitResults(t, e.console, 1)[0]
	if took := time.Since(start); took > 1800*time.Millisecond {
		t.Fatalf("prefetch took %v, the budget is 400ms", took)
	}
	if res.GetState() != nodev1.TaskState_TASK_STATE_FAILED || res.GetSucceeded() != 0 || res.GetFailed() != 3 ||
		!strings.Contains(res.GetMessage(), "prefetch time budget exhausted: 0 of 3 URLs done") ||
		res.GetErrorCode() != "prefetch_timeout" || !maps.Equal(res.GetErrorParams(), map[string]string{"done": "0", "total": "3"}) {
		t.Fatalf("result = %v", res)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("%d requests started, want only the first one (concurrency 1)", n)
	}
}

// TestAgentPrefetchFailureCodes (CP-M9): the first failed URL and its reason
// travel as error_code prefetch_failed with parameters.
func TestAgentPrefetchFailureCodes(t *testing.T) {
	edge, _ := slowEdge(t, 0)
	e := startEnrolledConfig(t, "codes", atEdge(edge, ""), edgeConfig())
	e.console.AddTask(prefetchTask("p-status", "http://site-a.test/ok", "http://site-a.test/status/1", "http://site-a.test/status/2"), false)
	res := waitResults(t, e.console, 1)[0]
	want := map[string]string{"failed": "2", "total": "3", "url": "http://site-a.test/status/1", "reason": "status", "status": "503"}
	if res.GetErrorCode() != "prefetch_failed" || !maps.Equal(res.GetErrorParams(), want) || res.GetSucceeded() != 1 {
		t.Fatalf("result = %v", res)
	}
	e.console.AddTask(prefetchTask("p-https", "https://site-a.test/x"), false)
	res = waitResults(t, e.console, 2)[1]
	if res.GetErrorCode() != "prefetch_failed" || res.GetErrorParams()["reason"] != "https_unsupported" || res.GetErrorParams()["status"] != "" {
		t.Fatalf("https result = %v", res)
	}
	e.console.AddTask(prefetchTask("p-ok", "http://site-a.test/fine"), false)
	res = waitResults(t, e.console, 3)[2]
	if res.GetState() != nodev1.TaskState_TASK_STATE_SUCCEEDED || res.GetErrorCode() != "" || len(res.GetErrorParams()) != 0 {
		t.Fatalf("successful prefetch carries an error: %v", res)
	}
}

// TestAgentPrefetchConnectFailed: nothing listens on the local edge socket.
func TestAgentPrefetchConnectFailed(t *testing.T) {
	e := startEnrolledConfig(t, "refused", atEdge(edgeSocket(t), ""), edgeConfig())
	e.console.AddTask(prefetchTask("p-refused", "http://site-a.test/x"), false)
	res := waitResults(t, e.console, 1)[0]
	if res.GetErrorCode() != "prefetch_failed" || res.GetErrorParams()["reason"] != "connect_failed" {
		t.Fatalf("result = %v", res)
	}
}

// TestAgentReportsUnsupportedTasks: a task kind added by a newer console
// fails with task_unsupported and the unknown field number.
func TestAgentReportsUnsupportedTasks(t *testing.T) {
	e := startEnrolled(t, "unknown", nil, demoSite("site-a", "site-a.test"))
	task := &nodev1.NodeTask{Id: "t-new", CreatedAt: timestamppb.Now()}
	// A oneof case this node does not know: field 9, a message.
	var unknown []byte
	unknown = protowire.AppendTag(unknown, 9, protowire.BytesType)
	unknown = protowire.AppendBytes(unknown, []byte{0x0a, 0x01, 'x'})
	task.ProtoReflect().SetUnknown(unknown)
	e.console.AddTask(task, false)
	e.console.AddTask(&nodev1.NodeTask{Id: "t-empty", CreatedAt: timestamppb.Now()}, false)
	res := waitResults(t, e.console, 2)
	if res[0].GetState() != nodev1.TaskState_TASK_STATE_FAILED || res[0].GetErrorCode() != "task_unsupported" ||
		res[0].GetErrorParams()["type"] != "field_9" || !strings.Contains(res[0].GetMessage(), "upgrade edgeweir-node") {
		t.Fatalf("unknown task result = %v", res[0])
	}
	if res[1].GetErrorCode() != "task_unsupported" || res[1].GetErrorParams()["type"] != "unknown" {
		t.Fatalf("empty task result = %v", res[1])
	}
}

// TestAgentPrefetchUsesTheLocalSocket: prefetches never go to the public
// listeners (where bans, CC and challenges apply), plain HTTP ones
// included, but to the local edge socket.
func TestAgentPrefetchUsesTheLocalSocket(t *testing.T) {
	var publicHits atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		publicHits.Add(1)
		_, _ = w.Write([]byte("public"))
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	cfg := edgeConfig()
	cfg.Listeners[0].Port = uint32(ln.Addr().(*net.TCPAddr).Port)
	cfg.Listeners = append(cfg.Listeners, &nodev1.Listener{Port: 8080, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTP, ProxyProtocol: true})
	edge, hits := slowEdge(t, 0)
	e := startEnrolledConfig(t, "local", atEdge(edge, ""), cfg)
	e.console.AddTask(prefetchTask("p-local", "http://site-a.test/a"), false)
	if res := waitResults(t, e.console, 1)[0]; res.GetState() != nodev1.TaskState_TASK_STATE_SUCCEEDED || hits.Load() != 1 || publicHits.Load() != 0 {
		t.Fatalf("prefetch: %v (local %d, public %d)", res, hits.Load(), publicHits.Load())
	}
}
