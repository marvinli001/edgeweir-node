package agent_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/edgeweir/edgeweir-node/internal/agent"
	nodev1 "github.com/edgeweir/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// slowEdge imitates the node's edge listener for prefetches, answering
// after delay; it returns the port and a request counter.
func slowEdge(t *testing.T, delay time.Duration) (uint32, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return uint32(ln.Addr().(*net.TCPAddr).Port), &n
}

func prefetchTask(id string, urls ...string) *nodev1.NodeTask {
	p := &nodev1.PrefetchTask{}
	for _, u := range urls {
		p.Targets = append(p.Targets, &nodev1.PrefetchTarget{SiteId: "site-a", Url: u})
	}
	return &nodev1.NodeTask{Id: id, CreatedAt: timestamppb.Now(), Kind: &nodev1.NodeTask_Prefetch{Prefetch: p}}
}

func edgeConfig(port uint32) *nodev1.NodeConfig {
	c := baseConfig(demoSite("site-a", "site-a.test"))
	c.Listeners[0].Port = port
	return c
}

// TestAgentRunsPurgesBeforePrefetches (N-M7): in one pulled batch the
// purge runs first although the slow prefetch was queued before it.
func TestAgentRunsPurgesBeforePrefetches(t *testing.T) {
	port, _ := slowEdge(t, 300*time.Millisecond)
	e := startEnrolledConfig(t, "order", func(c *agent.Config) {
		c.TaskPollInterval = time.Hour
		c.PrefetchConcurrency = 1
	}, edgeConfig(port))
	e.console.AddTasks(true,
		prefetchTask("prefetch-1", "http://site-a.test/1", "http://site-a.test/2"),
		purgeTask("purge-1", time.Now(), urlTarget("site-a", "/x")))
	// Both are found through the heartbeat (tasks_pending) in one pull.
	res := waitResults(t, e.console, 2)
	if res[0].GetTaskId() != "purge-1" || res[1].GetTaskId() != "prefetch-1" {
		t.Fatalf("results in order %s, %s; want the purge first", res[0].GetTaskId(), res[1].GetTaskId())
	}
	if res[1].GetState() != nodev1.TaskState_TASK_STATE_SUCCEEDED || res[1].GetSucceeded() != 2 {
		t.Fatalf("prefetch = %v", res[1])
	}
}

// TestAgentPrefetchTimeBudget (N-M7): a prefetch stops when the batch's
// budget runs out and reports the URLs it did not finish as failed.
func TestAgentPrefetchTimeBudget(t *testing.T) {
	port, requests := slowEdge(t, 2*time.Second)
	e := startEnrolledConfig(t, "budget", func(c *agent.Config) {
		c.PrefetchBudget = 400 * time.Millisecond
		c.PrefetchConcurrency = 1
	}, edgeConfig(port))
	start := time.Now()
	e.console.AddTask(prefetchTask("prefetch-slow", "http://site-a.test/1", "http://site-a.test/2", "http://site-a.test/3"), false)
	res := waitResults(t, e.console, 1)[0]
	if took := time.Since(start); took > 1800*time.Millisecond {
		t.Fatalf("prefetch took %v, the budget is 400ms", took)
	}
	if res.GetState() != nodev1.TaskState_TASK_STATE_FAILED || res.GetSucceeded() != 0 || res.GetFailed() != 3 ||
		!strings.Contains(res.GetMessage(), "prefetch time budget exhausted: 0 of 3 URLs done") {
		t.Fatalf("result = %v", res)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("%d requests started, want only the first one (concurrency 1)", n)
	}
}
