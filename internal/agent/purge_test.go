package agent_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marvinli001/edgeweir-node/internal/agent"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

type enrolled struct {
	console *fakeconsole.Console
	dp      *fakedataplane.Server
	eng     *fakeEngine
	cfg     agent.Config
	h       *harness
	rev     uint64
}

// startEnrolled runs an agent against a fake console and data plane,
// enrolls it and waits until the configuration with sites is applied.
func startEnrolled(t *testing.T, name string, mutate func(*agent.Config), sites ...*nodev1.Site) *enrolled {
	t.Helper()
	return startEnrolledConfig(t, name, mutate, baseConfig(sites...))
}

func startEnrolledConfig(t *testing.T, name string, mutate func(*agent.Config), config *nodev1.NodeConfig) *enrolled {
	t.Helper()
	console, err := fakeconsole.New(fakeconsole.Options{
		NodeID: "node-" + name, ClusterID: "cl-" + name, ReportInterval: 1, KeepaliveInterval: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	root := t.TempDir()
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}
	rev := console.Publish(config)
	dp := fakedataplane.Start(t)
	cfg := h.agentConfig(dp.Socket)
	if mutate != nil {
		mutate(&cfg)
	}
	eng := newFakeEngine()
	startAgent(t, cfg, eng, dataplane.NewClient(dp.Socket))
	console.AddToken(name + "-token")
	if _, err := enroll.Run(context.Background(), enroll.Options{
		ServerURL: srv.URL, Token: name + "-token", CASHA256: console.CA.Pin(), StateDir: h.stateDir, Logger: testLogger(t),
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "configuration applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	return &enrolled{console: console, dp: dp, eng: eng, cfg: cfg, h: h, rev: rev}
}

func purgeTask(id string, created time.Time, targets ...*nodev1.PurgeTarget) *nodev1.NodeTask {
	return &nodev1.NodeTask{Id: id, CreatedAt: timestamppb.New(created), Kind: &nodev1.NodeTask_Purge{Purge: &nodev1.PurgeTask{Targets: targets}}}
}

func urlTarget(site, path string) *nodev1.PurgeTarget {
	return &nodev1.PurgeTarget{SiteId: site, Type: nodev1.PurgeType_PURGE_TYPE_URL, Host: site + ".test", Path: path}
}

func waitResults(t *testing.T, c *fakeconsole.Console, n int) []*nodev1.ReportTaskResultRequest {
	t.Helper()
	eventually(t, "task results", func() bool { return len(c.TaskResults()) >= n })
	return c.TaskResults()
}

// TestAgentServesSitesWhenPurgeSyncFails (N-H3): after an nginx restart the
// site table is pushed even when purge markers cannot be installed; the
// sites used to answer 404 until the next revision.
func TestAgentServesSitesWhenPurgeSyncFails(t *testing.T) {
	e := startEnrolled(t, "pf", nil, demoSite("site-a", "site-a.test"))
	e.console.AddTask(purgeTask("t1", time.Now(), urlTarget("site-a", "/x")), false)
	waitResults(t, e.console, 1)
	if len(e.dp.Markers()) != 1 {
		t.Fatalf("markers = %+v", e.dp.Markers())
	}
	e.dp.FailNextPurges(1 << 30)
	e.dp.Restart()
	eventually(t, "site table pushed although every purge call fails", func() bool {
		tb := e.dp.Table()
		return tb != nil && tb.Revision == e.rev && len(tb.Sites) == 1
	})
}

// TestAgentFallsBackToSiteLevelMarkers (N-H3): when the marker set does not
// fit into the data plane after a restart, every site with markers gets one
// site-level marker instead (over-purging), and the sites are served.
func TestAgentFallsBackToSiteLevelMarkers(t *testing.T) {
	e := startEnrolled(t, "fb", nil, demoSite("site-a", "site-a.test"), demoSite("site-b", "site-b.test"))
	e.console.AddTask(purgeTask("t1", time.Now(),
		urlTarget("site-a", "/1"), urlTarget("site-a", "/2"), urlTarget("site-a", "/3"),
		&nodev1.PurgeTarget{SiteId: "site-b", Type: nodev1.PurgeType_PURGE_TYPE_PREFIX, Host: "site-b.test", Path: "/s/"},
	), false)
	res := waitResults(t, e.console, 1)[0]
	if res.GetState() != nodev1.TaskState_TASK_STATE_SUCCEEDED || len(e.dp.Markers()) != 4 {
		t.Fatalf("result %v, markers %+v", res, e.dp.Markers())
	}
	epoch := e.dp.Markers()[0].Epoch
	e.dp.SetPurgeCapacity(2)
	e.dp.Restart()
	want := []dataplane.PurgeMarker{{SiteID: "site-a", Type: "site", Epoch: epoch}, {SiteID: "site-b", Type: "site", Epoch: epoch}}
	eventually(t, "site-level markers and the site table installed", func() bool {
		tb := e.dp.Table()
		return tb != nil && tb.Revision == e.rev && slices.Equal(e.dp.Markers(), want)
	})
	// The agent keeps the collapsed set, so the next restart fits at once.
	raw, err := os.ReadFile(filepath.Join(e.h.stateDir, "purge.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"type":"url"`) || strings.Contains(string(raw), `"type":"prefix"`) {
		t.Fatalf("purge.json still holds URL/prefix markers: %s", raw)
	}
}

// TestAgentPurgeMarkersPerSiteCap (N-H3): beyond the per-site cap a site's
// markers collapse into one site-level marker in the data plane too.
func TestAgentPurgeMarkersPerSiteCap(t *testing.T) {
	e := startEnrolled(t, "cap", func(c *agent.Config) { c.PurgeMarkersPerSite = 2 }, demoSite("site-a", "site-a.test"))
	e.console.AddTask(purgeTask("t1", time.Now(), urlTarget("site-a", "/1")), false)
	waitResults(t, e.console, 1)
	e.console.AddTask(purgeTask("t2", time.Now(), urlTarget("site-a", "/2"), urlTarget("site-a", "/3")), false)
	res := waitResults(t, e.console, 2)[1]
	if res.GetState() != nodev1.TaskState_TASK_STATE_SUCCEEDED || res.GetSucceeded() != 2 {
		t.Fatalf("result = %v", res)
	}
	eventually(t, "one site-level marker", func() bool {
		m := e.dp.Markers()
		return len(m) == 1 && m[0].Type == "site" && m[0].SiteID == "site-a"
	})
}

// TestAgentPurgeEpochPerTask (N-M3): a task handed out again keeps the
// epoch the node assigned first; a later task gets a later epoch even when
// its created_at is older.
func TestAgentPurgeEpochPerTask(t *testing.T) {
	e := startEnrolled(t, "ep", nil, demoSite("site-a", "site-a.test"))
	e.console.AddTask(purgeTask("t1", time.Now(), urlTarget("site-a", "/x")), false)
	waitResults(t, e.console, 1)
	first := e.dp.Markers()[0].Epoch
	time.Sleep(5 * time.Millisecond)
	e.console.AddTask(purgeTask("t1", time.Now(), urlTarget("site-a", "/x")), false) // redelivered
	waitResults(t, e.console, 2)
	if got := e.dp.Markers()[0].Epoch; got != first {
		t.Fatalf("redelivered task moved the epoch %d -> %d", first, got)
	}
	e.console.AddTask(purgeTask("t0", time.Now().Add(-time.Hour), urlTarget("site-a", "/x")), false)
	waitResults(t, e.console, 3)
	if got := e.dp.Markers()[0].Epoch; got <= first {
		t.Fatalf("later task with an older created_at got epoch %d <= %d", got, first)
	}
	var stored struct {
		Tasks map[string]int64 `json:"tasks"`
	}
	raw, _ := os.ReadFile(filepath.Join(e.h.stateDir, "purge.json"))
	if err := json.Unmarshal(raw, &stored); err != nil || stored.Tasks["t1"] != first {
		t.Fatalf("task epochs not persisted: %s", raw)
	}
}

// TestAgentInstallsSiteLevelFallbackWhenTheFullSetFails (N-H3): when the
// full marker set cannot be installed after a restart, a site-level marker
// per affected site is installed instead, so the fresh data plane never
// serves purged objects, and the sites are served.
func TestAgentInstallsSiteLevelFallbackWhenTheFullSetFails(t *testing.T) {
	e := startEnrolled(t, "fbf", nil, demoSite("site-a", "site-a.test"))
	e.console.AddTask(purgeTask("t1", time.Now(), urlTarget("site-a", "/1"), urlTarget("site-a", "/2")), false)
	waitResults(t, e.console, 1)
	epoch := e.dp.Markers()[0].Epoch
	e.dp.FailNextPurges(1) // the full set fails once
	e.dp.Restart()
	want := []dataplane.PurgeMarker{{SiteID: "site-a", Type: "site", Epoch: epoch}}
	eventually(t, "site-level fallback and site table", func() bool {
		tb := e.dp.Table()
		return tb != nil && tb.Revision == e.rev && slices.Equal(e.dp.Markers(), want)
	})
	// The agent's own set is unchanged (only 507 collapses it for good).
	raw, _ := os.ReadFile(filepath.Join(e.h.stateDir, "purge.json"))
	if !strings.Contains(string(raw), `"/1"`) || !strings.Contains(string(raw), `"/2"`) {
		t.Fatalf("purge.json lost the URL markers: %s", raw)
	}
}
