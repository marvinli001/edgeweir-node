package agent_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/edgeweir/edgeweir-node/internal/dataplane"
	"github.com/edgeweir/edgeweir-node/internal/enroll"
	nodev1 "github.com/edgeweir/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/edgeweir/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/edgeweir/edgeweir-node/internal/testutil/fakedataplane"
)

func s3Site(id, domain, credentialID string, version uint64) *nodev1.Site {
	s := demoSite(id, domain)
	s.OriginPool.Origins = []*nodev1.Origin{{
		Id: "s3-" + id, Address: "minio", Port: 9000, Scheme: nodev1.OriginScheme_ORIGIN_SCHEME_HTTP, Weight: 1,
		S3: &nodev1.S3Auth{Region: "us-east-1", Bucket: "media", CredentialId: credentialID, CredentialVersion: version},
	}}
	return s
}

// edgeListener imitates the node's own edge listener for prefetch tasks.
type edgeListener struct {
	mu       sync.Mutex
	requests []string
}

func (e *edgeListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	e.requests = append(e.requests, r.Host+" "+r.URL.RequestURI())
	e.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, "/missing") {
		http.NotFound(w, r)
		return
	}
	_, _ = w.Write([]byte("cached body"))
}

func (e *edgeListener) seen() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.requests)
}

func TestAgentCredentialsTasksAndHealth(t *testing.T) {
	console, err := fakeconsole.New(fakeconsole.Options{
		NodeID: "node-m2", ClusterID: "cl-m2", NodeName: "edge-m2",
		ReportInterval: 1, KeepaliveInterval: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	root := t.TempDir()
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}

	// The prefetch target: a listener whose port the configuration uses.
	edge := &edgeListener{}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	edgeSrv := httptest.NewUnstartedServer(edge)
	edgeSrv.Listener = ln
	edgeSrv.Start()
	t.Cleanup(edgeSrv.Close)
	port := uint32(ln.Addr().(*net.TCPAddr).Port)
	config := func(sites ...*nodev1.Site) *nodev1.NodeConfig {
		c := baseConfig(sites...)
		c.Listeners[0].Port = port
		return c
	}

	console.SetCredential(&nodev1.OriginCredential{Id: "cred-1", Version: 1, AccessKeyId: "AKID1", SecretAccessKey: "secret-1"})
	rev1 := console.Publish(config(demoSite("site-a", "a.test"), s3Site("site-s3", "s3.test", "cred-1", 1)))
	dp := fakedataplane.Start(t)
	eng := newFakeEngine()
	cfg := h.agentConfig(dp.Socket)
	cfg.TaskPollInterval = time.Hour // tasks must arrive via the watch event or the heartbeat
	startAgent(t, cfg, eng, dataplane.NewClient(dp.Socket))

	console.AddToken("m2-token")
	if _, err := enroll.Run(context.Background(), enroll.Options{
		ServerURL: srv.URL, Token: "m2-token", CASHA256: console.CA.Pin(),
		StateDir: h.stateDir, Logger: testLogger(t),
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "revision 1 applied", statusWith(console, rev1, nodev1.ApplyState_APPLY_STATE_APPLIED))

	// S3 credentials are fetched over mTLS, attached to the site table and
	// kept (0600) for restarts while the console is unreachable.
	var s3Origin *struct{ key, secret string }
	for _, s := range dp.Table().Sites {
		if s.ID == "site-s3" && s.Origins[0].S3 != nil {
			s3Origin = &struct{ key, secret string }{s.Origins[0].S3.AccessKey, s.Origins[0].S3.SecretKey}
		}
	}
	if s3Origin == nil || s3Origin.key != "AKID1" || s3Origin.secret != "secret-1" {
		t.Fatalf("S3 origin in the site table = %+v", s3Origin)
	}
	if reqs := console.CredentialRequests(); len(reqs) != 1 || !slices.Equal(reqs[0], []string{"cred-1"}) {
		t.Fatalf("credential requests = %v", reqs)
	}
	credFile := filepath.Join(h.stateDir, "credentials.json")
	if st, err := os.Stat(credFile); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("credentials file: %v %v", st, err)
	}

	// A credential the console does not hand out: the origin is dropped,
	// the site skipped and the reason reported.
	rev2 := console.Publish(config(demoSite("site-a", "a.test"), s3Site("site-s3", "s3.test", "cred-1", 1), s3Site("site-x", "x.test", "cred-2", 1)))
	eventually(t, "revision 2 applied", statusWith(console, rev2, nodev1.ApplyState_APPLY_STATE_APPLIED))
	if msg := console.LastStatus().GetMessage(); !strings.Contains(msg, "S3 credential cred-2 (version 1) unavailable") {
		t.Fatalf("status message = %q", msg)
	}
	for _, s := range dp.Table().Sites {
		if s.ID == "site-x" {
			t.Fatal("site without a usable credential was pushed")
		}
	}

	// A purge task announced on the watch stream. Its marker time is the
	// node's clock when it first applies the task, not created_at.
	created := time.Now().Add(24 * time.Hour)
	appliedFrom := time.Now().UnixMilli()
	console.AddTask(&nodev1.NodeTask{
		Id: "task-purge", CreatedAt: timestamppb.New(created),
		Kind: &nodev1.NodeTask_Purge{Purge: &nodev1.PurgeTask{Targets: []*nodev1.PurgeTarget{
			{SiteId: "site-a", Type: nodev1.PurgeType_PURGE_TYPE_URL, Host: "A.test", Path: "/img/1.png", Query: "v=2"},
			{SiteId: "site-a", Type: nodev1.PurgeType_PURGE_TYPE_PREFIX, Host: "a.test", Path: "/static/"},
			{SiteId: "site-s3", Type: nodev1.PurgeType_PURGE_TYPE_SITE},
			{SiteId: "site-a", Type: nodev1.PurgeType_PURGE_TYPE_UNSPECIFIED},
		}}},
	}, false)
	eventually(t, "purge result", func() bool { return len(console.TaskResults()) == 1 })
	res := console.TaskResults()[0]
	if res.GetTaskId() != "task-purge" || res.GetSucceeded() != 3 || res.GetFailed() != 1 || res.GetState() != nodev1.TaskState_TASK_STATE_FAILED {
		t.Fatalf("purge result = %v", res)
	}
	markers := dp.Markers()
	epoch := markers[0].Epoch
	if epoch < appliedFrom || epoch > time.Now().UnixMilli() {
		t.Fatalf("marker epoch %d is not the node's time of the purge [%d, now] (created_at %d)", epoch, appliedFrom, created.UnixMilli())
	}
	want := []dataplane.PurgeMarker{
		{SiteID: "site-a", Type: "prefix", Host: "a.test", Path: "/static/", Epoch: epoch},
		{SiteID: "site-a", Type: "url", Host: "a.test", Path: "/img/1.png", Query: "v=2", Epoch: epoch},
		{SiteID: "site-s3", Type: "site", Epoch: epoch},
	}
	if !slices.Equal(markers, want) {
		t.Fatalf("markers = %+v\nwant %+v", markers, want)
	}
	raw, err := os.ReadFile(filepath.Join(h.stateDir, "purge.json"))
	if err != nil || !json.Valid(raw) || !strings.Contains(string(raw), `"/static/"`) {
		t.Fatalf("persisted markers: %s %v", raw, err)
	}

	// A prefetch task found through the heartbeat (no watch event).
	console.AddTask(&nodev1.NodeTask{
		Id: "task-prefetch", CreatedAt: timestamppb.Now(),
		Kind: &nodev1.NodeTask_Prefetch{Prefetch: &nodev1.PrefetchTask{Targets: []*nodev1.PrefetchTarget{
			{SiteId: "site-a", Url: "http://a.test/ok.js?v=1"},
			{SiteId: "site-a", Url: "http://a.test/missing"},
			{SiteId: "site-a", Url: "https://a.test/secure"},
		}}},
	}, true)
	eventually(t, "prefetch result", func() bool { return len(console.TaskResults()) == 2 })
	res = console.TaskResults()[1]
	if res.GetSucceeded() != 1 || res.GetFailed() != 2 || res.GetState() != nodev1.TaskState_TASK_STATE_FAILED ||
		!strings.Contains(res.GetMessage(), "http://a.test/missing: HTTP 404") ||
		!strings.Contains(res.GetMessage(), "https://a.test/secure: HTTPS prefetch needs an HTTPS listener") {
		t.Fatalf("prefetch result = %v", res)
	}
	seen := edge.seen()
	slices.Sort(seen)
	if !slices.Equal(seen, []string{"a.test /missing", "a.test /ok.js?v=1"}) {
		t.Fatalf("edge listener saw %v", seen)
	}

	// Passive origin health rides on the heartbeat.
	dp.SetOriginHealth(dataplane.OriginHealth{
		SiteID: "site-a", OriginID: "o1", Healthy: false, Failures: 3,
		LastFailureAt: 1790000000.5, DownUntil: 1790000030, LastError: "timeout or HTTP 504",
	})
	eventually(t, "origin health reported", func() bool {
		s := console.LastStatus()
		return s != nil && len(s.GetOriginHealth()) == 1
	})
	oh := console.LastStatus().GetOriginHealth()[0]
	if oh.GetOriginId() != "o1" || oh.GetHealthy() || oh.GetConsecutiveFailures() != 3 ||
		oh.GetLastError() != "timeout or HTTP 504" || oh.GetLastFailureAt().AsTime().UnixMilli() != 1790000000500 ||
		oh.GetDownUntil().AsTime().Unix() != 1790000030 {
		t.Fatalf("origin health = %v", oh)
	}

	// After an nginx restart the markers are installed again, before the
	// site table.
	before := len(dp.Events())
	dp.Restart()
	eventually(t, "resync after restart", func() bool { return len(dp.Events()) >= before+2 && dp.Table() != nil })
	events := dp.Events()[before:]
	if events[0] != "purge:PUT" || events[1] != "sites" {
		t.Fatalf("resync order = %v, want purge markers before sites", events)
	}
	if !slices.Equal(dp.Markers(), want) {
		t.Fatalf("markers after restart = %+v", dp.Markers())
	}
}

// TestAgentServesStoredCredentialsOffline restarts the agent without a
// reachable console: the last-known-good configuration keeps its S3 origin
// thanks to the stored credential.
func TestAgentServesStoredCredentialsOffline(t *testing.T) {
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-o", ClusterID: "cl-o", ReportInterval: 1, KeepaliveInterval: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	root := t.TempDir()
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}
	console.SetCredential(&nodev1.OriginCredential{Id: "cred-o", Version: 3, AccessKeyId: "AKIDO", SecretAccessKey: "offline-secret"})
	rev := console.Publish(baseConfig(s3Site("site-o", "o.test", "cred-o", 3)))
	dp := fakedataplane.Start(t)
	stop := startAgent(t, h.agentConfig(dp.Socket), newFakeEngine(), dataplane.NewClient(dp.Socket))
	console.AddToken("o-token")
	if _, err := enroll.Run(context.Background(), enroll.Options{
		ServerURL: srv.URL, Token: "o-token", CASHA256: console.CA.Pin(), StateDir: h.stateDir, Logger: testLogger(t),
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	stop()
	console.Close()
	srv.Close()

	dp2 := fakedataplane.Start(t)
	startAgent(t, h.agentConfig(dp2.Socket), newFakeEngine(), dataplane.NewClient(dp2.Socket))
	eventually(t, "last-known-good served with the stored credential", func() bool {
		tb := dp2.Table()
		return tb != nil && tb.Revision == rev && len(tb.Sites) == 1 && tb.Sites[0].Origins[0].S3 != nil &&
			tb.Sites[0].Origins[0].S3.SecretKey == "offline-secret"
	})
}
