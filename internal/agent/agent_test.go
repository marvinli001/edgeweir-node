package agent_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/edgeweir/edgeweir-node/internal/agent"
	"github.com/edgeweir/edgeweir-node/internal/configstore"
	"github.com/edgeweir/edgeweir-node/internal/dataplane"
	"github.com/edgeweir/edgeweir-node/internal/enroll"
	nodev1 "github.com/edgeweir/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/edgeweir/edgeweir-node/internal/gen/edgeweir/node/v1/nodev1connect"
	"github.com/edgeweir/edgeweir-node/internal/identity"
	"github.com/edgeweir/edgeweir-node/internal/render"
	"github.com/edgeweir/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/edgeweir/edgeweir-node/internal/testutil/fakedataplane"
)

// fakeEngine records configuration tests and reloads instead of running
// OpenResty.
type fakeEngine struct {
	mu      sync.Mutex
	tests   int
	reloads int
	running bool
	conf    string
	started chan struct{}
}

func newFakeEngine() *fakeEngine { return &fakeEngine{started: make(chan struct{}, 1)} }

func (e *fakeEngine) Run(ctx context.Context) error { <-ctx.Done(); return nil }
func (e *fakeEngine) Version(context.Context) (string, error) {
	return "1.31.1.1", nil
}

func (e *fakeEngine) Test(_ context.Context, conf string) error {
	b, err := os.ReadFile(conf)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tests++
	e.conf = string(b)
	return nil
}

func (e *fakeEngine) Reload(context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.reloads++
	if !e.running {
		e.running = true
		select {
		case e.started <- struct{}{}:
		default:
		}
	}
	return nil
}

func (e *fakeEngine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

func (e *fakeEngine) Started() <-chan struct{} { return e.started }

func (e *fakeEngine) counts() (tests, reloads int, conf string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.tests, e.reloads, e.conf
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func testLogger(t *testing.T) *slog.Logger {
	if testing.Verbose() {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func demoSite(id, domain string) *nodev1.Site {
	return &nodev1.Site{
		Id:      id,
		Name:    id,
		Enabled: true,
		Domains: []*nodev1.Domain{{Name: domain}},
		OriginPool: &nodev1.OriginPool{
			Id:     "pool-" + id,
			Policy: nodev1.LoadBalancePolicy_LOAD_BALANCE_POLICY_WEIGHTED_RANDOM,
			Origins: []*nodev1.Origin{{
				Id: "o1", Address: "whoami", Port: 80, Scheme: nodev1.OriginScheme_ORIGIN_SCHEME_HTTP, Weight: 1,
			}},
		},
		CacheRules: []*nodev1.CacheRule{{
			Id: "r1", Priority: 1,
			Match:              &nodev1.CacheRuleMatch{PathPrefixes: []string{"/"}},
			Action:             nodev1.CacheAction_CACHE_ACTION_CACHE,
			EdgeTtlSeconds:     60,
			OriginCacheControl: nodev1.OriginCacheControl_ORIGIN_CACHE_CONTROL_OVERRIDE,
		}},
		CacheZone:       "default",
		CacheGeneration: 1,
	}
}

func baseConfig(sites ...*nodev1.Site) *nodev1.NodeConfig {
	return &nodev1.NodeConfig{
		Listeners:  []*nodev1.Listener{{Port: 80, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTP}},
		CacheZones: []*nodev1.CacheZone{{Name: "default", MaxSizeMb: 256, KeysZoneMb: 8, InactiveSeconds: 600}},
		Sites:      sites,
	}
}

type harness struct {
	t        *testing.T
	console  *fakeconsole.Console
	url      string
	stateDir string
	root     string
}

func (h *harness) agentConfig(controlSocket string) agent.Config {
	return agent.Config{
		StateDir: h.stateDir,
		ConfPath: filepath.Join(h.root, "nginx", "conf", "nginx.conf"),
		Render: render.Params{
			Prefix:        filepath.Join(h.root, "nginx"),
			LuaDir:        "/usr/share/edgeweir-node/lua",
			CacheDir:      filepath.Join(h.root, "cache"),
			ControlSocket: controlSocket,
			OriginSocket:  filepath.Join(h.root, "origin.sock"),
			Resolvers:     []string{"127.0.0.11"},
		},
		DefaultPort:        80,
		EnrollPollInterval: 50 * time.Millisecond,
		PollInterval:       time.Hour, // updates in this test must arrive via WatchConfig
		ReportInterval:     time.Second,
		StatsInterval:      100 * time.Millisecond,
		DataPlaneInterval:  100 * time.Millisecond,
		WatchIdleTimeout:   3 * time.Second,
		WatchBackoffMin:    50 * time.Millisecond,
		WatchBackoffMax:    200 * time.Millisecond,
		PushTimeout:        3 * time.Second,
	}
}

func startAgent(t *testing.T, cfg agent.Config, eng agent.Engine, dp agent.DataPlane) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	a := agent.New(cfg, eng, dp, testLogger(t))
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("agent.Run: %v", err)
				}
			case <-time.After(15 * time.Second):
				t.Error("agent did not stop")
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

func statusWith(c *fakeconsole.Console, rev uint64, state nodev1.ApplyState) func() bool {
	return func() bool {
		s := c.LastStatus()
		return s != nil && s.GetAppliedRevision() == rev && s.GetState() == state
	}
}

func TestAgentEndToEnd(t *testing.T) {
	console, err := fakeconsole.New(fakeconsole.Options{
		NodeID: "node-7", ClusterID: "cl-1", NodeName: "edge-7",
		ReportInterval: 1, KeepaliveInterval: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	root := t.TempDir()
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}

	rev1 := console.Publish(baseConfig(demoSite("site-a", "a.test")))
	dp := fakedataplane.Start(t)
	eng := newFakeEngine()
	stop := startAgent(t, h.agentConfig(dp.Socket), eng, dataplane.NewClient(dp.Socket))

	// Before enrollment the node already serves the bootstrap config
	// (404 for every host) so the container is healthy right away.
	eventually(t, "bootstrap site table", func() bool {
		tb := dp.Table()
		return tb != nil && tb.Revision == 0 && len(tb.Sites) == 0
	})
	if _, reloads, conf := eng.counts(); reloads != 1 || !strings.Contains(conf, "listen 80 default_server;") {
		t.Fatalf("bootstrap: reloads=%d conf=%q", reloads, conf)
	}

	// Enroll while `run` is already running (as `docker compose exec` does).
	console.AddToken("secret-token")
	if _, err := enroll.Run(context.Background(), enroll.Options{
		ServerURL: srv.URL, Token: "secret-token", CASHA256: console.CA.Pin(),
		StateDir: h.stateDir, Logger: testLogger(t),
	}); err != nil {
		t.Fatal(err)
	}

	// Snapshot of revision 1 applied and reported.
	eventually(t, "revision 1 applied and reported", statusWith(console, rev1, nodev1.ApplyState_APPLY_STATE_APPLIED))
	tb := dp.Table()
	if tb.Revision != rev1 || len(tb.Sites) != 1 || tb.Sites[0].Domains[0].Name != "a.test" {
		t.Fatalf("data plane table = %+v", tb)
	}
	// The table carries this node's CDN-Loop id (RFC 8586).
	if tb.CDNID != dataplane.CDNID("node-7") || tb.CDNID == "" {
		t.Fatalf("site table cdn_id = %q, want %q", tb.CDNID, dataplane.CDNID("node-7"))
	}
	calls := console.GetConfigCalls()
	if len(calls) == 0 || !calls[0].Snapshot || calls[0].Request.GetBaseRevision() != 0 {
		t.Fatalf("first GetConfig = %+v, want snapshot with base 0", calls)
	}
	st := console.LastStatus()
	if st.GetInfo().GetEngine() != "openresty" || st.GetInfo().GetEngineVersion() != "1.31.1.1" ||
		st.GetInfo().GetHostname() == "" || st.GetCertificateNotAfter() == nil || st.GetAppliedAt() == nil ||
		st.GetAppliedContentHash() == "" || !st.GetDataPlaneHealthy() {
		t.Fatalf("status report incomplete: %v", st)
	}
	_, reloadsAfter1, _ := eng.counts()

	// Revision 2 changes sites only: delivered as a diff, hot-updated,
	// no nginx reload.
	rev2 := console.Publish(baseConfig(demoSite("site-a", "a.test"), demoSite("site-b", "b.test")))
	eventually(t, "revision 2 applied", statusWith(console, rev2, nodev1.ApplyState_APPLY_STATE_APPLIED))
	if tb := dp.Table(); tb.Revision != rev2 || len(tb.Sites) != 2 {
		t.Fatalf("data plane table after rev 2 = %+v", tb)
	}
	if !hasCall(console.GetConfigCalls(), func(c fakeconsole.GetConfigCall) bool {
		return !c.Snapshot && c.Request.GetBaseRevision() == rev1 && c.Revision == rev2
	}) {
		t.Fatalf("revision 2 was not fetched as a diff against revision 1: %+v", console.GetConfigCalls())
	}
	if _, reloads, _ := eng.counts(); reloads != reloadsAfter1 {
		t.Fatalf("site-only change reloaded nginx (%d -> %d)", reloadsAfter1, reloads)
	}

	// Revision 3 adds a listener (structural: reload) and its diff carries
	// a wrong hash: the agent must fall back to a full snapshot.
	console.CorruptNextDiff()
	cfg3 := baseConfig(demoSite("site-a", "a.test"), demoSite("site-b", "b.test"))
	cfg3.Listeners = append(cfg3.Listeners, &nodev1.Listener{Port: 8080, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTP})
	rev3 := console.Publish(cfg3)
	eventually(t, "revision 3 applied", statusWith(console, rev3, nodev1.ApplyState_APPLY_STATE_APPLIED))
	calls = console.GetConfigCalls()
	if !hasCall(calls, func(c fakeconsole.GetConfigCall) bool {
		return !c.Snapshot && c.Request.GetBaseRevision() == rev2 && c.Revision == rev3
	}) || !hasCall(calls, func(c fakeconsole.GetConfigCall) bool {
		return c.Snapshot && c.Request.GetBaseRevision() == 0 && c.Revision == rev3
	}) {
		t.Fatalf("expected corrupted diff followed by snapshot fallback: %+v", calls)
	}
	if _, reloads, conf := eng.counts(); reloads != reloadsAfter1+1 || !strings.Contains(conf, "listen 8080 default_server;") {
		t.Fatalf("structural change: reloads %d -> %d, conf has 8080: %v", reloadsAfter1, reloads, strings.Contains(conf, "8080"))
	}

	// Revision 4 uses a rule expression: rejected, LKG keeps serving.
	cfg4 := baseConfig(demoSite("site-a", "a.test"))
	cfg4.Sites[0].CacheRules[0].Match.Expression = `http.host eq "a.test"`
	console.Publish(cfg4)
	eventually(t, "revision 4 rejected", statusWith(console, rev3, nodev1.ApplyState_APPLY_STATE_FAILED))
	if msg := console.LastStatus().GetMessage(); !strings.Contains(msg, "expression") {
		t.Fatalf("failure message = %q", msg)
	}
	if tb := dp.Table(); tb.Revision != rev3 {
		t.Fatalf("data plane moved away from LKG: %+v", tb)
	}
	lkg, _, err := configstore.Store{Dir: filepath.Join(h.stateDir, identity.ConfigDir)}.Load()
	if err != nil || lkg.GetRevision() != rev3 {
		t.Fatalf("persisted LKG = %v, %v; want revision %d", lkg.GetRevision(), err, rev3)
	}

	// nginx restarted: shared dicts are empty, the agent re-pushes.
	pushes := len(dp.Pushes())
	dp.Restart()
	eventually(t, "site table re-pushed after data plane restart", func() bool {
		tb := dp.Table()
		return tb != nil && tb.Revision == rev3 && len(dp.Pushes()) > pushes
	})

	// Per-minute stats are drained and uploaded.
	dp.AddStats(dataplane.MinuteStats{Minute: 1790000040, SiteID: "site-a", Requests: 2, BytesSent: 512,
		CacheHits: 1, CacheMisses: 1, StatusCodes: map[string]uint64{"200": 2}})
	eventually(t, "stats uploaded", func() bool {
		for _, s := range console.Stats() {
			if s.GetSiteId() == "site-a" && s.GetStatusCodes()[200] == 2 && s.GetMinute().AsTime().Unix() == 1790000040 {
				return true
			}
		}
		return false
	})

	// The console asks for a certificate renewal: new key pair on disk and
	// the channel keeps working with the new certificate.
	before, err := identity.Store{Dir: h.stateDir}.Load()
	if err != nil {
		t.Fatal(err)
	}
	console.RequestRenewal()
	eventually(t, "certificate renewed", func() bool {
		_, renewals, _, _ := console.Counters()
		return renewals == 1
	})
	eventually(t, "renewed certificate installed", func() bool {
		after, err := identity.Store{Dir: h.stateDir}.Load()
		return err == nil && after.Certificate.SerialNumber.Cmp(before.Certificate.SerialNumber) != 0
	})
	n := len(console.Statuses())
	eventually(t, "reports continue after renewal", func() bool { return len(console.Statuses()) > n+1 })

	// Every RPC except Enroll went over mTLS with CN = node id.
	enrollments, _, watches, mtls := console.Counters()
	if enrollments != 1 || watches < 1 {
		t.Fatalf("enrollments=%d watch streams=%d", enrollments, watches)
	}
	for _, p := range []string{
		nodev1connect.NodeServiceGetConfigProcedure, nodev1connect.NodeServiceReportStatusProcedure,
		nodev1connect.NodeServiceWatchConfigProcedure, nodev1connect.NodeServiceReportStatsProcedure,
		nodev1connect.NodeServiceRenewCertificateProcedure,
	} {
		if mtls[p] == 0 {
			t.Errorf("no authenticated call to %s: %v", p, mtls)
		}
	}
	if mtls[nodev1connect.NodeServiceEnrollProcedure] != 0 {
		t.Error("Enroll must not require a client certificate")
	}

	// Restart with the console gone: the LKG is served immediately.
	stop()
	console.Close()
	srv.CloseClientConnections()
	srv.Close()
	dp2 := fakedataplane.Start(t)
	startAgent(t, h.agentConfig(dp2.Socket), newFakeEngine(), dataplane.NewClient(dp2.Socket))
	eventually(t, "LKG served after restart without console", func() bool {
		tb := dp2.Table()
		return tb != nil && tb.Revision == rev3 && len(tb.Sites) == 2
	})
	// Before the mTLS channel is up the cdn-id comes from identity.json.
	if got := dp2.Table().CDNID; got != dataplane.CDNID("node-7") {
		t.Fatalf("cdn_id of the last-known-good table = %q", got)
	}
}

func hasCall(calls []fakeconsole.GetConfigCall, pred func(fakeconsole.GetConfigCall) bool) bool {
	for _, c := range calls {
		if pred(c) {
			return true
		}
	}
	return false
}
