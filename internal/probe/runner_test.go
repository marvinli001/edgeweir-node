package probe_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/marvinli001/edgeweir-node/internal/controlplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1/nodev1connect"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/pki"
	"github.com/marvinli001/edgeweir-node/internal/probe"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

func testLogger() *slog.Logger {
	if testing.Verbose() {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// healthServer answers GET /.edgeweir/health like a node.
func healthServer(t *testing.T) (host string, port uint32) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != probe.HealthPath || r.Host != probe.HealthHost {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	h, p, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	n, _ := strconv.Atoi(p)
	return h, uint32(n)
}

func closedPort(t *testing.T) uint32 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return uint32(port)
}

// enrolledProbe enrolls a probe with the fake console and opens its channel.
func enrolledProbe(t *testing.T, c *fakeconsole.Console, url string) (*controlplane.Channel, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "probe")
	c.AddProbeToken("ptok")
	if _, err := enroll.Probe(context.Background(), enroll.ProbeOptions{
		ServerURL: url, Token: "ptok", CASHA256: c.CA.Pin(), StateDir: dir, Info: probe.Info(), Logger: testLogger(),
	}); err != nil {
		t.Fatal(err)
	}
	ch, err := controlplane.NewChannel(identity.Store{Dir: dir, Probe: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ch.Close)
	return ch, dir
}

func TestSettingsFrom(t *testing.T) {
	for _, c := range []struct {
		in   *nodev1.GetProbeTargetsResponse
		want probe.Settings
	}{
		{&nodev1.GetProbeTargetsResponse{}, probe.Settings{Interval: 10 * time.Second, Timeout: 3 * time.Second, Attempts: 3}},
		{nil, probe.Settings{Interval: 10 * time.Second, Timeout: 3 * time.Second, Attempts: 3}},
		{&nodev1.GetProbeTargetsResponse{IntervalSeconds: 30, TimeoutMs: 1500, Attempts: 5}, probe.Settings{Interval: 30 * time.Second, Timeout: 1500 * time.Millisecond, Attempts: 5}},
		{&nodev1.GetProbeTargetsResponse{IntervalSeconds: 1, TimeoutMs: 10, Attempts: 99}, probe.Settings{Interval: 5 * time.Second, Timeout: 500 * time.Millisecond, Attempts: 10}},
		{&nodev1.GetProbeTargetsResponse{IntervalSeconds: 3600, TimeoutMs: 60000, Attempts: 1}, probe.Settings{Interval: 60 * time.Second, Timeout: 10 * time.Second, Attempts: 1}},
	} {
		if got := probe.SettingsFrom(c.in); got != c.want {
			t.Errorf("SettingsFrom(%v) = %+v, want %+v", c.in, got, c.want)
		}
	}
}

// One round: targets of the probing node and unsupported ones are left
// out, the others are reported in order with the response's attempts.
func TestRunnerRound(t *testing.T) {
	c, err := fakeconsole.New(fakeconsole.Options{})
	if err != nil {
		t.Fatal(err)
	}
	url := c.StartTLS(t).URL
	ch, _ := enrolledProbe(t, c, url)
	host, port := healthServer(t)
	refused := closedPort(t)
	c.SetProbeTargets(&nodev1.GetProbeTargetsResponse{
		IntervalSeconds: 7, TimeoutMs: 800, Attempts: 2,
		Targets: []*nodev1.ProbeTarget{
			{NodeId: "node-a", Address: host, Port: port, Method: nodev1.ProbeMethod_PROBE_METHOD_HTTP},
			{NodeId: "node-a", Address: host, Port: refused, Method: nodev1.ProbeMethod_PROBE_METHOD_TCP},
			{NodeId: "node-a", Address: "edge.example.com", Port: port, Method: nodev1.ProbeMethod_PROBE_METHOD_HTTP},
			{NodeId: "node-self", Address: host, Port: port, Method: nodev1.ProbeMethod_PROBE_METHOD_HTTP},
			{NodeId: "node-b", Address: host, Port: port, Method: nodev1.ProbeMethod_PROBE_METHOD_TCP},
		},
	})
	r := &probe.Runner{Client: ch.ProbeClient, Info: probe.Info(), SkipNodeID: "node-self", Log: testLogger()}
	before := time.Now()
	interval, err := r.Round(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if interval != 7*time.Second {
		t.Fatalf("interval = %v, want 7s", interval)
	}
	reports := c.ProbeReports()
	if len(reports) != 1 || reports[0].Caller != "probe-1" {
		t.Fatalf("reports = %+v", reports)
	}
	req := reports[0].Request
	if at := req.GetStartedAt().AsTime(); at.Before(before.Add(-time.Second)) || at.After(time.Now()) {
		t.Fatalf("started_at = %v", at)
	}
	got := req.GetResults()
	if len(got) != 3 {
		t.Fatalf("results = %v", got)
	}
	want := []struct {
		node   string
		port   uint32
		method nodev1.ProbeMethod
		lost   uint32
		err    string
	}{
		{"node-a", port, nodev1.ProbeMethod_PROBE_METHOD_HTTP, 0, ""},
		{"node-a", refused, nodev1.ProbeMethod_PROBE_METHOD_TCP, 2, probe.ErrRefused},
		{"node-b", port, nodev1.ProbeMethod_PROBE_METHOD_TCP, 0, ""},
	}
	for i, w := range want {
		g := got[i]
		if g.GetNodeId() != w.node || g.GetPort() != w.port || g.GetMethod() != w.method || g.GetSent() != 2 || g.GetLost() != w.lost || g.GetError() != w.err {
			t.Errorf("result %d = %v, want %+v with 2 attempts", i, g, w)
		}
		if (w.lost == 0) != (g.GetRttMs() > 0) {
			t.Errorf("result %d rtt_ms = %d", i, g.GetRttMs())
		}
	}
	calls := c.ProbeTargetCalls()
	if len(calls) != 1 || calls[0].Caller != "probe-1" || calls[0].Info.GetAgentVersion() == "" || calls[0].Info.GetHostname() == "" {
		t.Fatalf("GetProbeTargets calls = %+v", calls)
	}
}

// Failed calls back off and the loop recovers; it stops with its context.
func TestRunnerRetriesAndStops(t *testing.T) {
	c, err := fakeconsole.New(fakeconsole.Options{})
	if err != nil {
		t.Fatal(err)
	}
	url := c.StartTLS(t).URL
	ch, _ := enrolledProbe(t, c, url)
	c.FailProbeTargets(2)
	c.FailProbeReports(1)
	r := &probe.Runner{Client: ch.ProbeClient, Info: probe.Info(), Log: testLogger(), BackoffMin: 10 * time.Millisecond, BackoffMax: 40 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); r.Run(ctx) }()
	eventually(t, "a round reported after failures", func() bool { return len(c.ProbeReports()) == 1 })
	if n := len(c.ProbeTargetCalls()); n != 4 {
		t.Fatalf("GetProbeTargets calls = %d, want 4 (2 failed, 1 whose report failed, 1 reported)", n)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not stop")
	}
	// The next round waits for the interval (10s by default): nothing more.
	if n := len(c.ProbeReports()); n != 1 {
		t.Fatalf("reports = %d, want 1", n)
	}
}

// A node certificate reaches ProbeService only while the node may probe,
// a probe certificate never reaches NodeService.
func TestProbeServiceRejectsNodeCertificates(t *testing.T) {
	c, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-x"})
	if err != nil {
		t.Fatal(err)
	}
	url := c.StartTLS(t).URL
	c.AddToken("ntok")
	dir := t.TempDir()
	if _, err := enroll.Run(context.Background(), enroll.Options{ServerURL: url, Token: "ntok", CASHA256: c.CA.Pin(), StateDir: dir, Logger: testLogger()}); err != nil {
		t.Fatal(err)
	}
	node, err := controlplane.NewChannel(identity.Store{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	r := &probe.Runner{Client: node.ProbeClient, Log: testLogger()}
	if _, err := r.Round(context.Background()); !controlplane.IsAuthError(err) {
		t.Fatalf("node certificate on ProbeService while not probing: %v", err)
	}
	c.SetNodeProbe(true)
	if _, err := r.Round(context.Background()); err != nil {
		t.Fatalf("node certificate while probing: %v", err)
	}
	if reps := c.ProbeReports(); len(reps) != 1 || reps[0].Caller != "node-x" {
		t.Fatalf("reports = %+v", reps)
	}
	// A probe certificate never reaches NodeService.
	ch, _ := enrolledProbe(t, c, url)
	if _, err := ch.Client().ReportStatus(context.Background(), connect.NewRequest(&nodev1.ReportStatusRequest{})); !controlplane.IsAuthError(err) {
		t.Fatalf("probe certificate on NodeService: %v", err)
	}
}

// Main enrolls once, runs rounds, renews on request and ignores a token
// once enrolled.
func TestMainEnrollsRunsAndRenews(t *testing.T) {
	c, err := fakeconsole.New(fakeconsole.Options{ProbeID: "probe-main"})
	if err != nil {
		t.Fatal(err)
	}
	url := c.StartTLS(t).URL
	dir := filepath.Join(t.TempDir(), "edgeweir-probe")
	if err := probe.Main(context.Background(), probe.Options{StateDir: dir, Log: testLogger()}); !errors.Is(err, probe.ErrNotEnrolled) {
		t.Fatalf("Main without identity and token: %v", err)
	}
	host, port := healthServer(t)
	c.SetProbeTargets(&nodev1.GetProbeTargetsResponse{Targets: []*nodev1.ProbeTarget{
		{NodeId: "node-a", Address: host, Port: port, Method: nodev1.ProbeMethod_PROBE_METHOD_HTTP},
	}})
	c.AddProbeToken("first-run")
	c.RequestProbeRenewal()
	run := func(token string) (stop func()) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- probe.Main(ctx, probe.Options{ServerURL: url, Token: token, CASHA256: c.CA.Pin(), StateDir: dir, Log: testLogger(), Timeout: 5 * time.Second})
		}()
		return func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("Main: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("Main did not stop")
			}
		}
	}
	stop := run("first-run")
	eventually(t, "first round reported", func() bool { return len(c.ProbeReports()) >= 1 })
	eventually(t, "certificate renewed", func() bool { _, n := c.ProbeCounters(); return n == 1 })
	stop()
	store := identity.Store{Dir: dir, Probe: true}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ProbeID != "probe-main" || loaded.Certificate.Subject.CommonName != "probe-main" {
		t.Fatalf("identity %+v", loaded.Identity)
	}
	if st, err := os.Stat(store.Path(identity.ProbeKeyFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("probe.key: %v %v", st, err)
	}
	if rep := c.ProbeReports()[0]; rep.Caller != "probe-main" || len(rep.Request.GetResults()) != 1 ||
		rep.Request.GetResults()[0].GetLost() != 0 {
		t.Fatalf("report %+v", rep)
	}

	// A restart with the (used) token in the environment keeps the identity.
	reports := len(c.ProbeReports())
	stop = run("first-run")
	eventually(t, "round after restart", func() bool { return len(c.ProbeReports()) > reports })
	stop()
	if n, _ := c.ProbeCounters(); n != 1 {
		t.Fatalf("enrollments = %d, want 1", n)
	}
	after, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !after.Certificate.Equal(loaded.Certificate) {
		t.Fatal("identity changed across a restart")
	}
}

// Enrollment is retried while the console is unavailable; a CA pin
// mismatch ends it at once without sending the token.
func TestMainEnrollmentRetries(t *testing.T) {
	c, err := fakeconsole.New(fakeconsole.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := c.TLSConfig([]string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var refused atomic.Int32
	h := c.Handler()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == nodev1connect.ProbeServiceEnrollProbeProcedure && refused.Add(1) <= 2 {
			_ = connect.NewErrorWriter().Write(w, r, connect.NewError(connect.CodeUnavailable, errors.New("console starting")))
			return
		}
		h.ServeHTTP(w, r)
	}))
	srv.TLS = cfg
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	c.AddProbeToken("retry")

	other, err := fakeconsole.New(fakeconsole.Options{})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "p")
	err = probe.Main(context.Background(), probe.Options{ServerURL: srv.URL, Token: "retry", CASHA256: other.CA.Pin(), StateDir: dir, Log: testLogger()})
	if !errors.Is(err, pki.ErrPinMismatch) {
		t.Fatalf("pin mismatch: %v", err)
	}
	if refused.Load() != 0 {
		t.Fatal("token sent to a console with another CA")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- probe.Main(ctx, probe.Options{ServerURL: srv.URL, Token: "retry", CASHA256: c.CA.Pin(), StateDir: dir, Log: testLogger(),
			BackoffMin: 10 * time.Millisecond, BackoffMax: 20 * time.Millisecond})
	}()
	eventually(t, "enrolled after retries", func() bool { return (identity.Store{Dir: dir, Probe: true}).Enrolled() })
	if n := refused.Load(); n != 3 {
		t.Fatalf("EnrollProbe calls = %d, want 3", n)
	}
	eventually(t, "a round reported", func() bool { return len(c.ProbeReports()) == 1 })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// A rejected token is not retried.
	err = probe.Main(context.Background(), probe.Options{ServerURL: srv.URL, Token: "unknown", CASHA256: c.CA.Pin(), StateDir: t.TempDir(), Log: testLogger(),
		BackoffMin: 10 * time.Millisecond})
	if !controlplane.IsAuthError(err) {
		t.Fatalf("rejected token: %v", err)
	}
}
