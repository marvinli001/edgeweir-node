package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/diag"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

// line is the output line of the named check.
func line(out, name string) string {
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) > 1 && strings.HasPrefix(strings.TrimSpace(l[5:]), name) {
			return l
		}
	}
	return ""
}

// TestDiagnoseCommand: diagnose checks the identity, the console (and the
// clock against it), the agent's diagnostics socket and the data plane.
func TestDiagnoseCommand(t *testing.T) {
	sockets, err := os.MkdirTemp("", "ewd")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockets)
	diagSock := filepath.Join(sockets, "diag.sock")
	dir := filepath.Join(t.TempDir(), "state")
	dp := fakedataplane.Start(t)
	flags := []string{"--state-dir", dir, "--control-socket", dp.Socket, "--diag-socket", diagSock, "--timeout", "5s"}

	var out, errOut bytes.Buffer
	if code := realMain(append([]string{"diagnose"}, flags...), &out, &errOut); code != 1 ||
		!strings.HasPrefix(line(out.String(), "identity"), "fail") || !strings.Contains(out.String(), "not enrolled") ||
		!strings.HasPrefix(line(out.String(), "console"), "skip") || !strings.HasPrefix(line(out.String(), "agent"), "fail") ||
		!strings.HasPrefix(line(out.String(), "data plane"), "fail") {
		t.Fatalf("not enrolled: code=%d stdout=%s stderr=%s", code, out.String(), errOut.String())
	}

	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-diag", ClusterID: "cl-diag", NodeName: "edge-diag"})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	console.AddToken("diag-token")
	if _, err := enroll.Run(context.Background(), enroll.Options{ServerURL: "https://127.0.0.1:" + port, Token: "diag-token", CASHA256: console.CA.Pin(), StateDir: dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := dataplane.NewClient(dp.Socket).PutSites(context.Background(), &dataplane.SiteTable{Revision: 7}); err != nil {
		t.Fatal(err)
	}
	status := diag.Status{
		Version: "v1.5.0", NodeID: "node-diag",
		Report: diag.Report{LastOK: time.Now(), IntervalSeconds: 15},
		Config: diag.Config{AppliedRevision: 7, LatestRevision: 7, State: "applied", DataPlaneHealthy: true},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	statusOf := make(chan diag.Status, 1)
	statusOf <- status
	current := func() diag.Status { s := <-statusOf; statusOf <- s; return s }
	if err := diag.Serve(ctx, diagSock, current, slog.Default()); err != nil {
		t.Fatal(err)
	}
	setStatus := func(s diag.Status) { <-statusOf; statusOf <- s }

	out.Reset()
	if code := realMain(append([]string{"diagnose"}, flags...), &out, &errOut); code != 0 {
		t.Fatalf("healthy: code=%d stdout=%s stderr=%s", code, out.String(), errOut.String())
	}
	for name, want := range map[string]string{
		"identity":      "node node-diag (edge-diag), cluster cl-diag",
		"certificate":   "valid until",
		"console":       "https://127.0.0.1:" + port + " answered in",
		"agent":         "edgeweir-node v1.5.0, last report",
		"configuration": "revision 7 applied",
		"data plane":    "revision 7, 0 sites",
		"clock":         "the console",
	} {
		if l := line(out.String(), name); !strings.HasPrefix(l, "ok") || !strings.Contains(l, want) {
			t.Errorf("%s: %q, want ok with %q", name, l, want)
		}
	}

	// The console's clock is 45 s ahead: the node is behind and fails the clock check.
	console.SetClock(45 * time.Second)
	stale := status
	stale.Report.LastOK = time.Now().Add(-time.Hour)
	stale.Report.LastError, stale.Report.LastErrorAt = "unavailable: connection refused", time.Now()
	stale.Config.State, stale.Config.Message = "failed", "nginx -t failed"
	setStatus(stale)
	out.Reset()
	if code := realMain(append([]string{"diagnose", "--json"}, flags...), &out, &errOut); code != 1 {
		t.Fatalf("failing: code=%d stdout=%s", code, out.String())
	}
	var got struct {
		Checks []checkResult `json:"checks"`
		Agent  *diag.Status  `json:"agent"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || got.Agent == nil || got.Agent.NodeID != "node-diag" {
		t.Fatalf("json: %v %s", err, out.String())
	}
	results := map[string]checkResult{}
	for _, c := range got.Checks {
		results[c.Name] = c
	}
	if c := results["clock"]; c.Result != checkFail || !strings.Contains(c.Detail, "behind the console") || !strings.Contains(c.Detail, "NTP") {
		t.Errorf("clock = %+v", c)
	}
	if c := results["agent"]; c.Result != checkFail || !strings.Contains(c.Detail, "connection refused") {
		t.Errorf("agent = %+v", c)
	}
	if c := results["configuration"]; c.Result != checkFail || !strings.Contains(c.Detail, "nginx -t failed") {
		t.Errorf("configuration = %+v", c)
	}

	// pprof writes a profile from the socket, never binary to a terminal.
	file := filepath.Join(t.TempDir(), "heap.pb.gz")
	if code := realMain([]string{"pprof", "heap", "--diag-socket", diagSock, "--output", file}, &out, &errOut); code != 0 {
		t.Fatalf("pprof heap: code=%d stderr=%s", code, errOut.String())
	}
	if b, err := os.ReadFile(file); err != nil || len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
		t.Fatalf("heap profile: %d bytes, %v", len(b), err)
	}
	errOut.Reset()
	if code := realMain([]string{"pprof", "--diag-socket", diagSock}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "PROFILE is one of") {
		t.Fatalf("no profile: code=%d stderr=%s", code, errOut.String())
	}
}
