package agent_test

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/probe"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

// A node probes the other nodes with its own certificate while the
// heartbeat answer says so, never itself, and stops when the flag turns
// off.
func TestNodeProbesWhileAllowed(t *testing.T) {
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-p", ReportInterval: 1, KeepaliveInterval: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	root := t.TempDir()
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}
	rev := console.Publish(baseConfig(demoSite("site-a", "a.test")))
	dp := fakedataplane.Start(t)
	startAgent(t, h.agentConfig(dp.Socket), newFakeEngine(), dataplane.NewClient(dp.Socket))
	console.AddToken("tok")
	if _, err := enroll.Run(context.Background(), enroll.Options{ServerURL: srv.URL, Token: "tok", CASHA256: console.CA.Pin(), StateDir: h.stateDir, Logger: testLogger(t)}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "revision applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))

	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == probe.HealthPath && r.Host == probe.HealthHost {
			_, _ = io.WriteString(w, "ok")
			return
		}
		http.NotFound(w, r)
	}))
	defer health.Close()
	host, p, _ := net.SplitHostPort(strings.TrimPrefix(health.URL, "http://"))
	port, _ := strconv.Atoi(p)
	console.SetProbeTargets(&nodev1.GetProbeTargetsResponse{Targets: []*nodev1.ProbeTarget{
		{NodeId: "node-other", Address: host, Port: uint32(port), Method: nodev1.ProbeMethod_PROBE_METHOD_HTTP},
		{NodeId: "node-p", Address: host, Port: uint32(port), Method: nodev1.ProbeMethod_PROBE_METHOD_HTTP},
	}})
	time.Sleep(1500 * time.Millisecond) // heartbeats without the flag start nothing
	if calls := console.ProbeTargetCalls(); len(calls) != 0 {
		t.Fatalf("probed without the console's permission: %+v", calls)
	}

	console.SetNodeProbe(true)
	eventually(t, "a probe round of the node", func() bool { return len(console.ProbeReports()) == 1 })
	rep := console.ProbeReports()[0]
	if rep.Caller != "node-p" {
		t.Fatalf("round reported by %q, want the node certificate", rep.Caller)
	}
	res := rep.Request.GetResults()
	if len(res) != 1 || res[0].GetNodeId() != "node-other" || res[0].GetSent() != 3 || res[0].GetLost() != 0 {
		t.Fatalf("results %v, want node-other only (never the node itself)", res)
	}
	if info := console.ProbeTargetCalls()[0].Info; info.GetHostname() == "" || info.GetAgentVersion() == "" {
		t.Fatalf("ProbeInfo %v", info)
	}

	// Off: the loop stops. On again: a new loop starts with a round at
	// once (the old one would wait for the 10 s interval).
	console.SetNodeProbe(false)
	seen := len(console.Statuses())
	eventually(t, "two heartbeats after the flag turned off", func() bool { return len(console.Statuses()) >= seen+2 })
	calls := len(console.ProbeTargetCalls())
	console.SetNodeProbe(true)
	deadline := time.Now().Add(4 * time.Second)
	for len(console.ProbeTargetCalls()) == calls {
		if time.Now().After(deadline) {
			t.Fatal("no new probe round after the flag turned on again: the loop did not stop and restart")
		}
		time.Sleep(20 * time.Millisecond)
	}
	eventually(t, "second round reported", func() bool { return len(console.ProbeReports()) == 2 })
}
