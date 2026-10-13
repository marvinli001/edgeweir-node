package agent_test

import (
	"context"
	"net"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/controlplane"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

// TestAgentFollowsTheConsolesAddress: heartbeats report channel-follow-v1
// and the address in use; the address the console gives out is checked,
// persisted and used without a restart, and the node keeps applying
// revisions; an address the node cannot reach is reported and left alone;
// an address changed on disk (set-server) is picked up.
func TestAgentFollowsTheConsolesAddress(t *testing.T) {
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-f", ClusterID: "cl-f", ReportInterval: 1})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	enrolledAt := "https://127.0.0.1:" + port
	second := "https://localhost:" + port
	root := t.TempDir()
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}
	rev := console.Publish(baseConfig(demoSite("site-f", "f.test")))
	dp := fakedataplane.Start(t)
	startAgent(t, h.agentConfig(dp.Socket), newFakeEngine(), dataplane.NewClient(dp.Socket))
	console.AddToken("f-token")
	if _, err := enroll.Run(context.Background(), enroll.Options{
		ServerURL: enrolledAt, Token: "f-token", CASHA256: console.CA.Pin(), StateDir: h.stateDir, Logger: testLogger(t),
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "configuration applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	st := console.LastStatus()
	if !slices.Contains(st.GetInfo().GetSupportedFeatures(), controlplane.FollowFeature) {
		t.Fatalf("features = %v", st.GetInfo().GetSupportedFeatures())
	}
	if ch := st.GetChannel(); ch.GetCurrent().GetUrl() != enrolledAt || ch.GetSource() != nodev1.ChannelSource_CHANNEL_SOURCE_ENROLL || ch.GetFallback() != nil {
		t.Fatalf("channel status = %v", ch)
	}

	store := identity.Store{Dir: h.stateDir}
	reportsAt := func(url string) func() bool {
		return func() bool {
			s := console.LastStatus()
			return s.GetChannel().GetCurrent().GetUrl() == url && !s.GetChannel().GetOnFallback()
		}
	}

	// An address that does not answer: reported, nothing changes.
	console.SetChannel(&nodev1.ChannelAddress{Url: "https://127.0.0.1:1"})
	eventually(t, "failed check reported", func() bool {
		ch := console.LastStatus().GetChannel()
		return ch.GetErrorCode() == controlplane.CheckUnreachable && ch.GetFailed().GetUrl() == "https://127.0.0.1:1"
	})
	if id, _ := store.ReadIdentity(); id.ServerURL != enrolledAt {
		t.Fatalf("identity changed after a failed check: %+v", id)
	}

	// The console's second name: checked, persisted, used.
	console.SetChannel(&nodev1.ChannelAddress{Url: second})
	eventually(t, "switched to the second address", reportsAt(second))
	id, err := store.ReadIdentity()
	if err != nil || id.ServerURL != second || id.FallbackServerURL != enrolledAt || id.ServerSource != identity.ServerSourceConsole {
		t.Fatalf("identity = %+v, %v", id, err)
	}
	if st := console.LastStatus().GetChannel(); st.GetFailed() != nil || st.GetSource() != nodev1.ChannelSource_CHANNEL_SOURCE_CONSOLE {
		t.Fatalf("status after the switch = %v", st)
	}
	rev = console.Publish(baseConfig(demoSite("site-f", "f.test"), demoSite("site-g", "g.test")))
	eventually(t, "a revision applied after the switch", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))

	// set-server while the agent runs: picked up without a restart. The
	// console then still gives out its address, so the agent goes back.
	console.SetChannel(nil)
	heard := len(console.Statuses())
	eventually(t, "a heartbeat without the console's address", func() bool { return len(console.Statuses()) >= heard+2 })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := controlplane.SetServer(ctx, store, controlplane.Address{URL: enrolledAt}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "set-server picked up", reportsAt(enrolledAt))
	if st := console.LastStatus().GetChannel(); st.GetSource() != nodev1.ChannelSource_CHANNEL_SOURCE_COMMAND || st.GetFallback().GetUrl() != second {
		t.Fatalf("status after set-server = %v", st)
	}
	console.SetChannel(&nodev1.ChannelAddress{Url: second})
	eventually(t, "back on the console's address", reportsAt(second))
}
