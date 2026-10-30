package agent_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marvinli001/edgeweir-node/internal/agent"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

func decommissionTask(id string) *nodev1.NodeTask {
	return &nodev1.NodeTask{Id: id, CreatedAt: timestamppb.Now(), Kind: &nodev1.NodeTask_Decommission{Decommission: &nodev1.DecommissionTask{}}}
}

// runUntilDone runs an agent and returns the channel of Run's result.
func runUntilDone(t *testing.T, cfg agent.Config, dp *fakedataplane.Server) (<-chan error, *fakeEngine, context.CancelFunc) {
	t.Helper()
	eng := newFakeEngine()
	c := dataplane.NewClient(dp.Socket)
	eng.mu.Lock()
	eng.confPath, eng.dp = cfg.ConfPath, dp
	eng.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done, finished := make(chan error, 1), make(chan struct{})
	a := agent.New(cfg, eng, c, testLogger(t))
	go func() {
		defer close(finished)
		done <- a.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(15 * time.Second):
			t.Error("agent did not stop")
		}
	})
	return done, eng, cancel
}

func enrollWith(t *testing.T, console *fakeconsole.Console, url, dir, token string) {
	t.Helper()
	console.AddToken(token)
	if _, err := enroll.Run(context.Background(), enroll.Options{
		ServerURL: url, Token: token, CASHA256: console.CA.Pin(), StateDir: dir, Logger: testLogger(t),
	}); err != nil {
		t.Fatal(err)
	}
}

// A decommission task is reported, stops the agent with ErrDecommissioned
// and leaves no identity, configuration or cache; the node does not start
// again until it is enrolled anew.
func TestDecommissionTask(t *testing.T) {
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-dc", ClusterID: "cl-dc", ReportInterval: 1, KeepaliveInterval: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	root := t.TempDir()
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}
	rev := console.Publish(baseConfig(demoSite("site-a", "site-a.test")))
	dp := fakedataplane.Start(t)
	cfg := h.agentConfig(dp.Socket)
	cfg.TaskPollInterval = 100 * time.Millisecond
	enrollWith(t, console, srv.URL, h.stateDir, "dc-token")
	done, _, _ := runUntilDone(t, cfg, dp)
	eventually(t, "configuration applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	eventually(t, "decommission-v1 reported", func() bool {
		return slices.Contains(console.LastStatus().GetInfo().GetSupportedFeatures(), agent.FeatureDecommission)
	})
	if err := os.MkdirAll(filepath.Join(cfg.Render.CacheDir, "zone", "a"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.Render.CacheDir, "zone", "a", "obj"), []byte("cached"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(h.stateDir, "upgrades"), 0o700); err != nil {
		t.Fatal(err)
	}

	// A result that does not reach the console undoes it: the agent keeps
	// running and the task comes again.
	console.FailTaskResults(1)
	console.AddTask(decommissionTask("dc-1"), false)
	time.Sleep(500 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("agent stopped although the result was not reported: %v", err)
	default:
	}
	if _, err := os.Stat(filepath.Join(h.stateDir, identity.DecommissionedFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker left after an unreported result: %v", err)
	}

	console.AddTask(decommissionTask("dc-1"), false)
	res := waitResults(t, console, 1)
	if res[0].GetTaskId() != "dc-1" || res[0].GetState() != nodev1.TaskState_TASK_STATE_SUCCEEDED {
		t.Fatalf("result %v", res[0])
	}
	select {
	case err := <-done:
		if !errors.Is(err, agent.ErrDecommissioned) {
			t.Fatalf("Run = %v, want ErrDecommissioned", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("agent did not stop after the decommission task")
	}
	entries, err := os.ReadDir(h.stateDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, []string{identity.DecommissionedFile, "upgrades"}) {
		t.Fatalf("state dir after decommissioning: %v", names)
	}
	if entries, err := os.ReadDir(cfg.Render.CacheDir); err != nil || len(entries) != 0 {
		t.Fatalf("cache dir after decommissioning: %v %v", entries, err)
	}

	// Not again, also after a restart.
	done, _, _ = runUntilDone(t, cfg, dp)
	select {
	case err := <-done:
		if !errors.Is(err, agent.ErrDecommissioned) {
			t.Fatalf("restart: Run = %v, want ErrDecommissioned", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("decommissioned agent started")
	}

	// A new enrollment brings it back.
	enrollWith(t, console, srv.URL, h.stateDir, "dc-token-2")
	if _, err := os.Stat(filepath.Join(h.stateDir, identity.DecommissionedFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("marker left after enrolling again: %v", err)
	}
	done, _, cancel := runUntilDone(t, cfg, dp)
	eventually(t, "configuration applied after enrolling again", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run after enrolling again: %v", err)
	}
}
