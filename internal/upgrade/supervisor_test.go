package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The real test executable doubles as an independently started agent process.
func TestMain(m *testing.M) {
	if os.Getenv("EDGEWEIR_UPGRADE_TEST_CHILD") == "1" {
		lua := ""
		for i := 0; i < len(os.Args)-1; i++ {
			if os.Args[i] == "--lua-dir" {
				lua = os.Args[i+1]
			}
		}
		raw, _ := os.ReadFile(filepath.Join(lua, "version"))
		v := strings.TrimSpace(string(raw))
		socket := os.Getenv("EDGEWEIR_SUPERVISOR_SOCKET")
		if v == "fail" {
			_ = os.WriteFile(filepath.Join(filepath.Dir(socket), "config", "current.binpb"), []byte("bad candidate"), 0600)
			os.Exit(42)
		}
		if v == "usage" || v == "crash" {
			f, _ := os.OpenFile(filepath.Join(filepath.Dir(socket), "starts"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
			_, _ = f.WriteString("start\n")
			_ = f.Close()
			if v == "usage" {
				os.Exit(2)
			}
			os.Exit(1)
		}
		client := NewClient(socket)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = client.Healthy(ctx, v)
			cancel()
			time.Sleep(50 * time.Millisecond)
		}
	}
	os.Exit(m.Run())
}
func wait(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition did not complete")
}
func fixture(t *testing.T) (Options, *Client) {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "ew-up-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	t.Setenv("EDGEWEIR_UPGRADE_TEST_CHILD", "1")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	lua := filepath.Join(root, "base-lua")
	_ = os.MkdirAll(lua, 0700)
	_ = os.WriteFile(filepath.Join(lua, "version"), []byte("0.1.0"), 0600)
	_ = os.MkdirAll(filepath.Join(root, "config"), 0700)
	_ = os.WriteFile(filepath.Join(root, "config", "current.binpb"), []byte("original LKG"), 0600)
	opts := Options{Trust: Trust{StateDir: root}, Executable: exe, LuaDir: lua, Version: "0.1.0", Output: io.Discard, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), StableWindow: 100 * time.Millisecond, TrialTimeout: 2 * time.Second}
	opts.prepare = func(_ context.Context, o Trust, t Task) (Bundle, error) {
		dir := filepath.Join(o.StateDir, "upgrades", "releases", t.ID)
		if err := os.MkdirAll(filepath.Join(dir, "lua"), 0700); err != nil {
			return Bundle{}, err
		}
		raw, err := os.ReadFile(exe)
		if err != nil {
			return Bundle{}, err
		}
		if err = fsutil.WriteFileAtomic(filepath.Join(dir, "edgeweir-node"), raw, 0700); err != nil {
			return Bundle{}, err
		}
		v := t.Version
		if v == "0.3.0" {
			v = "fail"
		}
		if err = fsutil.WriteFileAtomic(filepath.Join(dir, "lua", "version"), []byte(v), 0600); err != nil {
			return Bundle{}, err
		}
		return Bundle{TaskID: t.ID, Version: t.Version, Dir: dir, SHA256: strings.Repeat("a", 64)}, nil
	}
	return opts, NewClient(Socket(root))
}
func launch(t *testing.T, opts Options, client *Client) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, opts) }()
	wait(t, func() bool { _, err := client.Result(context.Background()); return err == nil })
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("supervisor did not stop")
		}
	}
	t.Cleanup(stop)
	return stop
}
func TestUpgradeResultSurvivesRestartAndFailedAckThenRollsBackStartupFailure(t *testing.T) {
	opts, client := fixture(t)
	stop := launch(t, opts, client)
	id := "11111111-1111-4111-8111-111111111111"
	if err := client.Stage(context.Background(), Task{ID: id, Version: "0.2.0"}); err != nil {
		t.Fatal(err)
	}
	wait(t, func() bool { r, e := client.Result(context.Background()); return e == nil && r != nil && r.Success })
	stop()
	stop = launch(t, opts, client)
	r, err := client.Result(context.Background())
	if err != nil || r == nil || r.TaskID != id || !r.Success {
		t.Fatalf("lost successful result: %+v %v", r, err)
	}
	state := filepath.Join(opts.Trust.StateDir, "upgrades", "state.json")
	if err = os.Rename(state, state+".backup"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	if err = client.Ack(context.Background(), id); err == nil {
		t.Fatal("ack succeeded despite an unwritable journal")
	}
	r, err = client.Result(context.Background())
	if err != nil || r == nil || r.TaskID != id {
		t.Fatal("failed ACK erased the result from memory")
	}
	_ = os.Remove(state)
	_ = os.Rename(state+".backup", state)
	if err = client.Ack(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	bad := "22222222-2222-4222-8222-222222222222"
	if err = client.Stage(context.Background(), Task{ID: bad, Version: "0.3.0"}); err != nil {
		t.Fatal(err)
	}
	wait(t, func() bool {
		r, e := client.Result(context.Background())
		return e == nil && r != nil && r.TaskID == bad
	})
	r, err = client.Result(context.Background())
	if err != nil || r.Success || !r.RolledBack {
		t.Fatalf("failed candidate was not rolled back: %+v %v", r, err)
	}
	raw, err := os.ReadFile(filepath.Join(opts.Trust.StateDir, "config", "current.binpb"))
	if err != nil || string(raw) != "original LKG" {
		t.Fatalf("LKG not restored: %q %v", raw, err)
	}
	raw, err = os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var j journal
	if err = json.Unmarshal(raw, &j); err != nil {
		t.Fatal(err)
	}
	if j.Active.Version != "0.2.0" || j.Pending != nil {
		t.Fatalf("wrong active version: %+v", j)
	}
	stop()
}
func TestRestartDuringTrialFailsClosed(t *testing.T) {
	opts, client := fixture(t)
	candidate, err := opts.prepare(context.Background(), opts.Trust, Task{ID: "33333333-3333-4333-8333-333333333333", Version: "0.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	s := &Supervisor{opts: opts, state: journal{Version: 1}}
	if err = s.backupConfig(candidate); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(opts.Trust.StateDir, "config", "current.binpb"), []byte("trial changes"), 0600)
	if err = s.persist(journal{Version: 1, Pending: &pending{Candidate: candidate, Phase: "trial", StartedAt: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	stop := launch(t, opts, client)
	defer stop()
	r, err := client.Result(context.Background())
	if err != nil || r == nil || r.Success || !r.RolledBack {
		t.Fatalf("restart committed trial: %+v %v", r, err)
	}
	raw, _ := os.ReadFile(filepath.Join(opts.Trust.StateDir, "config", "current.binpb"))
	if string(raw) != "original LKG" {
		t.Fatalf("restart did not restore config: %s", raw)
	}
}

func TestNewBaseInstallationSupersedesOldActiveBundle(t *testing.T) {
	opts, client := fixture(t)
	stop := launch(t, opts, client)
	if err := client.Stage(context.Background(), Task{ID: "55555555-5555-4555-8555-555555555555", Version: "0.2.0"}); err != nil {
		t.Fatal(err)
	}
	wait(t, func() bool { r, err := client.Result(context.Background()); return err == nil && r != nil && r.Success })
	stop()
	// A system-package/image update changes the base fingerprint; a plain restart does not.
	opts.Version = "0.4.0"
	if err := os.WriteFile(filepath.Join(opts.LuaDir, "version"), []byte("0.4.0"), 0600); err != nil {
		t.Fatal(err)
	}
	stop = launch(t, opts, client)
	defer stop()
	raw, err := os.ReadFile(filepath.Join(opts.Trust.StateDir, "upgrades", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var j journal
	if err = json.Unmarshal(raw, &j); err != nil {
		t.Fatal(err)
	}
	if j.Result == nil || j.Result.Success || j.Result.ErrorCode != "upgrade_interrupted" {
		t.Fatal("base installation reported the superseded upgrade as successful")
	}
	if j.Active.Dir != "" || j.Previous.Version != "0.2.0" || j.BaseDigest == "" {
		t.Fatalf("old bundle shadowed the new base installation: %+v", j)
	}
}

// TestUsageExitStopsTheSupervisor (P1-62): a node that exits with status 2
// (invalid flags or local settings) is not started again every two
// seconds; the supervisor stops with ErrUsage.
func TestUsageExitStopsTheSupervisor(t *testing.T) {
	opts, _ := fixture(t)
	_ = os.WriteFile(filepath.Join(opts.LuaDir, "version"), []byte("usage"), 0600)
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), opts) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrUsage) {
			t.Fatalf("Run = %v, want ErrUsage", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the supervisor kept restarting the node")
	}
	if raw, _ := os.ReadFile(filepath.Join(opts.Trust.StateDir, "starts")); strings.Count(string(raw), "start") != 1 {
		t.Fatalf("node started %d times", strings.Count(string(raw), "start"))
	}
}

// TestCrashingNodeIsRestartedWithBackoff (P1-62): a node that keeps exiting
// right after its start is restarted after 2 s, then 4 s, ... (at most a
// minute), not every 2 s.
func TestCrashingNodeIsRestartedWithBackoff(t *testing.T) {
	opts, client := fixture(t)
	_ = os.WriteFile(filepath.Join(opts.LuaDir, "version"), []byte("crash"), 0600)
	stop := launch(t, opts, client)
	time.Sleep(7500 * time.Millisecond)
	stop()
	// Starts at 0 s, 2 s and 6 s, each up to 250 ms later (every 2 s: also at 4 s).
	if raw, _ := os.ReadFile(filepath.Join(opts.Trust.StateDir, "starts")); strings.Count(string(raw), "start") != 3 {
		t.Fatalf("node started %d times in 7.5 s", strings.Count(string(raw), "start"))
	}
}
