package engine

import (
	"context"
	"github.com/marvinli001/edgeweir-node/internal/nodelog"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/testutil/childproc"
)

func TestMain(m *testing.M) {
	childproc.UnignoreSIGHUP()
	os.Exit(m.Run())
}

// fakeNginx is a shell script standing in for the openresty binary.
const fakeNginx = `#!/bin/sh
conf=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-c" ]; then conf="$a"; fi
  prev="$a"
done
case " $* " in
  *" -v "*) echo "nginx version: openresty/1.31.1.1" >&2; exit 0 ;;
  *" -t "*)
    if grep -q BROKEN "$conf"; then
      echo "nginx: [emerg] unknown directive \"BROKEN\" in $conf:1" >&2
      exit 1
    fi
    exit 0 ;;
  *" -s reload "*) echo reload >> "$FAKE_NGINX_DIR/reloads"; exit 0 ;;
esac
# Signal handlers first: the test signals as soon as the pid file exists.
trap 'echo hup >> "$FAKE_NGINX_DIR/hups"' HUP
trap 'echo quit >> "$FAKE_NGINX_DIR/quits"; exit 0' QUIT
echo $$ > "$FAKE_NGINX_DIR/pid"
echo start >> "$FAKE_NGINX_DIR/starts"
echo "2026/09/25 00:00:00 [notice] 1#1: start worker processes" >&2
while :; do sleep 0.05; done
`

func setupFake(t *testing.T, managed bool) (*Nginx, string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "openresty")
	if err := os.WriteFile(bin, []byte(fakeNginx), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_NGINX_DIR", dir)
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("events {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, "stale.sock")
	if err := os.WriteFile(stale, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	n := New(Config{
		Bin: bin, Prefix: dir, Conf: conf, Managed: managed,
		StaleSockets: []string{stale},
		// TestManagedLifecycle checks that nginx stops on SIGQUIT, not on
		// the SIGKILL after StopTimeout.
		StopTimeout: time.Until(childproc.Deadline(t)),
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return n, dir
}

func lines(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return strings.Count(string(b), "\n")
}

func TestParseVersion(t *testing.T) {
	cases := map[string]string{
		"nginx version: openresty/1.31.1.1\n": "1.31.1.1",
		"nginx version: nginx/1.29.1":         "1.29.1",
		"nginx version: something":            "something",
	}
	for in, want := range cases {
		if got := ParseVersion(in); got != want {
			t.Errorf("ParseVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVersionAndTest(t *testing.T) {
	n, dir := setupFake(t, true)
	ctx := context.Background()
	v, err := n.Version(ctx)
	if err != nil || v != "1.31.1.1" {
		t.Fatalf("Version = %q, %v", v, err)
	}
	if err := n.Test(ctx, filepath.Join(dir, "nginx.conf")); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	broken := filepath.Join(dir, "broken.conf")
	_ = os.WriteFile(broken, []byte("BROKEN;\n"), 0o644)
	err = n.Test(ctx, broken)
	if err == nil || !strings.Contains(err.Error(), `unknown directive "BROKEN"`) {
		t.Fatalf("broken config: err = %v", err)
	}
}

func TestManagedLifecycle(t *testing.T) {
	n, dir := setupFake(t, true)
	deadline := childproc.Context(t)
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = n.Run(ctx) }()
	// A failed check stops nginx too; it would outlive the test otherwise.
	t.Cleanup(func() { cancel(); <-runDone })

	if n.Running() {
		t.Fatal("nginx running before the first reload")
	}
	// First Reload starts the child.
	if err := n.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-n.Started():
	case <-deadline.Done():
		t.Fatal("nginx not started")
	}
	childproc.Wait(t, "pid file", func() bool { return lines(t, filepath.Join(dir, "pid")) == 1 })
	if _, err := os.Stat(filepath.Join(dir, "stale.sock")); !os.IsNotExist(err) {
		t.Fatal("stale socket not removed before start")
	}

	// Further reloads send SIGHUP.
	if err := n.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	childproc.Wait(t, "SIGHUP", func() bool { return lines(t, filepath.Join(dir, "hups")) >= 1 })

	// A crashed child is restarted.
	pidBytes, _ := os.ReadFile(filepath.Join(dir, "pid"))
	pid, _ := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case <-n.Started():
	case <-deadline.Done():
		t.Fatal("nginx not restarted after crash")
	}
	childproc.Wait(t, "second start", func() bool { return lines(t, filepath.Join(dir, "starts")) == 2 })

	// Shutdown stops the child gracefully.
	cancel()
	select {
	case <-runDone:
	case <-deadline.Done():
		t.Fatal("Run did not return after cancel")
	}
	if lines(t, filepath.Join(dir, "quits")) != 1 {
		t.Fatal("nginx was not stopped with SIGQUIT")
	}
	if n.Running() {
		t.Fatal("still running after shutdown")
	}
}

func TestUnmanagedReload(t *testing.T) {
	n, dir := setupFake(t, false)
	if !n.Running() {
		t.Fatal("unmanaged engine must report running")
	}
	if err := n.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lines(t, filepath.Join(dir, "reloads")) != 1 {
		t.Fatal("-s reload not executed")
	}
}

func TestLineLoggerLevels(t *testing.T) {
	var buf strings.Builder
	l := &lineLogger{log: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	_, _ = l.Write([]byte("a [error] boom\nb [warn] hmm\nc [notice] ok\npartial"))
	l.flush()
	out := buf.String()
	for _, want := range []string{"level=ERROR", "level=WARN", "level=INFO", "partial"} {
		if !strings.Contains(out, want) {
			t.Errorf("log output missing %q:\n%s", want, out)
		}
	}
}

func TestLineLoggerSinkTakesWholeMessages(t *testing.T) {
	var out strings.Builder
	base := slog.NewTextHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug})
	var captured, sunk, debug []nodelog.Entry
	// The agent's logger adds warnings as entries; the line logger's own
	// records must not become entries a second time.
	log := slog.New(nodelog.NewHandler(base, func(e nodelog.Entry) { captured = append(captured, e) }, nodelog.SourceAgent))
	now := time.Unix(100, 0)
	l := &lineLogger{log: log.With(nodelog.Skip), sink: func(e nodelog.Entry) { sunk = append(sunk, e) }, now: func() time.Time { return now },
		debugSink: func(e nodelog.Entry) { debug = append(debug, e) }}
	_, _ = l.Write([]byte("2026/10/15 10:00:00 [error] 7#7: *1 lua entry thread aborted: runtime error: boom\nstack traceback:\n\t[C]: in function 'error'\n" +
		"2026/10/15 10:00:00 [notice] 7#7: signal process started\n2026/10/15 10:00:00 [warn] 7#7: *2 upstream response is buffered"))
	// The second warning ends in the next write.
	_, _ = l.Write([]byte(" to a temporary file, client: 192.0.2.1, server: a.test\n"))
	l.flush()
	if len(captured) != 0 {
		t.Fatalf("captured through the logger: %+v", captured)
	}
	if len(sunk) != 2 {
		t.Fatalf("%d entries: %+v", len(sunk), sunk)
	}
	if sunk[0].Source != nodelog.SourceLua || !strings.HasSuffix(sunk[0].Message, "in function 'error'") || !sunk[0].Time.Equal(now) {
		t.Fatalf("first %+v", sunk[0])
	}
	if sunk[1].Level != nodelog.LevelWarn || sunk[1].Message != "upstream response is buffered to a temporary file" || sunk[1].Fields["server"] != "a.test" {
		t.Fatalf("second %+v", sunk[1])
	}
	// The debug log ring gets every message, the notice too.
	if len(debug) != 3 || debug[1].Level != nodelog.LevelInfo || debug[1].Message != "signal process started" || debug[1].Fields["severity"] != "notice" {
		t.Fatalf("debug %+v", debug)
	}
	if !strings.Contains(out.String(), "signal process started") || strings.Contains(out.String(), "nodelog.skip") {
		t.Fatalf("local output %q", out.String())
	}
}
