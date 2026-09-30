// Package engine controls the OpenResty (nginx) process: configuration
// tests, reloads and, in managed mode, supervising nginx as a child
// process of the agent.
//
// Managed mode (--manage-nginx, used by the container image and the
// systemd unit) runs `openresty -g 'daemon off;'` as a child, reloads it
// with SIGHUP, restarts it with exponential backoff if it dies, and stops
// it gracefully (SIGQUIT, then SIGKILL after a timeout) when the agent
// shuts down. Unmanaged mode expects nginx to be run by someone else and
// reloads it with `-s reload` (pid file).
package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Config configures an Nginx engine.
type Config struct {
	// Bin is the openresty/nginx binary (looked up in PATH if relative).
	Bin string
	// Prefix is the nginx prefix directory (-p).
	Prefix string
	// Conf is the absolute path of the main configuration file (-c).
	Conf string
	// Managed runs nginx as a supervised child process.
	Managed bool
	// StaleSockets are unix sockets removed before nginx starts (left over
	// after a crash they would make bind() fail).
	StaleSockets []string
	// StopTimeout bounds graceful shutdown before SIGKILL (default 8s).
	StopTimeout time.Duration
	Logger      *slog.Logger
}

// Nginx implements the engine for OpenResty.
type Nginx struct {
	cfg Config
	log *slog.Logger

	mu      sync.Mutex
	proc    *os.Process
	kick    chan struct{}
	started chan struct{}
}

// New returns an engine for cfg.
func New(cfg Config) *Nginx {
	if cfg.StopTimeout == 0 {
		cfg.StopTimeout = 8 * time.Second
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Nginx{
		cfg:     cfg,
		log:     log.With("component", "nginx"),
		kick:    make(chan struct{}, 1),
		started: make(chan struct{}, 1),
	}
}

func (n *Nginx) args(conf string, extra ...string) []string {
	return append([]string{"-p", n.cfg.Prefix, "-c", conf, "-e", "stderr"}, extra...)
}

// Version returns the engine version, e.g. "1.31.1.1" for
// "nginx version: openresty/1.31.1.1".
func (n *Nginx) Version(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, n.cfg.Bin, "-v").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s -v: %w", n.cfg.Bin, err)
	}
	return ParseVersion(string(out)), nil
}

// ParseVersion extracts the version from `nginx -v` output.
func ParseVersion(out string) string {
	line := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	if i := strings.LastIndex(line, "/"); i >= 0 {
		return strings.TrimSpace(line[i+1:])
	}
	return strings.TrimPrefix(line, "nginx version: ")
}

// Test runs `openresty -t` against conf. The returned error carries
// nginx's own diagnostics, which are reported to the console verbatim.
func (n *Nginx) Test(ctx context.Context, conf string) error {
	cmd := exec.CommandContext(ctx, n.cfg.Bin, n.args(conf, "-t", "-q")...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("nginx configuration test failed: %s", msg)
	}
	return nil
}

// Reload makes nginx pick up the configuration file. In managed mode it
// sends SIGHUP to the child, or starts nginx if it is not running.
func (n *Nginx) Reload(ctx context.Context) error {
	if !n.cfg.Managed {
		out, err := exec.CommandContext(ctx, n.cfg.Bin, n.args(n.cfg.Conf, "-s", "reload")...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("nginx reload failed: %s", strings.TrimSpace(string(out)))
		}
		return nil
	}
	n.mu.Lock()
	p := n.proc
	n.mu.Unlock()
	if p == nil {
		select {
		case n.kick <- struct{}{}:
		default:
		}
		return nil
	}
	if err := p.Signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("signal nginx: %w", err)
	}
	return nil
}

// Running reports whether the managed child is running. In unmanaged mode
// it always returns true (the process is not ours to observe).
func (n *Nginx) Running() bool {
	if !n.cfg.Managed {
		return true
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.proc != nil
}

// Started receives a value every time the managed child (re)starts; the
// agent re-pushes the site table then, because the shared dicts are empty.
func (n *Nginx) Started() <-chan struct{} { return n.started }

// Run supervises the managed child until ctx is done. It waits for the
// first Reload before starting nginx (the agent tests the configuration
// first). In unmanaged mode it just blocks.
func (n *Nginx) Run(ctx context.Context) error {
	if !n.cfg.Managed {
		<-ctx.Done()
		return nil
	}
	select {
	case <-ctx.Done():
		return nil
	case <-n.kick:
	}
	backoff := time.Second
	for {
		startedAt := time.Now()
		err := n.runOnce(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if time.Since(startedAt) > time.Minute {
			backoff = time.Second
		}
		n.log.Error("nginx exited unexpectedly, restarting", "err", err, "backoff", backoff.String())
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		case <-n.kick:
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (n *Nginx) runOnce(ctx context.Context) error {
	for _, s := range n.cfg.StaleSockets {
		if err := os.Remove(s); err != nil && !errors.Is(err, os.ErrNotExist) {
			n.log.Warn("cannot remove stale socket", "path", s, "err", err)
		}
	}
	lw := &lineLogger{log: n.log}
	cmd := exec.Command(n.cfg.Bin, n.args(n.cfg.Conf, "-g", "daemon off;")...)
	cmd.Stdout = lw
	cmd.Stderr = lw
	cmd.SysProcAttr = sysProcAttr()
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start nginx: %w", err)
	}
	n.mu.Lock()
	n.proc = cmd.Process
	n.mu.Unlock()
	n.log.Info("nginx started", "pid", cmd.Process.Pid, "conf", n.cfg.Conf)
	select {
	case n.started <- struct{}{}:
	default:
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		n.mu.Lock()
		n.proc = nil
		n.mu.Unlock()
		lw.flush()
	}()

	select {
	case err := <-done:
		if err == nil {
			err = errors.New("exited with status 0")
		}
		return err
	case <-ctx.Done():
		n.log.Info("stopping nginx gracefully", "pid", cmd.Process.Pid)
		_ = cmd.Process.Signal(syscall.SIGQUIT)
		select {
		case <-done:
		case <-time.After(n.cfg.StopTimeout):
			n.log.Warn("nginx did not stop in time, killing", "pid", cmd.Process.Pid)
			_ = cmd.Process.Kill()
			<-done
		}
		return ctx.Err()
	}
}

// lineLogger forwards nginx's stderr (error_log stderr) line by line.
//
// ModSecurity logs every request it denies with the request line; under an
// attack that would flood the agent's log. Those lines are counted instead
// and summarized at most once a minute (the matched rules reach the console
// through the statistics).
type lineLogger struct {
	log *slog.Logger
	mu  sync.Mutex
	buf []byte

	now          func() time.Time // for tests; nil = time.Now
	denied       int
	deniedSince  time.Time
	deniedLogged time.Time
}

// modsecDenied marks ModSecurity's log line of a denied request.
const modsecDenied = "ModSecurity: Access denied"

func (l *lineLogger) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			break
		}
		l.emit(string(l.buf[:i]))
		l.buf = l.buf[i+1:]
	}
	if len(l.buf) > 64<<10 {
		l.emit(string(l.buf))
		l.buf = nil
	}
	return len(p), nil
}

func (l *lineLogger) flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buf) > 0 {
		l.emit(string(l.buf))
		l.buf = nil
	}
	l.summarizeDenied(true)
}

// summarizeDenied logs the number of denied requests counted since the last
// summary, at most once a minute unless force is set.
func (l *lineLogger) summarizeDenied(force bool) {
	if l.denied == 0 {
		return
	}
	now := time.Now()
	if l.now != nil {
		now = l.now()
	}
	if !force && now.Sub(l.deniedLogged) < time.Minute {
		return
	}
	l.log.Info("ModSecurity denied requests (OWASP CRS)", "requests", l.denied,
		"since", l.deniedSince.UTC().Format(time.RFC3339))
	l.denied, l.deniedLogged = 0, now
}

func (l *lineLogger) emit(line string) {
	line = strings.TrimRight(line, "\r")
	if line == "" {
		return
	}
	if strings.Contains(line, modsecDenied) {
		if l.denied == 0 {
			l.deniedSince = time.Now()
			if l.now != nil {
				l.deniedSince = l.now()
			}
		}
		l.denied++
		l.summarizeDenied(false)
		return
	}
	level := slog.LevelInfo
	switch {
	case strings.Contains(line, "[emerg]"), strings.Contains(line, "[alert]"), strings.Contains(line, "[crit]"), strings.Contains(line, "[error]"):
		level = slog.LevelError
	case strings.Contains(line, "[warn]"):
		level = slog.LevelWarn
	}
	l.log.Log(context.Background(), level, line)
}
