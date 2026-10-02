package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/engine"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
)

type Result struct {
	ErrorCode  string    `json:"error_code,omitempty"`
	TaskID     string    `json:"task_id"`
	Version    string    `json:"version"`
	Success    bool      `json:"success"`
	RolledBack bool      `json:"rolled_back"`
	Message    string    `json:"message"`
	FinishedAt time.Time `json:"finished_at"`
}
type pending struct {
	Candidate Bundle    `json:"candidate"`
	Previous  Bundle    `json:"previous"`
	Phase     string    `json:"phase"`
	StartedAt time.Time `json:"started_at"`
}
type journal struct {
	BaseDigest string   `json:"base_digest"`
	Version    int      `json:"version"`
	Active     Bundle   `json:"active"`
	Previous   Bundle   `json:"previous"`
	Pending    *pending `json:"pending,omitempty"`
	Result     *Result  `json:"result,omitempty"`
}
type Options struct {
	Trust        Trust
	Executable   string
	LuaDir       string
	Version      string
	RunArgs      []string
	Log          *slog.Logger
	Output       io.Writer
	TrialTimeout time.Duration
	StableWindow time.Duration
	// Engine is OpenResty the supervisor runs for its children (see
	// engine.go); nil: each child runs it itself.
	Engine *engine.Config
	// AllowDowngrade lets an upgrade task install an older version than
	// the active one (refused otherwise: an older signed release may have
	// known flaws).
	AllowDowngrade bool
	// Test seams remain package-private and cannot be configured by the console.
	prepare func(context.Context, Trust, Task) (Bundle, error)
}
type Supervisor struct {
	opts                    Options
	mu                      sync.Mutex
	state                   journal
	staging                 bool
	child                   *exec.Cmd
	exit                    <-chan error
	healthFirst, healthLast time.Time
	healthPID               int
	// startedAt is when the child started; restartDelay grows while it
	// keeps exiting within a minute.
	startedAt    time.Time
	restartDelay time.Duration
	engine       supervisedEngine
}

// ErrUsage stops the supervisor when the node exits with status 2: its
// flags or local settings are wrong, and starting it again cannot help.
var ErrUsage = errors.New("edgeweir-node run exited with status 2 (invalid flags or local settings); not restarting it")

// usageExit reports whether a child's exit was status 2.
func usageExit(err error) bool {
	var exit *exec.ExitError
	return errors.As(err, &exit) && exit.ExitCode() == 2
}

func Socket(stateDir string) string { return filepath.Join(stateDir, "upgrade.sock") }
func (s *Supervisor) statePath() string {
	return filepath.Join(s.opts.Trust.StateDir, "upgrades", "state.json")
}
func (s *Supervisor) persist(next journal) error {
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err = fsutil.WriteFileAtomic(s.statePath(), raw, 0600); err != nil {
		return err
	}
	s.state = next
	return nil
}
func (s *Supervisor) cleanup() {
	root := filepath.Join(s.opts.Trust.StateDir, "upgrades", "releases")
	keep := map[string]bool{s.state.Active.Dir: true, s.state.Previous.Dir: true}
	if p := s.state.Pending; p != nil {
		keep[p.Candidate.Dir] = true
		keep[p.Previous.Dir] = true
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		target := filepath.Join(root, entry.Name())
		if !keep[target] && (taskRE.MatchString(entry.Name()) || strings.HasPrefix(entry.Name(), ".stage-")) {
			_ = os.RemoveAll(target)
		}
	}
}

func (s *Supervisor) validBundle(b Bundle) bool {
	return b.Dir == "" || (taskRE.MatchString(b.TaskID) && versionRE.MatchString(b.Version) && b.Dir == filepath.Join(s.opts.Trust.StateDir, "upgrades", "releases", b.TaskID))
}
func (s *Supervisor) load() error {
	raw, err := os.ReadFile(s.statePath())
	if os.IsNotExist(err) {
		s.state = journal{Version: 1}
		return nil
	}
	if err != nil {
		return err
	}
	if len(raw) > 65536 {
		return errors.New("upgrade journal exceeds limit")
	}
	if err = json.Unmarshal(raw, &s.state); err != nil {
		return err
	}
	if s.state.Version != 1 || !s.validBundle(s.state.Active) || !s.validBundle(s.state.Previous) {
		return errors.New("invalid upgrade journal")
	}
	if p := s.state.Pending; p != nil {
		if !s.validBundle(p.Candidate) || p.Candidate.Dir == "" || !s.validBundle(p.Previous) || (p.Phase != "prepared" && p.Phase != "trial") {
			return errors.New("invalid pending upgrade")
		}
	}
	return nil
}

// Run owns the stable parent process. Its installed executable is never overwritten.
func Run(ctx context.Context, opts Options) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Output == nil {
		opts.Output = os.Stderr
	}
	if opts.TrialTimeout == 0 {
		opts.TrialTimeout = 90 * time.Second
	}
	if opts.StableWindow == 0 {
		opts.StableWindow = 10 * time.Second
	}
	if opts.prepare == nil {
		opts.prepare = Prepare
	}
	if err := os.MkdirAll(filepath.Join(opts.Trust.StateDir, "upgrades"), 0700); err != nil {
		return err
	}
	// The inode lock is held before reading or recovering the journal. A second
	// supervisor must never mistake a live trial for an interrupted one.
	lock, err := os.OpenFile(filepath.Join(opts.Trust.StateDir, "upgrades", "supervisor.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("another node supervisor owns this state directory")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	s := &Supervisor{opts: opts}
	if err := s.load(); err != nil {
		return err
	}
	// A power loss/restart during a trial is a failed trial, never implicit success.
	if s.state.Pending != nil && (s.state.Pending.Phase == "trial" || time.Since(s.state.Pending.StartedAt) > 30*time.Minute) {
		if err := s.rollback("supervisor restarted during upgrade trial"); err != nil {
			return err
		}
	}
	digest, err := baseDigest(opts)
	if err != nil {
		return err
	}
	if s.state.BaseDigest != digest {
		next := s.state
		if next.Result != nil && next.Result.Success {
			old := next.Result
			next.Result = &Result{TaskID: old.TaskID, Version: old.Version, ErrorCode: "upgrade_interrupted", Message: "base installation changed before the upgrade result was acknowledged", FinishedAt: time.Now()}
		}
		if next.Pending != nil {
			next.Result = &Result{TaskID: next.Pending.Candidate.TaskID, Version: next.Pending.Candidate.Version, ErrorCode: "upgrade_interrupted", Message: "base installation changed before activation", FinishedAt: time.Now()}
			next.Pending = nil
		}
		if next.Active.Dir != "" {
			next.Previous = next.Active
			next.Active = Bundle{}
		}
		next.BaseDigest = digest
		if err = s.persist(next); err != nil {
			return err
		}
		opts.Log.Info("using the installed base program and Lua", "version", opts.Version)
	}
	s.cleanup()
	sock := Socket(opts.Trust.StateDir)
	if st, err := os.Lstat(sock); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return errors.New("upgrade socket path is not a socket")
		}
		conn, e := net.DialTimeout("unix", sock, 200*time.Millisecond)
		if e == nil {
			_ = conn.Close()
			return errors.New("another node supervisor is already running")
		}
		if err = os.Remove(sock); err != nil {
			return err
		}
	}
	listener, err := net.Listen("unix", sock)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(sock)
	if err = os.Chmod(sock, 0600); err != nil {
		return err
	}
	server := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Minute, BaseContext: func(net.Listener) context.Context { return ctx }}
	defer func() { cancel(); _ = server.Shutdown(context.Background()) }()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			opts.Log.Error("upgrade socket failed", "err", err)
		}
	}()
	// Deferred first, so it runs after the child stopped (the child saves
	// its statistics from OpenResty's counters on the way out).
	s.startEngine()
	defer s.stopEngine()
	if err = s.start(s.state.Active); err != nil {
		return err
	}
	defer s.stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.mu.Lock()
			if p := s.state.Pending; p != nil && p.Phase == "prepared" && time.Since(p.StartedAt) >= time.Second {
				trial := *p
				trial.Phase = "trial"
				trial.StartedAt = time.Now()
				next := s.state
				next.Pending = &trial
				if err = s.persist(next); err != nil {
					s.mu.Unlock()
					return err
				}
				s.mu.Unlock()
				s.stop()
				s.switchEngine(p.Previous, p.Candidate)
				// Only configuration is restored on rollback. Never rewind enrollment keys,
				// credentials, stats/log cursors or other identity-bearing mutable state.
				err = s.backupConfig(p.Candidate)
				s.mu.Lock()
				if err == nil {
					err = s.startLocked(p.Candidate)
				}
				if err != nil {
					if e := s.rollback("candidate failed to start"); e != nil {
						s.mu.Unlock()
						return e
					}
					err = s.startLocked(s.state.Active)
				}
				s.mu.Unlock()
				if err != nil {
					return err
				}
				continue
			}
			if p := s.state.Pending; p != nil && p.Phase == "trial" {
				failed := false
				select {
				case <-s.exit:
					failed = true
					s.exit = nil
				default:
				}
				if failed || time.Since(p.StartedAt) > opts.TrialTimeout {
					s.mu.Unlock()
					s.stop()
					s.switchEngine(p.Candidate, p.Previous)
					s.mu.Lock()
					if err = s.rollback("candidate exited or did not pass the health window; previous version restored"); err == nil {
						err = s.startLocked(s.state.Active)
					}
					s.mu.Unlock()
					if err != nil {
						return err
					}
					continue
				}
				if !s.healthFirst.IsZero() && s.healthLast.Sub(s.healthFirst) >= opts.StableWindow && time.Since(s.healthLast) < 30*time.Second {
					next := s.state
					next.Previous = p.Previous
					next.Active = p.Candidate
					next.Pending = nil
					next.Result = &Result{TaskID: p.Candidate.TaskID, Version: p.Candidate.Version, Success: true, Message: "signed release activated and healthy", FinishedAt: time.Now()}
					if err = s.persist(next); err != nil {
						s.mu.Unlock()
						return err
					}
					s.cleanup()
					opts.Log.Info("node upgrade committed", "version", p.Candidate.Version, "task_id", p.Candidate.TaskID)
				}
			} else {
				select {
				case err := <-s.exit:
					s.exit = nil
					if usageExit(err) {
						s.mu.Unlock()
						opts.Log.Error("node exited with a usage error", "err", err)
						return ErrUsage
					}
					// 2 s, doubling up to a minute while the node keeps
					// failing within a minute of its start.
					if time.Since(s.startedAt) > time.Minute || s.restartDelay == 0 {
						s.restartDelay = 2 * time.Second
					} else {
						s.restartDelay = min(2*s.restartDelay, time.Minute)
					}
					delay := s.restartDelay
					s.mu.Unlock()
					opts.Log.Warn("node exited; restarting", "err", err, "after", delay.String())
					select {
					case <-ctx.Done():
						return nil
					case <-time.After(delay):
					}
					s.mu.Lock()
					err = s.startLocked(s.state.Active)
					if err != nil {
						s.mu.Unlock()
						return err
					}
				default:
				}
			}
			s.mu.Unlock()
		}
	}
}
func (s *Supervisor) start(b Bundle) error { s.mu.Lock(); defer s.mu.Unlock(); return s.startLocked(b) }
func (s *Supervisor) startLocked(b Bundle) error {
	bin, lua := s.opts.Executable, s.opts.LuaDir
	if b.Dir != "" {
		bin = filepath.Join(b.Dir, "edgeweir-node")
		lua = filepath.Join(b.Dir, "lua")
	}
	args := append([]string{"run"}, s.opts.RunArgs...)
	args = append(args, "--lua-dir", lua)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "EDGEWEIR_SUPERVISOR_SOCKET="+Socket(s.opts.Trust.StateDir))
	cmd.Stdout = s.opts.Output
	cmd.Stderr = s.opts.Output
	cmd.SysProcAttr = processAttributes()
	if err := cmd.Start(); err != nil {
		return err
	}
	result := make(chan error, 1)
	go func() { result <- cmd.Wait() }()
	s.child = cmd
	s.exit = result
	s.startedAt = time.Now()
	s.healthPID = cmd.Process.Pid
	s.healthFirst = time.Time{}
	s.healthLast = time.Time{}
	s.opts.Log.Info("supervisor started node", "pid", cmd.Process.Pid, "version", b.Version)
	return nil
}
func (s *Supervisor) stop() {
	s.mu.Lock()
	child, done := s.child, s.exit
	s.child = nil
	s.exit = nil
	s.healthPID = 0
	s.mu.Unlock()
	if child == nil || done == nil {
		return
	}
	select {
	case <-done:
		return
	default:
	}
	_ = child.Process.Signal(syscall.SIGTERM)
	if done != nil {
		select {
		case <-done:
			return
		case <-time.After(20 * time.Second):
		}
	}
	_ = child.Process.Kill()
	if done != nil {
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}
}
func (s *Supervisor) backupConfig(b Bundle) error {
	backup := filepath.Join(b.Dir, "rollback-config")
	if err := os.MkdirAll(backup, 0700); err != nil {
		return err
	}
	for _, name := range []string{"current.binpb", "previous.binpb", "receipts.json"} {
		raw, err := os.ReadFile(filepath.Join(s.opts.Trust.StateDir, "config", name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if err = fsutil.WriteFileAtomic(filepath.Join(backup, name), raw, 0600); err != nil {
			return err
		}
	}
	return fsutil.WriteFileAtomic(filepath.Join(backup, "complete"), []byte("1"), 0600)
}

// Called with the mutex held, or before the server/child is started.
func (s *Supervisor) rollback(message string) error {
	p := s.state.Pending
	if p == nil {
		return nil
	}
	backup := filepath.Join(p.Candidate.Dir, "rollback-config")
	if fsutil.Exists(filepath.Join(backup, "complete")) {
		dir := filepath.Join(s.opts.Trust.StateDir, "config")
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		for _, name := range []string{"current.binpb", "previous.binpb", "receipts.json"} {
			raw, err := os.ReadFile(filepath.Join(backup, name))
			if os.IsNotExist(err) {
				if e := os.Remove(filepath.Join(dir, name)); e != nil && !os.IsNotExist(e) {
					return e
				}
				continue
			}
			if err != nil {
				return err
			}
			if err = fsutil.WriteFileAtomic(filepath.Join(dir, name), raw, 0600); err != nil {
				return err
			}
		}
		if err := fsutil.SyncDir(dir); err != nil {
			return err
		}
	}
	next := s.state
	next.Active = p.Previous
	next.Pending = nil
	next.Result = &Result{TaskID: p.Candidate.TaskID, Version: p.Candidate.Version, RolledBack: p.Phase == "trial", Message: message, FinishedAt: time.Now()}
	s.opts.Log.Warn("node upgrade rolled back", "task_id", p.Candidate.TaskID, "version", p.Candidate.Version)
	return s.persist(next)
}
func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
func body(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	if json.NewDecoder(r.Body).Decode(v) != nil {
		reply(w, 400, map[string]string{"error": "invalid body"})
		return false
	}
	return true
}
func (s *Supervisor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.serveEngine(w, r) {
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/capabilities":
		bin := s.opts.Trust.Cosign
		if bin == "" {
			bin = "cosign"
		}
		_, err := exec.LookPath(bin)
		enabled := err == nil && (s.opts.Trust.PublicKey == "" || fsutil.Exists(s.opts.Trust.PublicKey))
		reply(w, 200, map[string]bool{"enabled": enabled, "engine": s.opts.Engine != nil})
	case r.Method == http.MethodPost && r.URL.Path == "/health":
		var h struct {
			PID     int    `json:"pid"`
			Version string `json:"version"`
			Healthy bool   `json:"healthy"`
		}
		if !body(w, r, &h) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		expected := s.state.Active.Version
		if p := s.state.Pending; p != nil && p.Phase == "trial" {
			expected = p.Candidate.Version
		}
		if h.PID != s.healthPID || (expected != "" && h.Version != expected) {
			reply(w, 409, map[string]string{"error": "not current child"})
			return
		}
		now := time.Now()
		if !h.Healthy {
			s.healthFirst = time.Time{}
			s.healthLast = time.Time{}
			reply(w, 200, map[string]bool{"ok": true})
			return
		}
		if !s.healthLast.IsZero() && now.Sub(s.healthLast) > 30*time.Second {
			s.healthFirst = time.Time{}
		}
		s.healthLast = now
		if s.healthFirst.IsZero() {
			s.healthFirst = s.healthLast
		}
		reply(w, 200, map[string]bool{"ok": true})
	case r.Method == http.MethodGet && r.URL.Path == "/result":
		s.mu.Lock()
		defer s.mu.Unlock()
		reply(w, 200, s.state.Result)
	case r.Method == http.MethodPost && r.URL.Path == "/ack":
		var ack struct {
			ID string `json:"id"`
		}
		if !body(w, r, &ack) {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.state.Result != nil && s.state.Result.TaskID == ack.ID {
			next := s.state
			next.Result = nil
			if err := s.persist(next); err != nil {
				reply(w, 500, map[string]string{"error": "cannot persist result acknowledgement"})
				return
			}
		}
		reply(w, 200, map[string]bool{"ok": true})
	case r.Method == http.MethodPost && r.URL.Path == "/stage":
		var t Task
		if !body(w, r, &t) {
			return
		}
		if !taskRE.MatchString(t.ID) {
			reply(w, 400, map[string]string{"error": "invalid task id"})
			return
		}
		s.mu.Lock()
		if (s.state.Pending != nil && s.state.Pending.Candidate.TaskID == t.ID) || (s.state.Result != nil && s.state.Result.TaskID == t.ID) {
			s.mu.Unlock()
			reply(w, 202, map[string]bool{"ok": true})
			return
		}
		if s.state.Active.TaskID == t.ID {
			next := s.state
			next.Result = &Result{TaskID: t.ID, Version: s.state.Active.Version, Success: true, Message: "release already active", FinishedAt: time.Now()}
			err := s.persist(next)
			s.mu.Unlock()
			if err != nil {
				reply(w, 500, map[string]string{"error": "journal write failed"})
			} else {
				reply(w, 202, map[string]bool{"ok": true})
			}
			return
		}
		if s.staging || s.state.Pending != nil || s.state.Result != nil {
			s.mu.Unlock()
			reply(w, 409, map[string]string{"error": "another upgrade is in progress"})
			return
		}
		current := s.state.Active.Version
		if s.state.Active.Dir == "" {
			current = s.opts.Version
		}
		if c, ok := compareVersions(t.Version, current); ok && c < 0 && !s.opts.AllowDowngrade {
			next := s.state
			next.Result = &Result{TaskID: t.ID, Version: t.Version, FinishedAt: time.Now(),
				Message: "refusing to downgrade from " + current + " to " + t.Version + " (--upgrade-allow-downgrade allows it on this node)"}
			err := s.persist(next)
			s.mu.Unlock()
			if err != nil {
				reply(w, 500, map[string]string{"error": "journal write failed"})
			} else {
				reply(w, 202, map[string]bool{"ok": true})
			}
			return
		}
		s.staging = true
		s.cleanup()
		s.mu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
		candidate, err := s.opts.prepare(ctx, s.opts.Trust, t)
		cancel()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.staging = false
		next := s.state
		if err != nil {
			next.Result = &Result{TaskID: t.ID, Version: t.Version, Message: err.Error(), FinishedAt: time.Now()}
		} else {
			next.Pending = &pending{Candidate: candidate, Previous: s.state.Active, Phase: "prepared", StartedAt: time.Now()}
		}
		if err = s.persist(next); err != nil {
			reply(w, 500, map[string]string{"error": "cannot persist staged upgrade"})
			return
		}
		reply(w, 202, map[string]bool{"ok": true})
	default:
		reply(w, 404, map[string]string{"error": "not found"})
	}
}
