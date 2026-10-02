package upgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/engine"
)

// OpenResty under the supervisor (Options.Engine): the stable parent runs
// it for its children, so replacing the agent process (an upgrade, its
// trial, a restart) never restarts OpenResty, and its shared dicts (bans,
// CC state, statistics counters, rate limits) survive. A child uses it
// through the supervisor socket (RemoteEngine) when /capabilities offers
// "engine"; older children run OpenResty themselves. It is started on the
// first reload a child asks for, and stopped before a child of an older
// version starts (it may run OpenResty itself) and when the supervisor
// stops, after the child.

// supervisedEngine is the supervisor's OpenResty and its start count.
type supervisedEngine struct {
	mu     sync.Mutex
	eng    *engine.Nginx
	starts int
	cancel context.CancelFunc
	done   chan struct{}
}

// start runs a new engine instance; nginx itself starts on the first
// Reload.
func (s *Supervisor) startEngine() {
	if s.opts.Engine == nil {
		return
	}
	e := &s.engine
	eng := engine.New(*s.opts.Engine)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := eng.Run(ctx); err != nil {
			s.opts.Log.Error("OpenResty supervisor stopped", "err", err)
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-eng.Started():
				e.mu.Lock()
				e.starts++
				e.mu.Unlock()
			}
		}
	}()
	e.mu.Lock()
	e.eng, e.cancel, e.done = eng, cancel, done
	e.mu.Unlock()
}

// stopEngine stops OpenResty gracefully and waits for it.
func (s *Supervisor) stopEngine() {
	e := &s.engine
	e.mu.Lock()
	cancel, done := e.cancel, e.done
	e.eng, e.cancel, e.done = nil, nil, nil
	e.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// keepEngine reports whether OpenResty may keep running when the child of
// bundle from is replaced by one of bundle to: when to is not older (it
// uses the supervisor's OpenResty as well). An older or unknown version
// may run OpenResty itself, which needs the ports.
func (s *Supervisor) keepEngine(from, to Bundle) bool {
	version := func(b Bundle) string {
		if b.Dir == "" {
			return s.opts.Version
		}
		return b.Version
	}
	c, ok := compareVersions(version(to), version(from))
	return ok && c >= 0
}

// switchEngine stops OpenResty unless keepEngine(from, to), and starts a
// fresh instance for the next child.
func (s *Supervisor) switchEngine(from, to Bundle) {
	if s.opts.Engine == nil || s.keepEngine(from, to) {
		return
	}
	s.opts.Log.Info("stopping OpenResty: the next node version may run it itself", "version", to.Version)
	s.stopEngine()
	s.startEngine()
}

func (s *Supervisor) currentEngine() *engine.Nginx {
	s.engine.mu.Lock()
	defer s.engine.mu.Unlock()
	return s.engine.eng
}

// engineStatus is GET /engine/status.
type engineStatus struct {
	Running bool `json:"running"`
	// Starts counts the starts of OpenResty: a new value means its shared
	// dicts are empty.
	Starts int `json:"starts"`
}

// serveEngine answers /engine/* requests; false when the path is not one.
func (s *Supervisor) serveEngine(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/engine/status", "/engine/reload", "/engine/test":
	default:
		return false
	}
	eng := s.currentEngine()
	if eng == nil {
		reply(w, 404, map[string]string{"error": "the supervisor runs no OpenResty"})
		return true
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/engine/status":
		s.engine.mu.Lock()
		st := engineStatus{Running: eng.Running(), Starts: s.engine.starts}
		s.engine.mu.Unlock()
		reply(w, 200, st)
	case r.Method == http.MethodPost && r.URL.Path == "/engine/reload":
		if err := eng.Reload(r.Context()); err != nil {
			reply(w, 422, map[string]string{"error": err.Error()})
			return true
		}
		reply(w, 200, map[string]bool{"ok": true})
	case r.Method == http.MethodPost && r.URL.Path == "/engine/test":
		var in struct {
			Conf string `json:"conf"`
		}
		if !body(w, r, &in) {
			return true
		}
		if !filepath.IsAbs(in.Conf) {
			reply(w, 400, map[string]string{"error": "conf must be an absolute path"})
			return true
		}
		if err := eng.Test(r.Context(), in.Conf); err != nil {
			reply(w, 422, map[string]string{"error": err.Error()})
			return true
		}
		reply(w, 200, map[string]bool{"ok": true})
	default:
		reply(w, 405, map[string]string{"error": "method not allowed"})
	}
	return true
}

// engineCall posts to /engine/<op> and returns the supervisor's error text
// as the error.
func (c *Client) engineCall(ctx context.Context, op string, input any) error {
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://upgrade/engine/"+op, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		return nil
	}
	var out struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
	if out.Error == "" {
		out.Error = fmt.Sprintf("supervisor answered %d", resp.StatusCode)
	}
	return errors.New(out.Error)
}

// EngineStatus returns the state of the supervisor's OpenResty.
func (c *Client) EngineStatus(ctx context.Context) (running bool, starts int, err error) {
	var st engineStatus
	err = c.do(ctx, http.MethodGet, "/engine/status", nil, &st)
	return st.Running, st.Starts, err
}

// Engine reports whether the supervisor runs OpenResty for its children.
func (c *Client) Engine(ctx context.Context) bool {
	var out struct {
		Engine bool `json:"engine"`
	}
	return c.do(ctx, http.MethodGet, "/capabilities", nil, &out) == nil && out.Engine
}

// RemoteEngine is the agent's engine when the supervisor runs OpenResty:
// tests and reloads go through the supervisor socket, version and module
// probes run the binary locally. Run only watches for restarts.
type RemoteEngine struct {
	client  *Client
	local   *engine.Nginx
	started chan struct{}
	mu      sync.Mutex
	running bool
}

// NewRemoteEngine returns the engine for a child of a supervisor that
// runs OpenResty (Client.Engine); local is the same binary, for probes.
func NewRemoteEngine(socket string, local *engine.Nginx) *RemoteEngine {
	return &RemoteEngine{client: NewClient(socket), local: local, started: make(chan struct{}, 1)}
}

func (e *RemoteEngine) Version(ctx context.Context) (string, error) { return e.local.Version(ctx) }
func (e *RemoteEngine) ModuleFeatures(ctx context.Context) ([]string, error) {
	return e.local.ModuleFeatures(ctx)
}
func (e *RemoteEngine) Started() <-chan struct{} { return e.started }

// Test runs `nginx -t` in the supervisor.
func (e *RemoteEngine) Test(ctx context.Context, conf string) error {
	return e.client.engineCall(ctx, "test", map[string]string{"conf": conf})
}

// Reload makes the supervisor's OpenResty load the installed
// configuration, starting it when it does not run.
func (e *RemoteEngine) Reload(ctx context.Context) error {
	if err := e.client.engineCall(ctx, "reload", struct{}{}); err != nil {
		return fmt.Errorf("nginx reload failed: %w", err)
	}
	e.refresh(ctx)
	return nil
}

// Running reports what the supervisor said last.
func (e *RemoteEngine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

func (e *RemoteEngine) refresh(ctx context.Context) (int, bool) {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	running, starts, err := e.client.EngineStatus(cctx)
	if err != nil {
		return 0, false
	}
	e.mu.Lock()
	e.running = running
	e.mu.Unlock()
	return starts, true
}

// Run signals Started whenever the supervisor's OpenResty (re)started
// after the agent began watching, until ctx is done. OpenResty keeps
// running when the agent stops.
func (e *RemoteEngine) Run(ctx context.Context) error {
	last, known := e.refresh(ctx)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		starts, ok := e.refresh(ctx)
		if !ok {
			continue
		}
		if known && starts != last {
			select {
			case e.started <- struct{}{}:
			default:
			}
		}
		last, known = starts, true
	}
}
