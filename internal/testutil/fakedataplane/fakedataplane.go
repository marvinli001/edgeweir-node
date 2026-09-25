// Package fakedataplane serves an in-memory imitation of the Lua control API
// (lua/edgeweir/control.lua) on a unix socket, for Go tests.
package fakedataplane

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/edgeweir/edgeweir-node/internal/dataplane"
)

// Server is a fake control API.
type Server struct {
	Socket string

	mu      sync.Mutex
	status  dataplane.Status
	table   *dataplane.SiteTable
	pushes  []*dataplane.SiteTable
	pending []dataplane.MinuteStats
	failPut int
}

// Start listens on a new unix socket in a short temporary directory (unix
// socket paths are limited to ~104 bytes on macOS) and stops when the test
// ends.
func Start(tb testing.TB) *Server {
	tb.Helper()
	dir, err := os.MkdirTemp("", "ewdp")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = os.RemoveAll(dir) })
	s := &Server{Socket: filepath.Join(dir, "control.sock")}
	l, err := net.Listen("unix", s.Socket)
	if err != nil {
		tb.Fatal(err)
	}
	srv := &http.Server{Handler: s}
	go func() { _ = srv.Serve(l) }()
	tb.Cleanup(func() { _ = srv.Close() })
	return s
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ServeHTTP implements the control API.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.URL.Path == "/v1/health":
		reply(w, 200, map[string]string{"status": "ok"})
	case r.URL.Path == "/v1/status" && r.Method == http.MethodGet:
		reply(w, 200, s.status)
	case r.URL.Path == "/v1/sites" && r.Method == http.MethodPut:
		if s.failPut > 0 {
			s.failPut--
			reply(w, 500, map[string]string{"error": "injected failure"})
			return
		}
		body, _ := io.ReadAll(r.Body)
		var t dataplane.SiteTable
		if err := json.Unmarshal(body, &t); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		s.table = &t
		s.pushes = append(s.pushes, &t)
		s.status = dataplane.Status{
			Version:     s.status.Version + 1,
			Revision:    t.Revision,
			ContentHash: t.ContentHash,
			SiteCount:   len(t.Sites),
		}
		reply(w, 200, s.status)
	case r.URL.Path == "/v1/stats/drain" && r.Method == http.MethodPost:
		out := s.pending
		s.pending = nil
		if len(out) == 0 {
			// Mimic lua-cjson encoding an empty table as an object.
			reply(w, 200, map[string]any{"stats": map[string]any{}})
			return
		}
		reply(w, 200, map[string]any{"stats": out})
	default:
		reply(w, 404, map[string]string{"error": "not found"})
	}
}

// Table returns the currently installed site table.
func (s *Server) Table() *dataplane.SiteTable {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.table
}

// Pushes returns every table received.
func (s *Server) Pushes() []*dataplane.SiteTable {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.pushes)
}

// Restart simulates an nginx restart: the shared dicts are empty again.
func (s *Server) Restart() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = dataplane.Status{}
	s.table = nil
}

// FailNextPuts makes the next n PUT /v1/sites calls fail.
func (s *Server) FailNextPuts(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failPut = n
}

// AddStats queues buckets returned by the next drain.
func (s *Server) AddStats(m ...dataplane.MinuteStats) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = append(s.pending, m...)
}
