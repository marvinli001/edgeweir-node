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
	// Purge markers by identity (site, type, host, path, query) -> epoch.
	markers    map[string]dataplane.PurgeMarker
	purgeCalls []string
	health     []dataplane.OriginHealth
	failPurge  int
	// purgeCapacity > 0 answers 507 to a purge call that would leave more
	// markers installed (a full shared dict).
	purgeCapacity int
	// events records successful writes in order: "sites", "purge:PUT", "purge:POST".
	events []string
}

var (
	registryMu sync.Mutex
	registry   = map[string]*Server{}
)

// Lookup returns the server listening on socket (nil if none).
func Lookup(socket string) *Server {
	registryMu.Lock()
	defer registryMu.Unlock()
	return registry[socket]
}

// LoadConf simulates nginx loading a configuration with id confID: the
// status reports it from now on (it survives Restart, like the file).
func (s *Server) LoadConf(confID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.ConfID = confID
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
	registryMu.Lock()
	registry[s.Socket] = s
	registryMu.Unlock()
	tb.Cleanup(func() {
		_ = srv.Close()
		registryMu.Lock()
		delete(registry, s.Socket)
		registryMu.Unlock()
	})
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
		s.events = append(s.events, "sites")
		s.status = dataplane.Status{
			ConfID:      s.status.ConfID,
			Version:     s.status.Version + 1,
			Revision:    t.Revision,
			ContentHash: t.ContentHash,
			SiteCount:   len(t.Sites),
			CDNID:       t.CDNID,
			Purge:       s.status.Purge,
		}
		reply(w, 200, s.status)
	case r.URL.Path == "/v1/purge" && (r.Method == http.MethodPut || r.Method == http.MethodPost):
		if s.failPurge > 0 {
			s.failPurge--
			reply(w, 500, map[string]string{"error": "injected failure"})
			return
		}
		var t dataplane.PurgeTable
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		next := map[string]dataplane.PurgeMarker{}
		if r.Method == http.MethodPost {
			for k, m := range s.markers {
				next[k] = m
			}
		}
		for _, m := range t.Markers {
			k := markerKey(m)
			if old, ok := next[k]; !ok || old.Epoch < m.Epoch {
				next[k] = m
			}
		}
		if s.purgeCapacity > 0 && len(next) > s.purgeCapacity {
			reply(w, 507, map[string]string{"error": "shared dict edgeweir_purge: no memory"})
			return
		}
		s.markers = next
		s.purgeCalls = append(s.purgeCalls, r.Method)
		s.events = append(s.events, "purge:"+r.Method)
		s.status.Purge = dataplane.PurgeStatus{ID: t.ID, Entries: len(s.markers), Markers: len(s.markers)}
		reply(w, 200, s.status.Purge)
	case r.URL.Path == "/v1/origins/health" && r.Method == http.MethodGet:
		if len(s.health) == 0 {
			reply(w, 200, map[string]any{"origins": map[string]any{}})
			return
		}
		reply(w, 200, map[string]any{"origins": s.health})
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
	s.status = dataplane.Status{ConfID: s.status.ConfID}
	s.table = nil
	s.markers = nil
}

func markerKey(m dataplane.PurgeMarker) string {
	return m.SiteID + "\x00" + m.Type + "\x00" + m.Host + "\x00" + m.Path + "\x00" + m.Query
}

// Markers returns the installed purge markers.
func (s *Server) Markers() []dataplane.PurgeMarker {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]dataplane.PurgeMarker, 0, len(s.markers))
	for _, m := range s.markers {
		out = append(out, m)
	}
	slices.SortFunc(out, func(a, b dataplane.PurgeMarker) int {
		switch {
		case markerKey(a) < markerKey(b):
			return -1
		case markerKey(a) > markerKey(b):
			return 1
		}
		return 0
	})
	return out
}

// Events returns the successful writes in order ("sites", "purge:PUT", "purge:POST").
func (s *Server) Events() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.events)
}

// PurgeCalls returns the methods of the purge calls received (PUT / POST).
func (s *Server) PurgeCalls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.purgeCalls)
}

// SetOriginHealth sets what GET /v1/origins/health returns.
func (s *Server) SetOriginHealth(h ...dataplane.OriginHealth) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.health = h
}

// SetPurgeCapacity makes purge calls that would leave more than n markers
// installed fail with 507 (0: unlimited).
func (s *Server) SetPurgeCapacity(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeCapacity = n
}

// FailNextPurges makes the next n purge calls fail.
func (s *Server) FailNextPurges(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failPurge = n
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
