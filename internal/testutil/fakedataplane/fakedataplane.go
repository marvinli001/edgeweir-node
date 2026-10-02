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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
)

// Server is a fake control API.
type Server struct {
	logs   []map[string]any
	Socket string

	mu             sync.Mutex
	status         dataplane.Status
	table          *dataplane.SiteTable
	pushes         []*dataplane.SiteTable
	pending        []dataplane.MinuteStats
	failPut        int
	rejectRevision uint64
	// tooLarge answers 507 to the site table of that revision; putCalls
	// counts PUT /v1/sites requests.
	tooLarge uint64
	putCalls int
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

	// Bans (lua/edgeweir/bans.lua): console bans by key, their sequence,
	// the capacity (0: unlimited) and the own bans waiting to be drained.
	bans        map[string]dataplane.Ban
	banSeq      uint64
	banCapacity int
	unapplied   map[string]bool
	autoEvicted uint64
	autoBans    []dataplane.AutoBan
	released    []dataplane.OwnBanRelease
	failRelease int
	banCalls    []string
	failBans    int

	// Challenges (lua/edgeweir/challenge.lua) and CC (lua/edgeweir/cc.lua).
	challengeKeys  *dataplane.ChallengeKeys
	captchas       *dataplane.CaptchaPool
	keyPuts        []dataplane.ChallengeKeys
	captchaPuts    int
	security       dataplane.SecurityStatus
	securityEvents []dataplane.SecurityEvent

	// Active health marks (PUT /v1/origins/active, lua/edgeweir/health.lua).
	active     *dataplane.ActiveHealth
	activePuts int

	// Layer-4 applications (/v1/l4, lua/edgeweir/l4.lua): the table, its
	// status, every push and the statistics the next drain returns.
	l4        *dataplane.L4Table
	l4Status  dataplane.L4Status
	l4Pushes  []*dataplane.L4Table
	l4Pending []dataplane.L4MinuteStats
	failL4    int
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

// SetConnections sets the connections_active the status reports.
func (s *Server) SetConnections(n uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status.ConnectionsActive = n
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
	case r.URL.Path == "/v1/l4" && r.Method == http.MethodGet:
		reply(w, 200, s.l4Status)
	case r.URL.Path == "/v1/l4" && r.Method == http.MethodPut:
		if s.failL4 > 0 {
			s.failL4--
			reply(w, 503, map[string]string{"error": "injected failure"})
			return
		}
		var t dataplane.L4Table
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil || t.Apps == nil || t.IPLists == nil {
			reply(w, 400, map[string]string{"error": "invalid layer-4 table"})
			return
		}
		s.l4 = &t
		s.l4Pushes = append(s.l4Pushes, &t)
		s.events = append(s.events, "l4")
		s.l4Status = dataplane.L4Status{Version: s.l4Status.Version + 1, Revision: t.Revision, ContentHash: t.ContentHash, Apps: len(t.Apps)}
		reply(w, 200, s.l4Status)
	case r.URL.Path == "/v1/l4/stats/drain" && r.Method == http.MethodPost:
		if s.failL4 > 0 {
			s.failL4--
			reply(w, 503, map[string]string{"error": "injected failure"})
			return
		}
		pending := s.l4Pending
		if pending == nil {
			pending = []dataplane.L4MinuteStats{}
		}
		s.l4Pending = nil
		reply(w, 200, map[string]any{"stats": pending})
	case r.URL.Path == "/v1/status" && r.Method == http.MethodGet:
		reply(w, 200, s.status)
	case r.URL.Path == "/v1/sites" && r.Method == http.MethodPut:
		s.putCalls++
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
		if t.Revision == s.rejectRevision && s.rejectRevision != 0 {
			reply(w, 400, map[string]string{"error": "injected revision rejection"})
			return
		}
		if t.Revision == s.tooLarge && s.tooLarge != 0 {
			reply(w, 507, map[string]string{"error": "shared dict edgeweir_sites: no memory"})
			return
		}
		s.table = &t
		s.pushes = append(s.pushes, &t)
		s.events = append(s.events, "sites")
		s.status = dataplane.Status{
			ConfID:            s.status.ConfID,
			ConnectionsActive: s.status.ConnectionsActive,
			Version:           s.status.Version + 1,
			Revision:          t.Revision,
			ContentHash:       t.ContentHash,
			SiteCount:         len(t.Sites),
			CDNID:             t.CDNID,
			Purge:             s.status.Purge,
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
	case r.URL.Path == "/v1/bans" && r.Method == http.MethodGet:
		st := s.banStatusLocked()
		if r.URL.Query().Get("list") == "1" {
			list := []dataplane.BanEntry{}
			for _, b := range s.bans {
				list = append(list, dataplane.BanEntry{ID: b.ID, Kind: b.Kind, CIDR: b.CIDR, Scope: b.Scope, SiteID: b.SiteID, ExpiresAt: b.ExpiresAt})
			}
			slices.SortFunc(list, func(a, b dataplane.BanEntry) int { return strings.Compare(a.ID, b.ID) })
			st["bans"] = list
		}
		reply(w, 200, st)
	case r.URL.Path == "/v1/bans" && (r.Method == http.MethodPut || r.Method == http.MethodPost):
		s.serveBansLocked(w, r)
	case r.URL.Path == "/v1/bans/release" && r.Method == http.MethodPost:
		if s.failRelease > 0 {
			s.failRelease--
			reply(w, 409, map[string]string{"error": "another ban update is in progress"})
			return
		}
		var body struct {
			Bans []dataplane.OwnBanRelease `json:"bans"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		s.released = append(s.released, body.Bans...)
		reply(w, 200, map[string]int{"released": len(body.Bans)})
	case r.URL.Path == "/v1/bans/auto/drain" && r.Method == http.MethodPost:
		out := s.autoBans
		if len(out) > 1000 {
			out = out[:1000]
		}
		s.autoBans = slices.Clone(s.autoBans[len(out):])
		if len(out) == 0 {
			reply(w, 200, map[string]any{"bans": map[string]any{}})
			return
		}
		reply(w, 200, map[string]any{"bans": out})
	case r.URL.Path == "/v1/challenge" && r.Method == http.MethodGet:
		reply(w, 200, s.challengeStatusLocked())
	case r.URL.Path == "/v1/challenge/keys" && r.Method == http.MethodPut:
		var k dataplane.ChallengeKeys
		if err := json.NewDecoder(r.Body).Decode(&k); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		s.challengeKeys = &k
		s.keyPuts = append(s.keyPuts, k)
		reply(w, 200, s.challengeStatusLocked())
	case r.URL.Path == "/v1/challenge/captchas" && r.Method == http.MethodPut:
		var p dataplane.CaptchaPool
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		s.captchas = &p
		s.captchaPuts++
		reply(w, 200, s.challengeStatusLocked())
	case r.URL.Path == "/v1/security" && r.Method == http.MethodGet:
		st := map[string]any{"sites": map[string]any{}, "pending_events": len(s.securityEvents)}
		if len(s.security.Sites) > 0 {
			st["sites"] = s.security.Sites
		}
		reply(w, 200, st)
	case r.URL.Path == "/v1/security/drain" && r.Method == http.MethodPost:
		out := s.securityEvents[:min(len(s.securityEvents), 1000)]
		s.securityEvents = slices.Clone(s.securityEvents[len(out):])
		if len(out) == 0 {
			reply(w, 200, map[string]any{"events": map[string]any{}})
			return
		}
		reply(w, 200, map[string]any{"events": out})
	case r.URL.Path == "/v1/origins/active" && r.Method == http.MethodPut:
		var a dataplane.ActiveHealth
		if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if a.TTL < 1 || a.TTL > 86400 {
			reply(w, 400, map[string]string{"error": "ttl must be 1-86400 seconds"})
			return
		}
		seen := map[dataplane.ActiveOrigin]bool{}
		for _, o := range a.Down {
			if !validID(o.SiteID) || !validID(o.OriginID) {
				reply(w, 400, map[string]string{"error": "invalid origin"})
				return
			}
			seen[o] = true
		}
		s.active = &a
		s.activePuts++
		reply(w, 200, dataplane.ActiveHealthStatus{Down: len(seen)})
	case r.URL.Path == "/v1/origins/health" && r.Method == http.MethodGet:
		if len(s.health) == 0 {
			reply(w, 200, map[string]any{"origins": map[string]any{}})
			return
		}
		reply(w, 200, map[string]any{"origins": s.health})
	case r.URL.Path == "/v1/logs/drain" && r.Method == http.MethodPost:
		out := s.logs
		s.logs = nil
		reply(w, 200, map[string]any{"logs": out})
	case r.URL.Path == "/v1/stats/drain" && r.Method == http.MethodPost:
		var body struct {
			All bool `json:"all"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.All {
			s.events = append(s.events, "stats:drain-all")
		}
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

func banKey(b dataplane.Ban) string { return b.Scope + "|" + b.SiteID + "|" + b.CIDR }

func (s *Server) banStatusLocked() map[string]any {
	ids := make([]string, 0, len(s.unapplied))
	for id := range s.unapplied {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	n := len(ids)
	if len(ids) > 100 {
		ids = ids[:100]
	}
	st := map[string]any{
		"sequence": strconv.FormatUint(s.banSeq, 10), "entries": len(s.bans), "capacity": s.banCapacity,
		"unapplied": n, "unapplied_ids": ids, "auto_evicted": s.autoEvicted, "pending_reports": len(s.autoBans),
	}
	if len(ids) == 0 {
		st["unapplied_ids"] = map[string]any{} // like lua-cjson without array_mt
	}
	return st
}

// storeBanLocked writes one ban, or records it as unapplied (manual) or
// evicted (automatic) when the capacity is reached.
func (s *Server) storeBanLocked(b dataplane.Ban) {
	k := banKey(b)
	if _, ok := s.bans[k]; !ok && s.banCapacity > 0 && len(s.bans) >= s.banCapacity {
		if b.Kind == "m" {
			s.unapplied[b.ID] = true
		} else {
			s.autoEvicted++
		}
		return
	}
	delete(s.unapplied, b.ID)
	s.bans[k] = b
}

func (s *Server) serveBansLocked(w http.ResponseWriter, r *http.Request) {
	if s.failBans > 0 {
		s.failBans--
		reply(w, 500, map[string]string{"error": "injected failure"})
		return
	}
	if s.bans == nil {
		s.bans, s.unapplied = map[string]dataplane.Ban{}, map[string]bool{}
	}
	if r.Method == http.MethodPut {
		var t dataplane.BanTable
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		s.bans, s.unapplied = map[string]dataplane.Ban{}, map[string]bool{}
		for _, b := range t.Bans {
			s.storeBanLocked(b)
		}
		s.banSeq = t.Sequence
	} else {
		var d dataplane.BanDelta
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		if d.Base != s.banSeq {
			reply(w, 409, map[string]string{"error": "sequence mismatch: the data plane holds " + strconv.FormatUint(s.banSeq, 10)})
			return
		}
		for _, b := range d.Remove {
			delete(s.unapplied, b.ID)
			if cur, ok := s.bans[banKey(b)]; ok && cur.ID == b.ID {
				delete(s.bans, banKey(b))
			}
		}
		for _, b := range d.Upsert {
			s.storeBanLocked(b)
		}
		s.banSeq = d.Sequence
	}
	s.banCalls = append(s.banCalls, r.Method)
	s.events = append(s.events, "bans:"+r.Method)
	reply(w, 200, s.banStatusLocked())
}

// Bans returns the console bans held, sorted by scope, site and CIDR.
func (s *Server) Bans() []dataplane.Ban {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]dataplane.Ban, 0, len(s.bans))
	for _, b := range s.bans {
		out = append(out, b)
	}
	slices.SortFunc(out, func(a, b dataplane.Ban) int { return strings.Compare(banKey(a), banKey(b)) })
	return out
}

// BanSequence returns the sequence of the console bans held.
func (s *Server) BanSequence() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.banSeq
}

// BanCalls returns the methods of the ban writes received (PUT / POST).
func (s *Server) BanCalls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.banCalls)
}

// SetBanCapacity limits the bans held (0: unlimited).
func (s *Server) SetBanCapacity(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.banCapacity = n
}

// FailNextBans makes the next n ban writes fail.
func (s *Server) FailNextBans(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failBans = n
}

// Released returns every own ban the agent asked to delete
// (POST /v1/bans/release).
func (s *Server) Released() []dataplane.OwnBanRelease {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.released)
}

// FailNextReleases makes the next n POST /v1/bans/release fail.
func (s *Server) FailNextReleases(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failRelease = n
}

// AddAutoBans queues own bans for the next drains.
func (s *Server) AddAutoBans(b ...dataplane.AutoBan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.autoBans = append(s.autoBans, b...)
}

// challengeStatusLocked mimics GET /v1/challenge (an empty key list is
// encoded as {}, like lua-cjson without array metatables).
func (s *Server) challengeStatusLocked() map[string]any {
	st := map[string]any{"keys_id": "", "current": "", "keys": map[string]any{}, "captchas": 0, "captchas_id": ""}
	if k := s.challengeKeys; k != nil {
		ids := []string{}
		for _, key := range k.Keys {
			ids = append(ids, key.ID)
		}
		st["keys_id"], st["current"] = k.ID, k.Current
		if len(ids) > 0 {
			st["keys"] = ids
		}
	}
	if p := s.captchas; p != nil {
		st["captchas"], st["captchas_id"] = len(p.Images), p.ID
	}
	return st
}

// ChallengeKeys returns the installed challenge keys (nil: none).
func (s *Server) ChallengeKeys() *dataplane.ChallengeKeys {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.challengeKeys
}

// Captchas returns the installed captcha pool and how many pools were put.
func (s *Server) Captchas() (*dataplane.CaptchaPool, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.captchas, s.captchaPuts
}

// KeyPuts counts the PUT /v1/challenge/keys calls.
func (s *Server) KeyPuts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.keyPuts)
}

// KeySets returns the key sets put so far, oldest first.
func (s *Server) KeySets() []dataplane.ChallengeKeys {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.keyPuts)
}

// SetSecurity sets the sites GET /v1/security reports.
func (s *Server) SetSecurity(sites ...dataplane.SecuritySite) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.security.Sites = sites
}

// AddSecurityEvents queues CC events for the next drains.
func (s *Server) AddSecurityEvents(e ...dataplane.SecurityEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.securityEvents = append(s.securityEvents, e...)
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
	s.bans, s.unapplied, s.banSeq, s.autoBans, s.autoEvicted = nil, nil, 0, nil, 0
	s.challengeKeys, s.captchas, s.securityEvents = nil, nil, nil
	s.active = nil
	s.l4, s.l4Status, s.l4Pending = nil, dataplane.L4Status{}, nil
}

// L4 returns the installed layer-4 table (nil before the first push and
// after Restart).
func (s *Server) L4() *dataplane.L4Table {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.l4
}

// L4Pushes returns every layer-4 table received.
func (s *Server) L4Pushes() []*dataplane.L4Table {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.l4Pushes)
}

// AddL4Stats queues buckets returned by the next layer-4 drain.
func (s *Server) AddL4Stats(m ...dataplane.L4MinuteStats) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.l4Pending = append(s.l4Pending, m...)
}

// FailNextL4 answers the next n layer-4 calls with 503.
func (s *Server) FailNextL4(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failL4 = n
}

// Active returns the installed active health marks (nil before the first
// push and after Restart) and the number of pushes.
func (s *Server) Active() (*dataplane.ActiveHealth, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return nil, s.activePuts
	}
	a := *s.active
	a.Down = slices.Clone(a.Down)
	return &a, s.activePuts
}

// validID mirrors the data plane's id check ([A-Za-z0-9_-], 1-128).
func validID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	return strings.Trim(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") == ""
}

func markerKey(m dataplane.PurgeMarker) string {
	return m.SiteID + "\x00" + m.Type + "\x00" + m.Host + "\x00" + m.Path + "\x00" + m.Query + "\x00" + strings.ToLower(m.Tag)
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

// TooLarge makes the site table of revision not fit (507).
func (s *Server) TooLarge(revision uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tooLarge = revision
}

// PutCalls counts PUT /v1/sites requests.
func (s *Server) PutCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putCalls
}

func (s *Server) RejectRevision(revision uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rejectRevision = revision
}

// AddStats queues buckets returned by the next drain.
func (s *Server) AddStats(m ...dataplane.MinuteStats) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = append(s.pending, m...)
}

// AddLogEntry queues a raw sampled access log entry (JSON fields).
func (s *Server) AddLogEntry(entry map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = append(s.logs, entry)
}

func (s *Server) AddLog(site string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs = append(s.logs, map[string]any{"site_id": site, "time": float64(time.Now().UnixMilli()) / 1000, "client_ip": "192.0.2.1", "method": "GET", "path": "/hello", "status": 200, "sample_rate": 10000})
}
