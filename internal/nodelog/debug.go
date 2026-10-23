package nodelog

import (
	"slices"
	"sync"
	"time"
)

// Debug logs (feature debug-logs-v1): a Ring keeps what the process logged
// recently at every level (slog records from debug up, OpenResty's error
// log from debug up) in memory. Nothing leaves the node until the console
// asks for it with a DebugLogsTask; the agent then uploads the matching
// entries of its own ring and of the supervisor's (GET /debug-logs).
// Secrets are removed and sizes capped before an entry is kept, as for the
// collector; entries are neither folded nor rate limited, and the oldest
// make room when the ring is full.

// DebugFeature is the capability the agent reports while it keeps a ring.
const DebugFeature = "debug-logs-v1"

// LevelDebug is the level of debug records; only rings keep them.
const LevelDebug Level = "debug"

// Limits of a ring and of one upload (the console checks the upload's).
const (
	// DefaultDebugCapacity is the default number of entries of a ring.
	DefaultDebugCapacity = 5000
	// MaxDebugCapacity bounds the capacity a ring can be given.
	MaxDebugCapacity = 100000
	// debugMaxBytes bounds the estimated size of a ring's entries.
	debugMaxBytes = 4 << 20
	// MaxDebugUpload and MaxDebugUploadBytes bound one upload: the
	// newest matching entries are kept.
	MaxDebugUpload      = 10000
	MaxDebugUploadBytes = 4 << 20
)

// Ring is a bounded buffer of a process's recent log entries. A nil ring
// keeps nothing.
type Ring struct {
	mu          sync.Mutex
	buf         []Entry
	head, size  int
	bytes       int
	maxBytes    int
	overwritten uint64
}

// NewRing returns a ring of capacity entries (at most MaxDebugCapacity);
// nil for capacity 0 or less.
func NewRing(capacity int) *Ring {
	if capacity <= 0 {
		return nil
	}
	return &Ring{buf: make([]Entry, min(capacity, MaxDebugCapacity)), maxBytes: debugMaxBytes}
}

// Add keeps e, dropping the oldest entries when the ring is full.
// Secrets are removed first; entries without a known level or source are
// ignored. An event that is not one of the events becomes a field.
func (r *Ring) Add(e Entry) {
	if r == nil {
		return
	}
	if e.Event != "" && !IsEvent(e.Event) {
		fields := make(map[string]string, len(e.Fields)+1)
		for k, v := range e.Fields {
			fields[k] = v
		}
		fields[EventKey] = e.Event
		e.Fields, e.Event = fields, ""
	}
	e = sanitize(e)
	if _, ok := protoLevels[e.Level]; !ok {
		return
	}
	if _, ok := protoSources[e.Source]; !ok {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	size := e.size()
	r.mu.Lock()
	defer r.mu.Unlock()
	for r.size > 0 && (r.size == len(r.buf) || r.bytes+size > r.maxBytes) {
		r.bytes -= r.buf[r.head].size()
		r.buf[r.head] = Entry{}
		r.head = (r.head + 1) % len(r.buf)
		r.size--
		r.overwritten++
	}
	r.buf[(r.head+r.size)%len(r.buf)] = e
	r.size++
	r.bytes += size
}

// DebugFilter selects entries of a ring. Zero values select everything.
type DebugFilter struct {
	// Since is inclusive, Until exclusive.
	Since, Until time.Time
	Components   []string
	Sources      []Source
}

// Match reports whether e is selected.
func (f DebugFilter) Match(e Entry) bool {
	if !f.Since.IsZero() && e.Time.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !e.Time.Before(f.Until) {
		return false
	}
	if len(f.Components) > 0 && !slices.Contains(f.Components, e.Component) {
		return false
	}
	return len(f.Sources) == 0 || slices.Contains(f.Sources, e.Source)
}

// DebugSnapshot is what a ring holds that a filter selects.
type DebugSnapshot struct {
	// Oldest first, at most MaxDebugUpload entries and MaxDebugUploadBytes.
	Entries []Entry `json:"entries"`
	// Older selected entries were left out for those limits.
	Truncated bool `json:"truncated,omitempty"`
	// Oldest is the time of the oldest entry the ring held (zero when
	// none), Overwritten the entries it dropped for its capacity so far.
	Oldest      time.Time `json:"oldest"`
	Overwritten uint64    `json:"overwritten"`
}

// Snapshot returns the entries f selects, oldest first, within the upload
// limits.
func (r *Ring) Snapshot(f DebugFilter) DebugSnapshot {
	if r == nil {
		return DebugSnapshot{}
	}
	r.mu.Lock()
	var out DebugSnapshot
	if r.size > 0 {
		out.Oldest = r.buf[r.head].Time
	}
	out.Overwritten = r.overwritten
	for i := range r.size {
		if e := r.buf[(r.head+i)%len(r.buf)]; f.Match(e) {
			out.Entries = append(out.Entries, e)
		}
	}
	r.mu.Unlock()
	out.Entries, out.Truncated = LimitDebug(out.Entries)
	return out
}

// MergeDebug adds b's entries to a's in time order (stable: a's first for
// equal times) and applies the upload limits again. Oldest is the earlier
// of the two, Overwritten their sum.
func MergeDebug(a, b DebugSnapshot) DebugSnapshot {
	entries := append(append(make([]Entry, 0, len(a.Entries)+len(b.Entries)), a.Entries...), b.Entries...)
	slices.SortStableFunc(entries, func(x, y Entry) int { return x.Time.Compare(y.Time) })
	out := DebugSnapshot{Oldest: a.Oldest, Overwritten: a.Overwritten + b.Overwritten}
	if out.Oldest.IsZero() || (!b.Oldest.IsZero() && b.Oldest.Before(out.Oldest)) {
		out.Oldest = b.Oldest
	}
	var cut bool
	out.Entries, cut = LimitDebug(entries)
	out.Truncated = a.Truncated || b.Truncated || cut
	return out
}

// LimitDebug keeps the newest entries within MaxDebugUpload and
// MaxDebugUploadBytes (entries are oldest first), and reports whether any
// were left out.
func LimitDebug(entries []Entry) ([]Entry, bool) {
	total, start := 0, len(entries)
	for start > 0 && len(entries)-start < MaxDebugUpload {
		size := entries[start-1].size()
		if total+size > MaxDebugUploadBytes {
			break
		}
		total += size
		start--
	}
	return entries[start:], start > 0
}

// size estimates the encoded size of e.
func (e Entry) size() int {
	n := 48 + len(e.Component) + len(e.Message) + len(e.Event)
	for k, v := range e.Fields {
		n += 8 + len(k) + len(v)
	}
	return n
}
