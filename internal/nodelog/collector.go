package nodelog

import (
	"regexp"
	"sync"
	"time"
)

// Defaults of a Collector.
const (
	// DefaultCapacity is the number of entries a collector keeps until
	// they are read; beyond it the oldest go (counted as overflow).
	DefaultCapacity = 2000
	// keepPerWindow is the number of entries of one signature kept in a
	// window; the rest are folded into one entry when it closes.
	keepPerWindow = 3
	// maxSignatures bounds the folding state; entries of new signatures
	// beyond it are only rate limited.
	maxSignatures = 4096
)

// foldWindows are the lengths of successive folding windows of one
// signature: each window that folded entries makes the next one longer.
var foldWindows = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour}

// Rate limits per class of source: the processes' own records, and
// OpenResty's error log (one line per failing request under load).
type rate struct {
	perSecond float64
	burst     float64
}

var (
	ownRate    = rate{perSecond: 5, burst: 50}
	engineRate = rate{perSecond: 10, burst: 100}
)

// Options configure a Collector.
type Options struct {
	// Capacity of the buffer (default DefaultCapacity).
	Capacity int
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// Collector buffers entries for upload. Entries are numbered from 1 in
// the order they are kept; the numbers survive reads, so a reader can ask
// for the entries after the last one it has.
type Collector struct {
	mu       sync.Mutex
	now      func() time.Time
	buf      []Entry
	head     int    // index of the oldest entry in buf
	size     int    // entries in buf
	first    uint64 // number of the oldest entry (when size > 0)
	next     uint64 // number of the next entry
	buckets  map[bool]*bucket
	sigs     map[string]*signature
	limited  uint64
	overflow uint64
}

// NewCollector returns an empty collector.
func NewCollector(opts Options) *Collector {
	if opts.Capacity <= 0 {
		opts.Capacity = DefaultCapacity
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Collector{
		now:   opts.Now,
		buf:   make([]Entry, opts.Capacity),
		next:  1,
		first: 1,
		buckets: map[bool]*bucket{
			false: {rate: ownRate, tokens: ownRate.burst},
			true:  {rate: engineRate, tokens: engineRate.burst},
		},
		sigs: map[string]*signature{},
	}
}

// Add keeps e unless its rate limit is exhausted or it is folded into an
// entry like it. Secrets are removed first; invalid entries are ignored.
func (c *Collector) Add(e Entry) {
	if c == nil {
		return
	}
	e = sanitize(e)
	if !e.valid() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if e.Time.IsZero() {
		e.Time = now
	}
	c.tick(now)
	key := signatureOf(e)
	s := c.sigs[key]
	if s != nil && !s.closed {
		if s.kept >= keepPerWindow {
			s.folded++
			s.last = e
			return
		}
		s.kept++
	} else {
		if s == nil {
			if len(c.sigs) >= maxSignatures {
				c.limit(e, now)
				return
			}
			s = &signature{}
			c.sigs[key] = s
		}
		s.open(now)
	}
	c.limit(e, now)
}

// limit keeps e when the bucket of its source has a token.
func (c *Collector) limit(e Entry, now time.Time) {
	if !c.buckets[e.Source == SourceNginx || e.Source == SourceLua].take(now) {
		c.limited++
		return
	}
	c.push(e)
}

func (c *Collector) push(e Entry) {
	if c.size == len(c.buf) {
		c.buf[c.head] = Entry{}
		c.head = (c.head + 1) % len(c.buf)
		c.size--
		c.first++
		c.overflow++
	}
	if c.size == 0 {
		c.first = c.next
	}
	c.buf[(c.head+c.size)%len(c.buf)] = e
	c.size++
	c.next++
}

// tick closes the folding windows that ended: one that folded entries
// adds them as one entry (not rate limited: at most one per signature and
// window) and makes the next window longer.
func (c *Collector) tick(now time.Time) {
	for key, s := range c.sigs {
		end := s.start.Add(s.length)
		if !s.closed && !now.Before(end) {
			if s.folded > 0 {
				e := s.last
				e.Repeated = s.folded
				c.push(e)
				s.folded, s.last = 0, Entry{}
				s.streak++
			} else {
				s.streak = 0
			}
			s.closed = true
		}
		// A quiet signature starts over at the shortest window.
		if s.closed && (s.streak == 0 || !now.Before(end.Add(s.length))) {
			delete(c.sigs, key)
		}
	}
}

// Read returns at most max entries numbered after after (from the oldest
// kept when those are gone), and the number of the last one returned
// (after when none). Folding windows that ended are closed first.
func (c *Collector) Read(after uint64, max int) ([]Entry, uint64) {
	if c == nil {
		return nil, after
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tick(c.now())
	if c.size == 0 || after >= c.next-1 || max <= 0 {
		return nil, after
	}
	start := uint64(0)
	if after >= c.first {
		start = after - c.first + 1
	}
	n := min(uint64(c.size)-start, uint64(max))
	out := make([]Entry, 0, n)
	for i := start; i < start+n; i++ {
		out = append(out, c.buf[(c.head+int(i))%len(c.buf)])
	}
	return out, c.first + start + n - 1
}

// Discard drops the entries numbered up to upto.
func (c *Collector) Discard(upto uint64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.size > 0 && c.first <= upto {
		c.buf[c.head] = Entry{}
		c.head = (c.head + 1) % len(c.buf)
		c.size--
		c.first++
	}
}

// Take returns and drops at most max of the oldest entries.
func (c *Collector) Take(max int) []Entry {
	entries, last := c.Read(0, max)
	if len(entries) > 0 {
		c.Discard(last)
	}
	return entries
}

// Dropped returns the entries dropped so far: over the rate limits, and
// for the buffer's capacity.
func (c *Collector) Dropped() (rateLimited, overflow uint64) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.limited, c.overflow
}

// signature is the folding state of entries alike.
type signature struct {
	start  time.Time
	length time.Duration
	kept   int
	folded uint32
	last   Entry
	streak int
	closed bool
}

func (s *signature) open(now time.Time) {
	s.start, s.length = now, foldWindows[min(s.streak, len(foldWindows)-1)]
	s.kept, s.folded, s.closed = 1, 0, false
}

var (
	uuidPattern  = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	digitPattern = regexp.MustCompile(`[0-9]+`)
)

// signatureOf groups entries alike: same source, level, component, event
// and message once ids and numbers are left out (OpenResty's request
// context is in the fields, not the message).
func signatureOf(e Entry) string {
	m := digitPattern.ReplaceAllString(uuidPattern.ReplaceAllString(e.Message, "#"), "0")
	return string(e.Source) + "\x00" + string(e.Level) + "\x00" + e.Component + "\x00" + e.Event + "\x00" + m
}

// bucket is a token bucket.
type bucket struct {
	rate   rate
	tokens float64
	at     time.Time
}

func (b *bucket) take(now time.Time) bool {
	if !b.at.IsZero() {
		b.tokens = min(b.rate.burst, b.tokens+now.Sub(b.at).Seconds()*b.rate.perSecond)
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
