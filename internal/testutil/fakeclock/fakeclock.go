// Package fakeclock is a manual clock for tests of code that schedules
// with callbacks (healthcheck.Clock): time only moves with Advance.
package fakeclock

import (
	"slices"
	"sync"
	"time"
)

// Clock is a manual clock. The zero value is not usable; use New.
type Clock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*timer
}

type timer struct {
	at time.Time
	f  func()
}

// New returns a clock that reads start.
func New(start time.Time) *Clock { return &Clock{now: start} }

// Now returns the clock's time.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// AfterFunc arranges for f to run in its own goroutine once the clock has
// been advanced by d (a delay of 0 or less: at the next Advance). The
// returned function cancels it and reports whether it was still armed.
func (c *Clock) AfterFunc(d time.Duration, f func()) (stop func() bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &timer{at: c.now.Add(d), f: f}
	c.timers = append(c.timers, t)
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		i := slices.Index(c.timers, t)
		if i < 0 {
			return false
		}
		c.timers = slices.Delete(c.timers, i, i+1)
		return true
	}
}

// Advance moves the clock forward by d and starts the callbacks of the
// timers that are due, earliest first.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	var due []*timer
	c.timers = slices.DeleteFunc(c.timers, func(t *timer) bool {
		if t.at.After(c.now) {
			return false
		}
		due = append(due, t)
		return true
	})
	c.mu.Unlock()
	slices.SortStableFunc(due, func(a, b *timer) int { return a.at.Compare(b.at) })
	for _, t := range due {
		go t.f()
	}
}

// Armed returns the number of timers waiting to fire.
func (c *Clock) Armed() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

// Delays returns the remaining delay of every armed timer, shortest first.
func (c *Clock) Delays() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]time.Duration, 0, len(c.timers))
	for _, t := range c.timers {
		out = append(out, t.at.Sub(c.now))
	}
	slices.Sort(out)
	return out
}
