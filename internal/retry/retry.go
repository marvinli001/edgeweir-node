// Package retry calls an operation again after failures that may pass (a
// data plane that is still starting, a busy lock), with exponential backoff,
// until it succeeds, fails for good, its budget is spent or its context
// ends.
package retry

import (
	"context"
	"errors"
	"time"
)

// Policy is a retry schedule.
type Policy struct {
	// Budget is how long failures are retried: a failure once Budget has
	// passed since the first attempt is the last one.
	Budget time.Duration
	// Delay is the pause after the first failure; it doubles after every
	// further one, up to MaxDelay.
	Delay, MaxDelay time.Duration
	// Attempt bounds each attempt; 0 leaves that to the operation.
	Attempt time.Duration
}

type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// Permanent marks err as a failure another attempt would only repeat
// (nil stays nil).
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err}
}

// IsPermanent reports whether err, or an error it wraps, was marked by
// Permanent.
func IsPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p)
}

// Do calls fn until it returns nil or a Permanent error, until it fails
// once the budget has passed, or until ctx ends while Do waits for the next
// attempt. It returns nil, fn's last error (a permanent one still marked)
// or ctx.Err().
func Do(ctx context.Context, p Policy, fn func(context.Context) error) error {
	deadline := time.Now().Add(p.Budget)
	delay := p.Delay
	for {
		err := attempt(ctx, p.Attempt, fn)
		if err == nil || IsPermanent(err) || time.Now().After(deadline) {
			return err
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		delay = min(delay*2, p.MaxDelay)
	}
}

func attempt(ctx context.Context, timeout time.Duration, fn func(context.Context) error) error {
	if timeout <= 0 {
		return fn(ctx)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return fn(ctx)
}
