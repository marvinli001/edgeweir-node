package retry

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"testing/synctest"
	"time"
)

var errBusy = errors.New("busy")

// failing returns an operation that fails with err until the call numbered
// succeedAt (never when 0) and records when each call began.
func failing(err error, succeedAt int, calls *[]time.Duration) func(context.Context) error {
	start := time.Now()
	return func(context.Context) error {
		*calls = append(*calls, time.Since(start))
		if len(*calls) == succeedAt {
			return nil
		}
		return err
	}
}

func ms(list ...int) []time.Duration {
	out := make([]time.Duration, len(list))
	for i, v := range list {
		out[i] = time.Duration(v) * time.Millisecond
	}
	return out
}

// TestDoBacksOffWithinBounds: the pause starts at Delay and doubles up to
// MaxDelay; a failure after the budget is the last attempt.
func TestDoBacksOffWithinBounds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls []time.Duration
		err := Do(t.Context(), Policy{Budget: 3 * time.Second, Delay: 100 * time.Millisecond, MaxDelay: time.Second},
			failing(errBusy, 0, &calls))
		if !errors.Is(err, errBusy) || IsPermanent(err) {
			t.Fatalf("err = %v, want the last failure", err)
		}
		if want := ms(0, 100, 300, 700, 1500, 2500, 3500); !slices.Equal(calls, want) {
			t.Fatalf("attempts at %v, want %v", calls, want)
		}
	})
}

func TestDoReturnsOnSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls []time.Duration
		if err := Do(t.Context(), Policy{Budget: time.Minute, Delay: 100 * time.Millisecond, MaxDelay: 2 * time.Second},
			failing(errBusy, 3, &calls)); err != nil {
			t.Fatal(err)
		}
		if want := ms(0, 100, 300); !slices.Equal(calls, want) {
			t.Fatalf("attempts at %v, want %v", calls, want)
		}
	})
}

// TestDoGivesUpOnAPermanentError: a failure marked permanent is returned
// at once, still marked and still wrapping the cause.
func TestDoGivesUpOnAPermanentError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls []time.Duration
		start := time.Now()
		err := Do(t.Context(), Policy{Budget: time.Minute, Delay: 100 * time.Millisecond, MaxDelay: 2 * time.Second},
			func(ctx context.Context) error {
				calls = append(calls, time.Since(start))
				if len(calls) == 2 {
					return fmt.Errorf("put: %w", Permanent(errBusy))
				}
				return errBusy
			})
		if !IsPermanent(err) || !errors.Is(err, errBusy) || err.Error() != "put: busy" {
			t.Fatalf("err = %v", err)
		}
		if want := ms(0, 100); !slices.Equal(calls, want) {
			t.Fatalf("attempts at %v, want %v", calls, want)
		}
	})
}

// TestDoStopsWhenTheContextEnds: an end of the context while Do waits
// returns ctx.Err() at once.
func TestDoStopsWhenTheContextEnds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		start := time.Now()
		go func() {
			time.Sleep(250 * time.Millisecond)
			cancel()
		}()
		var calls []time.Duration
		err := Do(ctx, Policy{Budget: time.Minute, Delay: 100 * time.Millisecond, MaxDelay: 2 * time.Second},
			failing(errBusy, 0, &calls))
		if err != context.Canceled {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if since := time.Since(start); since != 250*time.Millisecond {
			t.Fatalf("returned after %v, want 250ms", since)
		}
		if want := ms(0, 100); !slices.Equal(calls, want) {
			t.Fatalf("attempts at %v, want %v", calls, want)
		}
	})
}

// TestDoBoundsEachAttempt: Attempt gives each call a deadline of its own;
// without it the call gets ctx as it is.
func TestDoBoundsEachAttempt(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		err := Do(t.Context(), Policy{Budget: time.Second, Delay: 100 * time.Millisecond, MaxDelay: 2 * time.Second, Attempt: 2 * time.Second},
			func(ctx context.Context) error {
				<-ctx.Done()
				return ctx.Err()
			})
		if err != context.DeadlineExceeded || time.Since(start) != 2*time.Second {
			t.Fatalf("err = %v after %v, want the attempt's deadline after 2s", err, time.Since(start))
		}
		if t.Context().Err() != nil {
			t.Fatal("the attempt's deadline ended the caller's context")
		}
		err = Do(t.Context(), Policy{}, func(ctx context.Context) error {
			if _, ok := ctx.Deadline(); ok {
				return errors.New("deadline without Attempt")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestPermanent(t *testing.T) {
	if Permanent(nil) != nil {
		t.Fatal("Permanent(nil) is not nil")
	}
	if IsPermanent(errBusy) || IsPermanent(nil) {
		t.Fatal("unmarked error reported permanent")
	}
	if err := fmt.Errorf("wrapped: %w", Permanent(errBusy)); !IsPermanent(err) || !errors.Is(err, errBusy) {
		t.Fatalf("%v", err)
	}
}
