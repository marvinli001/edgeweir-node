// Package childproc helps tests that run stand-in processes (a fake
// OpenResty, the test binary as a node) and wait for what those record.
// The waits end shortly before the go test -timeout deadline, not after a
// fixed time: on a loaded machine a process start alone can take seconds.
package childproc

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// UnignoreSIGHUP makes the processes a test starts receive SIGHUP. A test
// started with SIGHUP ignored (nohup) passes that on to its children, and a
// shell cannot trap a signal that was ignored when it started, so a fake
// OpenResty would never record a reload. Notify replaces an inherited
// SIG_IGN of SIGHUP with a handler (os/signal), and children start with
// the default action instead. The test process itself still drops SIGHUP.
// Call it from TestMain.
func UnignoreSIGHUP() {
	if signal.Ignored(syscall.SIGHUP) {
		signal.Notify(make(chan os.Signal, 1), syscall.SIGHUP)
	}
}

// Deadline is when a test stops waiting for its processes: a tenth of the
// remaining time before go test -timeout, so the test fails with its own
// message rather than the binary's timeout panic; a day from now with
// -timeout 0.
func Deadline(t *testing.T) time.Time {
	d, ok := t.Deadline()
	if !ok {
		return time.Now().Add(24 * time.Hour)
	}
	return d.Add(-time.Until(d) / 10)
}

// Context is t.Context() ending at Deadline(t).
func Context(t *testing.T) context.Context {
	ctx, cancel := context.WithDeadline(t.Context(), Deadline(t))
	t.Cleanup(cancel)
	return ctx
}

// Wait polls cond until it holds, failing the test at Deadline(t).
func Wait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := Deadline(t)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
