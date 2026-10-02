package agent

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/retry"
)

// TestRetryWriteGivesUpOnRefusals: every data plane write treats an
// invalid document (400), one too large to send (413) and one the store
// cannot hold (507) as final, wrapped or not; a busy lock (409), other
// errors and a socket that is not there yet are retried for PushTimeout
// (100ms doubling to 2s: attempts at 0, 0.1, 0.3, 0.7, 1.5, 3.1, 5.1, …,
// 15.1s).
func TestRetryWriteGivesUpOnRefusals(t *testing.T) {
	for _, tc := range []struct {
		err       error
		attempts  int
		permanent bool
	}{
		{&dataplane.APIError{Status: 400}, 1, true},
		{&dataplane.APIError{Status: 413}, 1, true},
		{fmt.Errorf("push challenge keys: %w", &dataplane.APIError{Status: 507}), 1, true},
		{&dataplane.APIError{Status: 409}, 12, false},
		{&dataplane.APIError{Status: 500}, 12, false},
		{errors.New("dial unix control.sock: connect: no such file or directory"), 12, false},
	} {
		synctest.Test(t, func(t *testing.T) {
			a := &Agent{cfg: Config{PushTimeout: 15 * time.Second}}
			start := time.Now()
			attempts := 0
			err := a.retryWrite(t.Context(), 0, func(context.Context) error { attempts++; return tc.err })
			if !errors.Is(err, tc.err) || retry.IsPermanent(err) != tc.permanent || attempts != tc.attempts {
				t.Fatalf("%v: err %v (permanent %v) after %d attempts, want %d", tc.err, err, retry.IsPermanent(err), attempts, tc.attempts)
			}
			if !tc.permanent && time.Since(start) != 15100*time.Millisecond {
				t.Fatalf("%v: gave up after %v", tc.err, time.Since(start))
			}
		})
	}
}

// TestTablePushError: a refused table fails the revision for good, a full
// store names its flag, a push that kept failing marks the data plane
// unhealthy, and a push cut short by its context returns just that.
func TestTablePushError(t *testing.T) {
	a := &Agent{dpHealthy: true}
	ctx, cancel := context.WithCancel(context.Background())
	var perm *permanentError
	err := a.tablePushError(ctx, retry.Permanent(&dataplane.APIError{Status: 507, Message: "no memory"}), "site table", "site store (--sites-dict-mb 64)")
	if !errors.As(err, &perm) || err.Error() != "the site table does not fit the data plane's site store (--sites-dict-mb 64): data plane control API: HTTP 507: no memory" {
		t.Fatalf("507: %v", err)
	}
	err = a.tablePushError(ctx, retry.Permanent(&dataplane.APIError{Status: 400, Message: "bad"}), "layer-4 table", "store")
	if !errors.As(err, &perm) || err.Error() != "data plane rejected the layer-4 table: data plane control API: HTTP 400: bad" {
		t.Fatalf("400: %v", err)
	}
	if !a.dpHealthy {
		t.Fatal("a refused table marked the data plane unhealthy")
	}
	cancel()
	if err := a.tablePushError(ctx, ctx.Err(), "site table", "store"); err != context.Canceled || !a.dpHealthy {
		t.Fatalf("cancelled: %v, healthy %v", err, a.dpHealthy)
	}
	err = a.tablePushError(context.Background(), &dataplane.APIError{Status: 409}, "site table", "store")
	if errors.As(err, &perm) || err.Error() != "push site table: data plane control API: HTTP 409: " || a.dpHealthy {
		t.Fatalf("budget spent: %v, healthy %v", err, a.dpHealthy)
	}
}
