package agent

import (
	"testing"
	"time"
)

// TestPurgeLimiter: purgeRate accepted PURGE requests per site and second;
// sites count apart and every second starts afresh.
func TestPurgeLimiter(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := &purgeLimiter{now: func() time.Time { return now }}
	for i := range purgeRate {
		if !l.allow("a") {
			t.Fatalf("request %d of site a refused", i+1)
		}
	}
	if l.allow("a") {
		t.Fatal("site a took more than purgeRate requests in one second")
	}
	if !l.allow("b") {
		t.Fatal("site b refused because of site a")
	}
	now = now.Add(time.Second)
	if !l.allow("a") {
		t.Fatal("site a still refused in the next second")
	}
}
