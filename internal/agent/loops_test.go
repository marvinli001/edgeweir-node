package agent

import (
	"testing"
	"time"
)

// TestJitteredPollInterval: fallback polls are spread over ±20% of the
// interval so that nodes do not poll the console in lockstep.
func TestJitteredPollInterval(t *testing.T) {
	d := 30 * time.Second
	seen := map[time.Duration]bool{}
	lo, hi := d, time.Duration(0)
	for range 2000 {
		j := jittered(d)
		if j < 24*time.Second || j > 36*time.Second {
			t.Fatalf("jittered(30s) = %v, outside [24s, 36s]", j)
		}
		seen[j] = true
		lo, hi = min(lo, j), max(hi, j)
	}
	if len(seen) < 100 || hi-lo < 10*time.Second {
		t.Fatalf("no real spread: %d distinct values in [%v, %v]", len(seen), lo, hi)
	}
	if jittered(0) != 0 {
		t.Fatal("jittered(0) != 0")
	}
}
