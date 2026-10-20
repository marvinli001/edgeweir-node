package agent

import (
	"testing"
	"time"
)

func TestMeasureClock(t *testing.T) {
	sent := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		rtt     time.Duration
		console time.Time
		wantNo  bool
		offset  time.Duration
	}{
		// The console answered at the middle of the round trip on its clock, 3 s behind the node's.
		{name: "node ahead", rtt: 200 * time.Millisecond, console: sent.Add(100*time.Millisecond - 3*time.Second), offset: 3 * time.Second},
		{name: "node behind", rtt: 2 * time.Second, console: sent.Add(time.Second + 90*time.Second), offset: -90 * time.Second},
		{name: "in sync", rtt: 40 * time.Millisecond, console: sent.Add(20 * time.Millisecond)},
		{name: "no console time", rtt: time.Second, wantNo: true},
		{name: "round trip too slow", rtt: maxClockRTT + time.Millisecond, console: sent, wantNo: true},
		{name: "clock stepped back mid-request", rtt: -time.Second, console: sent, wantNo: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := measureClock(sent, sent.Add(tc.rtt), tc.console)
			if tc.wantNo {
				if got != nil {
					t.Fatalf("got %+v, want none", got)
				}
				return
			}
			if got == nil || got.offset != tc.offset || got.rtt != tc.rtt || !got.at.Equal(sent.Add(tc.rtt)) {
				t.Fatalf("got %+v, want offset %v rtt %v", got, tc.offset, tc.rtt)
			}
		})
	}
}
