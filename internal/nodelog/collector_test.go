package nodelog

import (
	"fmt"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newTestCollector(capacity int) (*Collector, *clock) {
	c := &clock{t: time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)}
	return NewCollector(Options{Capacity: capacity, Now: c.now}), c
}

func warn(msg string) Entry { return Entry{Level: LevelWarn, Source: SourceAgent, Message: msg} }

func TestCollectorNumbersReadsAndDiscards(t *testing.T) {
	c, _ := newTestCollector(10)
	for i := range 5 {
		c.Add(warn(fmt.Sprintf("m%c", 'a'+i)))
	}
	got, last := c.Read(0, 2)
	if len(got) != 2 || got[0].Message != "ma" || last != 2 {
		t.Fatalf("%v %d", got, last)
	}
	got, last = c.Read(last, 10)
	if len(got) != 3 || got[0].Message != "mc" || last != 5 {
		t.Fatalf("%v %d", got, last)
	}
	if got, last := c.Read(5, 10); got != nil || last != 5 {
		t.Fatalf("%v %d", got, last)
	}
	c.Discard(3)
	got, last = c.Read(0, 10)
	if len(got) != 2 || got[0].Message != "md" || last != 5 {
		t.Fatalf("after discard: %v %d", got, last)
	}
	if taken := c.Take(10); len(taken) != 2 {
		t.Fatalf("take %v", taken)
	}
	c.Add(warn("mf"))
	got, last = c.Read(5, 10)
	if len(got) != 1 || got[0].Message != "mf" || last != 6 {
		t.Fatalf("numbers continue: %v %d", got, last)
	}
}

func TestCollectorOverflowDropsOldest(t *testing.T) {
	c, clk := newTestCollector(3)
	for i := range 5 {
		clk.advance(time.Second)
		c.Add(warn(fmt.Sprintf("m%c", 'a'+i)))
	}
	got, last := c.Read(0, 10)
	if len(got) != 3 || got[0].Message != "mc" || last != 5 {
		t.Fatalf("%v %d", got, last)
	}
	// A reader behind the oldest kept entry gets what is left.
	if got, _ := c.Read(1, 10); len(got) != 3 {
		t.Fatalf("%v", got)
	}
	if limited, overflow := c.Dropped(); limited != 0 || overflow != 2 {
		t.Fatalf("dropped %d %d", limited, overflow)
	}
}

func TestCollectorRateLimitsPerSourceClass(t *testing.T) {
	c, clk := newTestCollector(1000)
	for i := range 60 {
		c.Add(warn(fmt.Sprintf("agent %c%c", 'a'+i/26, 'a'+i%26)))
	}
	if limited, _ := c.Dropped(); limited != 10 {
		t.Fatalf("limited %d", limited)
	}
	// OpenResty has its own bucket.
	for i := range 100 {
		c.Add(Entry{Level: LevelError, Source: SourceNginx, Message: fmt.Sprintf("nginx %c%c", 'a'+i/26, 'a'+i%26)})
	}
	if limited, _ := c.Dropped(); limited != 10 {
		t.Fatalf("limited %d", limited)
	}
	clk.advance(time.Second)
	for i := range 6 {
		c.Add(warn(fmt.Sprintf("later %c", 'a'+i)))
	}
	if limited, _ := c.Dropped(); limited != 11 {
		t.Fatalf("limited %d", limited)
	}
}

func TestCollectorFoldsRepeatedEntries(t *testing.T) {
	c, clk := newTestCollector(100)
	add := func(n int) {
		for i := range n {
			e := Entry{Level: LevelError, Source: SourceNginx, Message: fmt.Sprintf("connect() failed (111: refused) attempt %d", i),
				Fields: map[string]string{"client": fmt.Sprintf("192.0.2.%d", i)}}
			c.Add(e)
		}
	}
	add(10)
	got, last := c.Read(0, 100)
	if len(got) != 3 {
		t.Fatalf("kept %d", len(got))
	}
	clk.advance(time.Minute)
	got, last = c.Read(last, 100)
	if len(got) != 1 || got[0].Repeated != 7 || got[0].Fields["client"] != "192.0.2.9" {
		t.Fatalf("summary %+v", got)
	}
	// The next window is 5 minutes: three more, then folded again.
	add(5)
	clk.advance(time.Minute)
	got, last = c.Read(last, 100)
	if len(got) != 3 {
		t.Fatalf("second window kept %d", len(got))
	}
	clk.advance(4 * time.Minute)
	got, _ = c.Read(last, 100)
	if len(got) != 1 || got[0].Repeated != 2 {
		t.Fatalf("second summary %+v", got)
	}
	// Quiet for a whole window: the signature starts over at one minute.
	clk.advance(time.Hour)
	c.Read(0, 0)
	if len(c.sigs) != 0 {
		t.Fatalf("signatures %d", len(c.sigs))
	}
}

func TestCollectorKeepsOnlyEventsAtInfo(t *testing.T) {
	c, _ := newTestCollector(10)
	c.Add(Entry{Level: LevelInfo, Source: SourceAgent, Message: "pushed site table"})
	c.Add(Entry{Level: LevelInfo, Source: SourceAgent, Message: "configuration applied", Event: "made_up"})
	c.Add(Entry{Level: LevelInfo, Source: SourceAgent, Message: "configuration applied", Event: EventConfigApplied})
	c.Add(Entry{Level: "debug", Source: SourceAgent, Message: "x"})
	c.Add(Entry{Level: LevelWarn, Source: "probe", Message: "x"})
	got, _ := c.Read(0, 10)
	if len(got) != 1 || got[0].Event != EventConfigApplied || got[0].Time.IsZero() {
		t.Fatalf("%+v", got)
	}
}

func TestCollectorRedacts(t *testing.T) {
	c, _ := newTestCollector(10)
	c.Add(Entry{Level: LevelWarn, Source: SourceAgent, Message: "GET /a?token=x failed",
		Fields: map[string]string{"err": "Bearer abcdefghijkl", "Token": "y"}})
	got, _ := c.Read(0, 10)
	if got[0].Message != "GET /a?[redacted] failed" || got[0].Fields["err"] != "Bearer [redacted]" || got[0].Fields["token"] != Redacted {
		t.Fatalf("%+v", got[0])
	}
}

func TestEntryProto(t *testing.T) {
	e := Entry{Time: time.Unix(10, 0), Level: LevelError, Source: SourceLua, Component: "c", Message: "m",
		Fields: map[string]string{"k": "v"}, Repeated: 2, Truncated: true}
	p := e.Proto()
	if p.GetLevel().String() != "NODE_LOG_LEVEL_ERROR" || p.GetSource().String() != "NODE_LOG_SOURCE_LUA" ||
		p.GetTime().AsTime().Unix() != 10 || p.GetFields()["k"] != "v" || p.GetRepeated() != 2 || !p.GetTruncated() {
		t.Fatalf("%v", p)
	}
}
