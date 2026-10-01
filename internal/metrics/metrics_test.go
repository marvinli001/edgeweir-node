package metrics

import (
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func open(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestParseStat(t *testing.T) {
	first, err := ParseStat(open(t, "first/stat"))
	if err != nil {
		t.Fatal(err)
	}
	if first != (CPUTimes{Total: 10000, Idle: 8400}) {
		t.Fatalf("first = %+v", first)
	}
	second, err := ParseStat(open(t, "second/stat"))
	if err != nil {
		t.Fatal(err)
	}
	if second != (CPUTimes{Total: 11000, Idle: 9150}) {
		t.Fatalf("second = %+v (guest time must not count twice)", second)
	}
	if got := CPUPercent(first, second); math.Abs(got-25) > 1e-9 {
		t.Fatalf("CPUPercent = %v, want 25", got)
	}
	if got := CPUPercent(second, second); got != 0 {
		t.Fatalf("no time passed: %v", got)
	}
	if got := CPUPercent(second, first); got != 0 {
		t.Fatalf("counters went back: %v", got)
	}
	if got := CPUPercent(CPUTimes{Total: 100, Idle: 0}, CPUTimes{Total: 200, Idle: 0}); got != 100 {
		t.Fatalf("all busy: %v", got)
	}
	// Old kernels: only user, nice, system and idle.
	old, err := ParseStat(strings.NewReader("cpu 1 2 3 4\n"))
	if err != nil || old != (CPUTimes{Total: 10, Idle: 4}) {
		t.Fatalf("four values: %+v %v", old, err)
	}
	for _, bad := range []string{"", "cpu0 1 2 3 4\n", "cpu 1 2 3\n", "cpu 1 x 3 4\n", "intr 5\n"} {
		if _, err := ParseStat(strings.NewReader(bad)); err == nil {
			t.Errorf("ParseStat(%q) accepted", bad)
		}
	}
}

func TestParseLoadavg(t *testing.T) {
	l1, l5, l15, err := ParseLoadavg(open(t, "first/loadavg"))
	if err != nil || l1 != 0.52 || l5 != 0.48 || l15 != 0.40 {
		t.Fatalf("loadavg = %v %v %v %v", l1, l5, l15, err)
	}
	for _, bad := range []string{"", "0.5 0.4", "a b c 1/2 3", "-1 0 0 1/2 3"} {
		if _, _, _, err := ParseLoadavg(strings.NewReader(bad)); err == nil {
			t.Errorf("ParseLoadavg(%q) accepted", bad)
		}
	}
}

func TestParseMeminfo(t *testing.T) {
	total, available, err := ParseMeminfo(open(t, "first/meminfo"))
	if err != nil || total != 8000000*1024 || available != 6000000*1024 {
		t.Fatalf("meminfo = %d %d %v", total, available, err)
	}
	// Without MemAvailable: free + buffers + cache.
	total, available, err = ParseMeminfo(strings.NewReader("MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 250 kB\n"))
	if err != nil || total != 1000*1024 || available != 400*1024 {
		t.Fatalf("old kernel = %d %d %v", total, available, err)
	}
	// Never more available than total.
	_, available, _ = ParseMeminfo(strings.NewReader("MemTotal: 1000 kB\nMemAvailable: 2000 kB\n"))
	if available != 1000*1024 {
		t.Fatalf("available = %d", available)
	}
	if _, _, err := ParseMeminfo(strings.NewReader("MemFree: 100 kB\n")); err == nil {
		t.Fatal("meminfo without MemTotal accepted")
	}
}

func TestParseNetDev(t *testing.T) {
	tx, err := ParseNetDev(open(t, "first/net/dev"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]uint64{"lo": 5000000, "eth0": 100000000, "eth1": 2000000, "docker0": 0}
	if len(tx) != len(want) {
		t.Fatalf("interfaces = %v", tx)
	}
	for name, v := range want {
		if tx[name] != v {
			t.Errorf("%s tx = %d, want %d", name, tx[name], v)
		}
	}
	for _, bad := range []string{"  eth0: 1 2 3\n", "  eth0: 1 2 3 4 5 6 7 8 x 1 2 3 4 5 6 7\n", " : 1 2 3 4 5 6 7 8 9 1 2 3 4 5 6 7\n"} {
		if _, err := ParseNetDev(strings.NewReader(bad)); err == nil {
			t.Errorf("ParseNetDev(%q) accepted", bad)
		}
	}
}

func TestEgressBytes(t *testing.T) {
	lo := func(n string) bool { return n == "lo" }
	prev := map[string]uint64{"lo": 10, "eth0": 100, "eth1": 500, "gone": 7}
	cur := map[string]uint64{"lo": 1000, "eth0": 350, "eth1": 20, "new0": 99}
	if got := EgressBytes(prev, cur, lo); got != 250 {
		t.Fatalf("EgressBytes = %d, want 250 (eth0 only)", got)
	}
	if got := EgressBytes(nil, cur, lo); got != 0 {
		t.Fatalf("no previous sample: %d", got)
	}
}

func TestCollector(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	c := &Collector{
		Root:     filepath.Join("testdata", "first"),
		Loopback: func(n string) bool { return n == "lo" },
		Now:      func() time.Time { return now },
	}
	m, err := c.Collect()
	if err != nil {
		t.Fatal(err)
	}
	if m.GetCpuPercent() != 0 || m.GetEgressBps() != 0 {
		t.Fatalf("first sample has rates: %v", m)
	}
	if m.GetLoad1() != 0.52 || m.GetLoad5() != 0.48 || m.GetLoad15() != 0.40 ||
		m.GetMemoryTotalBytes() != 8000000*1024 || m.GetMemoryUsedBytes() != 2000000*1024 {
		t.Fatalf("first sample = %v", m)
	}

	now = now.Add(10 * time.Second)
	c.Root = filepath.Join("testdata", "second")
	m, err = c.Collect()
	if err != nil {
		t.Fatal(err)
	}
	// eth0 sent 12.5 MB in 10 s; lo, the reset eth1 and the new veth do
	// not count.
	if math.Abs(m.GetCpuPercent()-25) > 1e-9 || m.GetEgressBps() != 10_000_000 {
		t.Fatalf("rates = %v %% %v bit/s, want 25 and 10000000", m.GetCpuPercent(), m.GetEgressBps())
	}
	if m.GetLoad1() != 1.25 || m.GetMemoryUsedBytes() != 3000000*1024 {
		t.Fatalf("second sample = %v", m)
	}

	// A report right after another keeps the rates.
	now = now.Add(100 * time.Millisecond)
	c.Root = filepath.Join("testdata", "first")
	m, _ = c.Collect()
	if math.Abs(m.GetCpuPercent()-25) > 1e-9 || m.GetEgressBps() != 10_000_000 || m.GetLoad1() != 0.52 {
		t.Fatalf("rates within MinInterval = %v", m)
	}

	// Unreadable files: zeros and an error naming them.
	now = now.Add(time.Minute)
	c.Root = t.TempDir()
	m, err = c.Collect()
	if err == nil || m.GetCpuPercent() != 0 || m.GetEgressBps() != 0 || m.GetMemoryTotalBytes() != 0 {
		t.Fatalf("missing files: %v, %v", m, err)
	}
}

func TestCollectorDisabled(t *testing.T) {
	var nilCollector *Collector
	for _, c := range []*Collector{nilCollector, {}} {
		if c.Enabled() {
			t.Fatal("enabled without a root")
		}
		if m, err := c.Collect(); m != nil || err != nil {
			t.Fatalf("disabled collector: %v %v", m, err)
		}
	}
	c := New()
	if c.Enabled() != (runtime.GOOS == "linux") {
		t.Fatalf("New().Enabled() = %v on %s", c.Enabled(), runtime.GOOS)
	}
	if runtime.GOOS == "linux" {
		m, err := c.Collect()
		if err != nil || m.GetMemoryTotalBytes() == 0 {
			t.Fatalf("/proc: %v %v", m, err)
		}
	}
}
