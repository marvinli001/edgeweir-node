package nft

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func ban(cidr string, left time.Duration) Ban {
	return Ban{Prefix: netip.MustParsePrefix(cidr), Expires: now.Add(left)}
}

func prefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, s := range list {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func TestSetupScriptDefinesTheTable(t *testing.T) {
	want := `add table inet edgeweir
delete table inet edgeweir
table inet edgeweir {
	set ban4 {
		type ipv4_addr
		flags interval, timeout
	}
	set ban6 {
		type ipv6_addr
		flags interval, timeout
	}
	set allow4 {
		type ipv4_addr
		flags interval
	}
	set allow6 {
		type ipv6_addr
		flags interval
	}
	chain input {
		type filter hook input priority -10; policy accept;
		ip saddr @allow4 accept
		ip6 saddr @allow6 accept
		ip saddr @ban4 drop
		ip6 saddr @ban6 drop
	}
}
`
	if SetupScript != want {
		t.Fatalf("setup script:\n%s", SetupScript)
	}
	if StopScript != "delete table inet edgeweir\n" {
		t.Fatalf("stop script: %q", StopScript)
	}
}

func TestSyncScript(t *testing.T) {
	p := buildPlan([]Ban{
		ban("203.0.113.7/32", 59*time.Second+time.Millisecond), // rounded up to 60s
		ban("198.51.100.0/24", time.Hour),
		ban("2001:db8:1::/48", 2*time.Hour),
		ban("2001:db8:2::5/128", 90*time.Second),
		ban("192.0.2.1/32", -time.Second), // expired
		ban("192.0.2.2/32", 0),            // expires now
	}, prefixes("127.0.0.0/8", "::1/128", "192.0.2.10/32", "10.1.0.0/16"), now)
	script, err := syncScript(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `flush set inet edgeweir allow4
flush set inet edgeweir allow6
flush set inet edgeweir ban4
flush set inet edgeweir ban6
add element inet edgeweir allow4 { 10.1.0.0/16, 127.0.0.0/8, 192.0.2.10 }
add element inet edgeweir allow6 { ::1 }
add element inet edgeweir ban4 { 198.51.100.0/24 timeout 3600s, 203.0.113.7 timeout 60s }
add element inet edgeweir ban6 { 2001:db8:1::/48 timeout 7200s, 2001:db8:2::5 timeout 90s }
`
	if script != want {
		t.Fatalf("sync script:\n%s\nwant:\n%s", script, want)
	}
	if p.entries() != 4 || !p.Resync.IsZero() {
		t.Fatalf("entries %d resync %v", p.entries(), p.Resync)
	}
}

func TestSyncScriptWithoutElementsOnlyFlushes(t *testing.T) {
	script, err := syncScript(buildPlan(nil, nil, now))
	if err != nil {
		t.Fatal(err)
	}
	if script != "flush set inet edgeweir allow4\nflush set inet edgeweir allow6\nflush set inet edgeweir ban4\nflush set inet edgeweir ban6\n" {
		t.Fatalf("empty sync:\n%s", script)
	}
}

func TestSyncScriptSplitsLargeSets(t *testing.T) {
	var bans []Ban
	for i := range 1200 {
		bans = append(bans, ban(fmt.Sprintf("10.%d.%d.1/32", i/256, i%256), time.Hour))
	}
	script, err := syncScript(buildPlan(bans, nil, now))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(script, "add element inet edgeweir ban4 {"); n != 3 {
		t.Fatalf("%d add element statements for 1200 elements", n)
	}
	if n := strings.Count(script, " timeout 3600s"); n != 1200 {
		t.Fatalf("%d elements written", n)
	}
}

func TestDeoverlap(t *testing.T) {
	p := buildPlan([]Ban{
		ban("198.51.100.0/24", time.Hour),
		ban("198.51.100.7/32", 30*time.Minute),      // covered, expires earlier: dropped
		ban("198.51.100.8/32", time.Hour),           // covered, same expiry: dropped
		ban("198.51.100.9/32", 2*time.Hour),         // covered, outlives the cover: resync at its expiry
		ban("198.51.100.128/25", 3*time.Hour),       // covered, outlives the cover
		ban("203.0.113.5/32", time.Minute),          // duplicate: latest expiry wins
		ban("203.0.113.5/32", 5*time.Minute),        //
		ban("2001:db8:1::/48", time.Hour),           //
		ban("2001:db8:1:2::/64", 10*time.Minute),    // covered
		ban("2001:db8:2::/64", 10*time.Minute),      // separate
		ban("::ffff:192.0.2.77/128", 5*time.Minute), // IPv4-mapped: written as IPv4
	}, nil, now)
	var got []string
	for _, e := range append(p.Ban4, p.Ban6...) {
		got = append(got, fmt.Sprintf("%s/%d", e.prefix, e.timeout))
	}
	want := []string{"192.0.2.77/32/300", "198.51.100.0/24/3600", "203.0.113.5/32/300", "2001:db8:1::/48/3600", "2001:db8:2::/64/600"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("elements = %v, want %v", got, want)
	}
	if !p.Resync.Equal(now.Add(time.Hour)) {
		t.Fatalf("resync = %v, want the cover's expiry", p.Resync)
	}

	// After the cover expires the longer-lived prefixes are written.
	later := buildPlan([]Ban{
		ban("198.51.100.0/24", time.Hour),
		ban("198.51.100.9/32", 2*time.Hour),
		ban("198.51.100.128/25", 3*time.Hour),
	}, nil, now.Add(time.Hour))
	got = nil
	for _, e := range later.Ban4 {
		got = append(got, fmt.Sprintf("%s/%d", e.prefix, e.timeout))
	}
	if strings.Join(got, " ") != "198.51.100.9/32/3600 198.51.100.128/25/7200" || !later.Resync.IsZero() {
		t.Fatalf("after the cover expired: %v resync %v", got, later.Resync)
	}
}

func TestProtectedSetDropsCoveredPrefixes(t *testing.T) {
	p := buildPlan(nil, prefixes(
		"127.0.0.0/8", "127.0.0.1/32", "10.0.0.5/32", "10.0.0.0/24", "10.0.0.0/24", "192.0.2.10/32",
		"::1/128", "fd00::/8", "fd00::1/128", "::ffff:198.51.100.1/128",
	), now)
	var got []string
	for _, pr := range append(p.Allow4, p.Allow6...) {
		got = append(got, pr.String())
	}
	if strings.Join(got, " ") != "10.0.0.0/24 127.0.0.0/8 192.0.2.10/32 198.51.100.1/32 ::1/128 fd00::/8" {
		t.Fatalf("allow elements = %v", got)
	}
}

func TestManagerLifecycle(t *testing.T) {
	fake := &Fake{}
	m := NewManager(fake, nil)
	if _, err := m.Sync(context.Background(), nil, nil, now); !errors.Is(err, ErrInactive) {
		t.Fatalf("sync before start: %v", err)
	}
	if err := m.Start(context.Background()); err != nil || !m.Active() {
		t.Fatalf("start: %v active %v", err, m.Active())
	}
	resync, err := m.Sync(context.Background(), []Ban{
		ban("198.51.100.0/24", time.Hour), ban("198.51.100.1/32", 2*time.Hour), ban("203.0.113.1/32", time.Minute),
	}, prefixes("127.0.0.0/8"), now)
	if err != nil || !resync.Equal(now.Add(time.Hour)) {
		t.Fatalf("sync: %v resync %v", err, resync)
	}
	if n := m.Entries(now); n != 2 {
		t.Fatalf("entries = %d", n)
	}
	if n := m.Entries(now.Add(2 * time.Minute)); n != 1 {
		t.Fatalf("entries after a timeout = %d", n)
	}
	if err := m.Stop(context.Background()); err != nil || m.Active() {
		t.Fatalf("stop: %v", err)
	}
	scripts := fake.Scripts()
	if len(scripts) != 3 || scripts[0] != SetupScript || !strings.HasPrefix(scripts[1], "flush set inet edgeweir allow4\n") || scripts[2] != StopScript {
		t.Fatalf("scripts = %q", scripts)
	}
	// Stopping twice runs nothing.
	if err := m.Stop(context.Background()); err != nil || len(fake.Scripts()) != 3 {
		t.Fatalf("second stop: %v, %d scripts", err, len(fake.Scripts()))
	}
}

func TestManagerProbeFailureLeavesItInactive(t *testing.T) {
	fake := &Fake{Fail: func(string) error { return errors.New("Operation not permitted") }}
	m := NewManager(fake, nil)
	if err := m.Start(context.Background()); err == nil || m.Active() {
		t.Fatalf("start with a failing nft: %v, active %v", err, m.Active())
	}
	if _, err := m.Sync(context.Background(), []Ban{ban("198.51.100.0/24", time.Hour)}, nil, now); !errors.Is(err, ErrInactive) {
		t.Fatalf("sync while inactive: %v", err)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(fake.Scripts()); n != 1 {
		t.Fatalf("an inactive manager ran %d scripts after the probe", n-1)
	}
}

func TestManagerRecreatesAMissingTable(t *testing.T) {
	failNext := true
	fake := &Fake{Fail: func(script string) error {
		if strings.HasPrefix(script, "flush set") && failNext {
			failNext = false
			return errors.New("Error: No such file or directory")
		}
		return nil
	}}
	m := NewManager(fake, nil)
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Sync(context.Background(), []Ban{ban("198.51.100.0/24", time.Hour)}, nil, now); err != nil {
		t.Fatal(err)
	}
	scripts := fake.Scripts()
	if len(scripts) != 4 || scripts[2] != SetupScript || scripts[1] != scripts[3] {
		t.Fatalf("scripts = %q", scripts)
	}
	if m.Entries(now) != 1 {
		t.Fatalf("entries = %d", m.Entries(now))
	}
}

func TestFormatRefusesAnythingButAddresses(t *testing.T) {
	for _, p := range []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::1/128")} {
		if _, err := format(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	if _, err := format(netip.Prefix{}); err == nil {
		t.Error("invalid prefix formatted")
	}
}
