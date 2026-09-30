package bans

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

var now = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func pb(id, cidr string, scope nodev1.BanScope, site string, source nodev1.BanSource, created, expires time.Duration) *nodev1.Ban {
	return &nodev1.Ban{
		Id: id, Cidr: cidr, Scope: scope, SiteId: site, Source: source, Reason: "abuse",
		CreatedAt: timestamppb.New(now.Add(created)), ExpiresAt: timestamppb.New(now.Add(expires)),
	}
}

func platform(id, cidr string, expires time.Duration) *nodev1.Ban {
	return pb(id, cidr, nodev1.BanScope_BAN_SCOPE_PLATFORM, "", nodev1.BanSource_BAN_SOURCE_MANUAL, -time.Minute, expires)
}

func site(id, cidr, siteID string, expires time.Duration) *nodev1.Ban {
	return pb(id, cidr, nodev1.BanScope_BAN_SCOPE_SITE, siteID, nodev1.BanSource_BAN_SOURCE_MANUAL, -time.Minute, expires)
}

func auto(id, cidr, siteID string, created time.Duration) *nodev1.Ban {
	return pb(id, cidr, nodev1.BanScope_BAN_SCOPE_SITE, siteID, nodev1.BanSource_BAN_SOURCE_AUTO, created, time.Hour)
}

func ids(bans []Ban) []string {
	out := make([]string, len(bans))
	for i, b := range bans {
		out[i] = b.ID
	}
	return out
}

func TestFromProtoValidates(t *testing.T) {
	good, err := FromProto(site("b1", "203.0.113.7/32", "site-a", time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if good.Prefix != netip.MustParsePrefix("203.0.113.7/32") || good.Scope != ScopeSite || good.SiteID != "site-a" || !good.Manual() {
		t.Fatalf("parsed ban = %+v", good)
	}
	// Host bits are cleared, IPv4-mapped addresses unmapped, IPv6 kept.
	for in, want := range map[string]string{
		"198.51.100.9/24":         "198.51.100.0/24",
		"::ffff:198.51.100.9/128": "198.51.100.9/32",
		"2001:DB8:1:2::5/64":      "2001:db8:1:2::/64",
		"2001:db8:1::/48":         "2001:db8:1::/48",
		"::ffff:198.51.100.0/120": "198.51.100.0/24",
	} {
		b, err := FromProto(platform("p", in, time.Hour))
		if err != nil || b.Prefix.String() != want {
			t.Errorf("%s: got %v, %v; want %s", in, b.Prefix, err, want)
		}
	}
	bad := []*nodev1.Ban{
		platform("", "203.0.113.7/32", time.Hour),                                    // no id
		platform("a b", "203.0.113.7/32", time.Hour),                                 // id charset
		platform("p", "203.0.113.7", time.Hour),                                      // not a prefix
		platform("p", "10.0.0.0/8", time.Hour),                                       // shorter than /16
		platform("p", "2001:db8::/32", time.Hour),                                    // shorter than /48
		platform("p", "fe80::1%eth0/128", time.Hour),                                 // zone
		site("s", "203.0.113.7/32", "", time.Hour),                                   // site ban without a site
		site("s", "203.0.113.7/32", "site/a", time.Hour),                             // site id charset
		{Id: "x", Cidr: "203.0.113.7/32", Scope: nodev1.BanScope_BAN_SCOPE_PLATFORM}, // no expiry
		{Id: "x", Cidr: "203.0.113.7/32", ExpiresAt: timestamppb.New(now)},           // no scope
	}
	for _, b := range bad {
		if got, err := FromProto(b); err == nil {
			t.Errorf("accepted invalid ban %v as %+v", b, got)
		}
	}
	// A platform ban never carries a site.
	p, err := FromProto(pb("p", "203.0.113.0/24", nodev1.BanScope_BAN_SCOPE_PLATFORM, "site-a", nodev1.BanSource_BAN_SOURCE_UNSPECIFIED, 0, time.Hour))
	if err != nil || p.SiteID != "" || !p.Manual() {
		t.Fatalf("platform ban = %+v, %v", p, err)
	}
}

func TestApplyPages(t *testing.T) {
	s := New()
	s.Bans["stale"] = Ban{ID: "stale", Prefix: netip.MustParsePrefix("192.0.2.1/32"), Scope: ScopePlatform, Source: SourceManual, ExpiresAt: now.Add(time.Hour)}

	errs := s.Apply(&nodev1.GetBansResponse{
		Reset_:   true,
		Bans:     []*nodev1.Ban{platform("p1", "198.51.100.0/24", time.Hour), site("s1", "203.0.113.7/32", "site-a", time.Hour)},
		Sequence: 10,
		More:     true,
	}, now)
	if len(errs) != 0 || s.Sequence != 10 || len(s.Bans) != 2 || s.Bans["stale"].ID != "" {
		t.Fatalf("after reset page: seq %d bans %v errs %v", s.Sequence, s.Bans, errs)
	}
	errs = s.Apply(&nodev1.GetBansResponse{
		Bans: []*nodev1.Ban{
			site("s1", "203.0.113.8/32", "site-a", 2*time.Hour), // changed address
			platform("bad", "10.0.0.0/8", time.Hour),            // refused
			platform("gone", "198.51.100.77/32", -time.Second),  // already expired
		},
		RemovedIds: []string{"p1", "unknown"},
		Sequence:   14,
	}, now)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "bad") {
		t.Fatalf("errors = %v", errs)
	}
	if s.Sequence != 14 || len(s.Bans) != 1 || s.Bans["s1"].Prefix.String() != "203.0.113.8/32" {
		t.Fatalf("after delta page: seq %d bans %v", s.Sequence, s.Bans)
	}
	// Expiries beyond 7 days are shortened.
	s.Apply(&nodev1.GetBansResponse{Bans: []*nodev1.Ban{site("s2", "203.0.113.9/32", "site-a", 30*24*time.Hour)}, Sequence: 14}, now)
	if got := s.Bans["s2"].ExpiresAt; !got.Equal(now.Add(MaxLifetime)) {
		t.Fatalf("expiry of a 30-day ban = %v", got)
	}
	delete(s.Bans, "s2")
	// An invalid update removes the previous version of the ban.
	s.Apply(&nodev1.GetBansResponse{Bans: []*nodev1.Ban{site("s1", "203.0.113.8/32", "", time.Hour)}, Sequence: 15}, now)
	if len(s.Bans) != 0 {
		t.Fatalf("invalid update kept %v", s.Bans)
	}
}

func TestDiff(t *testing.T) {
	from := New()
	from.Apply(&nodev1.GetBansResponse{Reset_: true, Sequence: 3, Bans: []*nodev1.Ban{
		platform("keep", "198.51.100.0/24", time.Hour),
		platform("moved", "198.51.100.1/32", time.Hour),
		platform("extended", "198.51.100.2/32", time.Hour),
		platform("removed", "198.51.100.3/32", time.Hour),
	}}, now)
	to := from.Clone()
	to.Apply(&nodev1.GetBansResponse{Sequence: 4, RemovedIds: []string{"removed"}, Bans: []*nodev1.Ban{
		site("moved", "198.51.100.1/32", "site-a", time.Hour),
		platform("extended", "198.51.100.2/32", 2*time.Hour),
		platform("new", "198.51.100.4/32", time.Hour),
	}}, now)
	d := Diff(from, to)
	if got := ids(d.Upsert); !slices.Equal(got, []string{"extended", "moved", "new"}) {
		t.Errorf("upsert = %v", got)
	}
	if got := ids(d.Remove); !slices.Equal(got, []string{"moved", "removed"}) {
		t.Errorf("remove = %v", got)
	}
	for _, b := range d.Remove {
		if b.ID == "moved" && b.Scope != ScopePlatform {
			t.Errorf("removal of a moved ban must carry its old key: %+v", b)
		}
	}
	if d := Diff(to, to.Clone()); d.Len() != 0 {
		t.Errorf("diff of equal states = %+v", d)
	}
}

func TestOrderedPutsManualFirstAndDropsOldestAuto(t *testing.T) {
	s := New()
	s.Apply(&nodev1.GetBansResponse{Reset_: true, Sequence: 1, Bans: []*nodev1.Ban{
		auto("a-old", "192.0.2.1/32", "site-a", -3*time.Hour),
		auto("a-new", "192.0.2.2/32", "site-a", -time.Hour),
		auto("a-mid", "192.0.2.3/32", "site-a", -2*time.Hour),
		pb("m2", "192.0.2.4/32", nodev1.BanScope_BAN_SCOPE_SITE, "site-a", nodev1.BanSource_BAN_SOURCE_MANUAL, -time.Hour, time.Hour),
		pb("m1", "192.0.2.5/32", nodev1.BanScope_BAN_SCOPE_SITE, "site-a", nodev1.BanSource_BAN_SOURCE_MANUAL, -2*time.Hour, time.Hour),
		pb("expired", "192.0.2.6/32", nodev1.BanScope_BAN_SCOPE_SITE, "site-a", nodev1.BanSource_BAN_SOURCE_MANUAL, -2*time.Hour, time.Minute),
	}}, now)
	later := now.Add(2 * time.Minute)
	all, dropped := s.Ordered(later, 100)
	if got := ids(all); !slices.Equal(got, []string{"m1", "m2", "a-new", "a-mid", "a-old"}) || dropped != 0 {
		t.Fatalf("ordered = %v dropped %d", got, dropped)
	}
	some, dropped := s.Ordered(later, 3)
	if got := ids(some); !slices.Equal(got, []string{"m1", "m2", "a-new"}) || dropped != 2 {
		t.Fatalf("capacity 3 = %v dropped %d", got, dropped)
	}
	// Manual bans are never dropped, even beyond capacity.
	manual, dropped := s.Ordered(later, 1)
	if got := ids(manual); !slices.Equal(got, []string{"m1", "m2"}) || dropped != 3 {
		t.Fatalf("capacity 1 = %v dropped %d", got, dropped)
	}
	if n := s.Prune(later); n != 1 || len(s.Bans) != 5 {
		t.Fatalf("prune dropped %d, %d left", n, len(s.Bans))
	}
}

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), File)
	if s, err := Load(path); err != nil || s.Sequence != 0 || len(s.Bans) != 0 {
		t.Fatalf("missing file: %+v, %v", s, err)
	}
	s := New()
	s.ClusterID = "cl-1"
	s.Apply(&nodev1.GetBansResponse{Reset_: true, Sequence: 1 << 60, Bans: []*nodev1.Ban{
		platform("p1", "198.51.100.0/24", time.Hour), site("s1", "2001:db8:1::/48", "site-a", time.Hour),
	}}, now)
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("bans.json mode = %v, %v", st, err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ClusterID != "cl-1" || got.Sequence != 1<<60 || len(got.Bans) != 2 || Diff(s, got).Len() != 0 {
		t.Fatalf("loaded %+v", got)
	}

	// Damaged entries are dropped, the rest is kept.
	raw, _ := os.ReadFile(path)
	raw = []byte(strings.Replace(string(raw), `"scope":"site"`, `"scope":"galaxy"`, 1))
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = Load(path)
	if err == nil || got == nil || len(got.Bans) != 1 || got.Bans["p1"].ID != "p1" {
		t.Fatalf("damaged entry: %+v, %v", got, err)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("unreadable file accepted")
	}
}

func TestPlatform(t *testing.T) {
	s := New()
	s.Apply(&nodev1.GetBansResponse{Reset_: true, Sequence: 1, Bans: []*nodev1.Ban{
		platform("p2", "198.51.100.0/24", time.Hour), platform("p1", "203.0.113.9/32", time.Minute),
		site("s1", "192.0.2.1/32", "site-a", time.Hour),
	}}, now)
	if got := ids(s.Platform(now)); !slices.Equal(got, []string{"p1", "p2"}) {
		t.Fatalf("platform = %v", got)
	}
	if got := ids(s.Platform(now.Add(time.Minute))); !slices.Equal(got, []string{"p2"}) {
		t.Fatalf("platform after expiry = %v", got)
	}
}
