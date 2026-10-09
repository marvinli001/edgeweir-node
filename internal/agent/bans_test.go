package agent_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marvinli001/edgeweir-node/internal/agent"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/nft"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

func consoleBan(id, cidr string, scope nodev1.BanScope, site string, source nodev1.BanSource, created time.Duration) *nodev1.Ban {
	now := time.Now()
	return &nodev1.Ban{
		Id: id, Cidr: cidr, Scope: scope, SiteId: site, Source: source, Reason: "abuse",
		CreatedAt: timestamppb.New(now.Add(created)), ExpiresAt: timestamppb.New(now.Add(time.Hour)),
	}
}

func platformBan(id, cidr string) *nodev1.Ban {
	return consoleBan(id, cidr, nodev1.BanScope_BAN_SCOPE_PLATFORM, "", nodev1.BanSource_BAN_SOURCE_MANUAL, -time.Minute)
}

func siteBan(id, cidr, site string) *nodev1.Ban {
	return consoleBan(id, cidr, nodev1.BanScope_BAN_SCOPE_SITE, site, nodev1.BanSource_BAN_SOURCE_MANUAL, -time.Minute)
}

func banIDs(list []dataplane.Ban) []string {
	var out []string
	for _, b := range list {
		out = append(out, b.ID)
	}
	slices.Sort(out)
	return out
}

func lastBanStatus(e *enrolled) *nodev1.BanStatus { return e.console.LastStatus().GetBans() }

func hasFeature(st *nodev1.ReportStatusRequest, f string) bool {
	return slices.Contains(st.GetInfo().GetSupportedFeatures(), f)
}

// TestBansChannel follows console bans to the data plane (deltas, full
// replacement after an nginx restart), to nftables and to disk, reports
// the node's own bans and restores everything at startup without the
// console.
func TestBansChannel(t *testing.T) {
	kernel := &nft.Fake{}
	e := startEnrolled(t, "bans", func(c *agent.Config) { c.Kernel = kernel }, demoSite("site-a", "site-a.test"))

	// The console's first ban arrives as a snapshot (after_sequence 0),
	// later ones as deltas.
	seq := e.console.AddBan(platformBan("p1", "198.51.100.0/24"))
	eventually(t, "first ban in the data plane", func() bool { return e.dp.BanSequence() == seq })
	seq = e.console.AddBan(siteBan("s1", "203.0.113.7/32", "site-a"))
	eventually(t, "bans in the data plane", func() bool {
		return e.dp.BanSequence() == seq && slices.Equal(banIDs(e.dp.Bans()), []string{"p1", "s1"})
	})
	if calls := e.dp.BanCalls(); calls[len(calls)-1] != "POST" {
		t.Fatalf("ban writes = %v, want a delta", calls)
	}
	for _, b := range e.dp.Bans() {
		if b.ID == "s1" && (b.Scope != "site" || b.SiteID != "site-a" || b.Kind != "m" || b.CIDR != "203.0.113.7/32") {
			t.Fatalf("site ban in the data plane = %+v", b)
		}
	}
	eventually(t, "platform ban in nftables", func() bool {
		return strings.Contains(kernel.Last("flush set"), "add element inet edgeweir ban4 { 198.51.100.0/24 timeout ")
	})
	if script := kernel.Last("flush set"); !regexp.MustCompile(`(?m)^add element inet edgeweir allow4 \{ .*127\.0\.0\.0/8`).MatchString(script) ||
		strings.Contains(script, "203.0.113.7") {
		t.Fatalf("kernel sync (site bans stay out of nftables):\n%s", script)
	}
	eventually(t, "ban status reported", func() bool {
		st := e.console.LastStatus()
		b := st.GetBans()
		return b.GetAppliedSequence() == seq && b.GetEntries() == 2 && b.GetKernelEntries() == 1 &&
			b.GetCapacity() == 100000 && hasFeature(st, "bans-v1") && hasFeature(st, "kernel-ban-v1")
	})

	// Unban: a delta removes it everywhere.
	seq = e.console.RemoveBan("s1")
	eventually(t, "site ban removed", func() bool {
		return e.dp.BanSequence() == seq && slices.Equal(banIDs(e.dp.Bans()), []string{"p1"})
	})
	raw, err := os.ReadFile(filepath.Join(e.cfg.StateDir, "bans.json"))
	if err != nil || !strings.Contains(string(raw), `"p1"`) || strings.Contains(string(raw), `"s1"`) {
		t.Fatalf("bans.json = %s, %v", raw, err)
	}
	if st, _ := os.Stat(filepath.Join(e.cfg.StateDir, "bans.json")); st.Mode().Perm() != 0o600 {
		t.Fatalf("bans.json mode %v", st.Mode())
	}

	// nginx restarted: the whole set goes in again.
	e.dp.Restart()
	eventually(t, "bans installed again after a data plane restart", func() bool {
		calls := e.dp.BanCalls()
		return e.dp.BanSequence() == seq && len(e.dp.Bans()) == 1 && calls[len(calls)-1] == "PUT"
	})

	// Own bans are drained and reported, also after a failed attempt.
	e.console.FailReportBans(1)
	e.dp.AddAutoBans(dataplane.AutoBan{SiteID: "site-a", IP: "::ffff:192.0.2.9", PrefixLen: 128, CreatedAt: 1790000000.25,
		ExpiresAt: 1790000600.25, Reason: "cc_ip_rate", Metric: "ip_qps", Observed: 210, Threshold: 100, WindowSeconds: 10},
		dataplane.AutoBan{SiteID: "bad site", IP: "192.0.2.10", ExpiresAt: 1790000600})
	eventually(t, "own ban reported", func() bool { return len(e.console.ReportedBans()) == 1 })
	got := e.console.ReportedBans()[0]
	if got.GetSiteId() != "site-a" || got.GetCidr() != "192.0.2.9/32" || got.GetMetric() != "ip_qps" || got.GetObserved() != 210 ||
		got.GetThreshold() != 100 || got.GetWindowSeconds() != 10 || got.GetReason() != "cc_ip_rate" ||
		got.GetExpiresAt().AsTime().Sub(got.GetCreatedAt().AsTime()) != 10*time.Minute {
		t.Fatalf("reported own ban = %v", got)
	}

	// Shutdown removes the table.
	e.stop()
	if scripts := kernel.Scripts(); scripts[len(scripts)-1] != nft.StopScript {
		t.Fatalf("last nft script = %q, want the table deleted", scripts[len(scripts)-1])
	}

	// Next start: the stored bans are installed in the data plane and
	// nftables before the console is asked.
	calls := len(e.console.GetBansCalls())
	dp2 := fakedataplane.Start(t)
	kernel2 := &nft.Fake{}
	cfg := e.cfg
	cfg.Kernel = kernel2
	cfg.Render.ControlSocket = dp2.Socket
	startAgent(t, cfg, newFakeEngine(), dataplane.NewClient(dp2.Socket))
	eventually(t, "stored bans restored", func() bool {
		return dp2.BanSequence() == seq && slices.Equal(banIDs(dp2.Bans()), []string{"p1"})
	})
	if dp2.BanCalls()[0] != "PUT" {
		t.Fatalf("ban writes after the restart = %v", dp2.BanCalls())
	}
	_ = calls
	eventually(t, "stored platform ban in nftables", func() bool {
		return strings.Contains(kernel2.Last("flush set"), "198.51.100.0/24 timeout")
	})
	if kernel2.Scripts()[0] != nft.SetupScript {
		t.Fatalf("first nft script = %q", kernel2.Scripts()[0])
	}
}

// TestBansEmptyConsoleIsQuiet: a console without any ban answers every
// poll with an empty snapshot; the node does not rewrite anything.
func TestBansEmptyConsoleIsQuiet(t *testing.T) {
	kernel := &nft.Fake{}
	e := startEnrolled(t, "bans-quiet", func(c *agent.Config) {
		c.Kernel = kernel
		c.PollInterval = 100 * time.Millisecond
	}, demoSite("site-a", "site-a.test"))
	eventually(t, "several polls", func() bool { return len(e.console.GetBansCalls()) >= 5 })
	calls, scripts := len(e.dp.BanCalls()), len(kernel.Scripts())
	eventually(t, "more polls", func() bool { return len(e.console.GetBansCalls()) >= 10 })
	if len(e.dp.BanCalls()) != calls || len(kernel.Scripts()) != scripts {
		t.Fatalf("empty snapshots rewrote bans: data plane %v, %d nft scripts (was %d)", e.dp.BanCalls(), len(kernel.Scripts()), scripts)
	}
}

// TestBansCapacityKeepsManualAndNewestAutomatic: beyond --ban-capacity the
// oldest automatic bans are left out, manual ones never.
func TestBansCapacityKeepsManualAndNewestAutomatic(t *testing.T) {
	e := startEnrolled(t, "bans-cap", func(c *agent.Config) { c.BanCapacity = 2 }, demoSite("site-a", "site-a.test"))
	e.dp.SetBanCapacity(2) // like the data plane with --ban-capacity 2
	auto := func(id, cidr string, created time.Duration) *nodev1.Ban {
		return consoleBan(id, cidr, nodev1.BanScope_BAN_SCOPE_SITE, "site-a", nodev1.BanSource_BAN_SOURCE_AUTO, created)
	}
	var seq uint64
	for _, b := range []*nodev1.Ban{
		siteBan("m1", "192.0.2.3/32", "site-a"), // the first ban arrives in a snapshot
		auto("a-old", "192.0.2.1/32", -3*time.Hour),
		auto("a-new", "192.0.2.2/32", -time.Hour), // a-old is left out from here on
		auto("a-mid", "192.0.2.4/32", -2*time.Hour),
	} {
		seq = e.console.AddBan(b)
		eventually(t, "ban "+b.GetId()+" applied", func() bool { return e.dp.BanSequence() == seq })
	}
	eventually(t, "manual and newest automatic ban held", func() bool {
		return e.dp.BanSequence() == seq && slices.Equal(banIDs(e.dp.Bans()), []string{"a-new", "m1"})
	})
	// Deltas stay within the capacity: the left-out ban is removed before
	// the newer one is written.
	if calls := e.dp.BanCalls(); calls[len(calls)-1] != "POST" {
		t.Fatalf("ban writes = %v, want deltas", calls)
	}
	if st, err := dataplane.NewClient(e.dp.Socket).BanStatus(context.Background()); err != nil || st.Unapplied != 0 || st.AutoEvicted != 0 {
		t.Fatalf("data plane status = %+v, %v", st, err)
	}
	eventually(t, "left-out automatic bans reported", func() bool {
		return lastBanStatus(e).GetAutoEvicted() == 2 && lastBanStatus(e).GetCapacity() == 2
	})
}

// TestBansWithoutKernel: when nft cannot be used the node still enforces
// bans at the edge layer and does not claim kernel-ban-v1.
func TestBansWithoutKernel(t *testing.T) {
	kernel := &nft.Fake{Fail: func(string) error { return errors.New("nft: Operation not permitted") }}
	e := startEnrolled(t, "bans-l7", func(c *agent.Config) { c.Kernel = kernel }, demoSite("site-a", "site-a.test"))
	seq := e.console.AddBan(platformBan("p1", "198.51.100.0/24"))
	eventually(t, "ban in the data plane", func() bool { return e.dp.BanSequence() == seq && len(e.dp.Bans()) == 1 })
	eventually(t, "status without kernel bans", func() bool {
		st := e.console.LastStatus()
		return st.GetBans().GetAppliedSequence() == seq && hasFeature(st, "bans-v1") && !hasFeature(st, "kernel-ban-v1") &&
			st.GetBans().GetKernelEntries() == 0
	})
	if n := len(kernel.Scripts()); n != 1 {
		t.Fatalf("%d nft scripts after a failed probe, want only the probe", n)
	}
}

// TestBansUnappliedManualBansAreRetried: a manual ban the data plane cannot
// hold is reported and retried until it fits.
func TestBansUnappliedManualBansAreRetried(t *testing.T) {
	e := startEnrolled(t, "bans-retry", func(c *agent.Config) { c.BanRetryInterval = 200 * time.Millisecond }, demoSite("site-a", "site-a.test"))
	e.dp.SetBanCapacity(1)
	e.console.AddBan(siteBan("m1", "192.0.2.1/32", "site-a"))
	seq := e.console.AddBan(siteBan("m2", "192.0.2.2/32", "site-a"))
	eventually(t, "unapplied manual ban reported", func() bool {
		b := lastBanStatus(e)
		return b.GetAppliedSequence() == seq && b.GetUnapplied() == 1 && slices.Equal(b.GetUnappliedIds(), []string{"m2"})
	})
	e.dp.SetBanCapacity(10)
	eventually(t, "manual ban retried", func() bool {
		return slices.Equal(banIDs(e.dp.Bans()), []string{"m1", "m2"}) && lastBanStatus(e).GetUnapplied() == 0
	})
}

// TestBansResetAfterConsoleRestore: a console whose sequence went back
// (restored database) answers with a snapshot; the node replaces its set.
func TestBansResetAfterConsoleRestore(t *testing.T) {
	e := startEnrolled(t, "bans-reset", func(c *agent.Config) { c.PollInterval = 300 * time.Millisecond }, demoSite("site-a", "site-a.test"))
	e.console.AddBan(platformBan("p1", "198.51.100.0/24"))
	e.console.AddBan(platformBan("p2", "198.51.101.0/24"))
	seq := e.console.RemoveBan("p1")
	eventually(t, "bans applied", func() bool { return e.dp.BanSequence() == seq && len(e.dp.Bans()) == 1 })
	e.console.SetBanSequence(1)
	restored := e.console.AddBan(platformBan("p3", "198.51.102.0/24"))
	eventually(t, "snapshot after the restore", func() bool {
		calls := e.dp.BanCalls()
		return e.dp.BanSequence() == restored && slices.Equal(banIDs(e.dp.Bans()), []string{"p2", "p3"}) && calls[len(calls)-1] == "PUT"
	})
}

// TestBansSnapshotPages: a snapshot larger than a page arrives in several
// GetBans calls and is installed once.
func TestBansSnapshotPages(t *testing.T) {
	e := startEnrolled(t, "bans-pages", nil, demoSite("site-a", "site-a.test"))
	e.stop()
	e.console.SetBanPageLimit(2)
	var seq uint64
	for _, cidr := range []string{"198.51.100.1/32", "198.51.100.2/32", "198.51.100.3/32", "198.51.100.4/32", "198.51.100.5/32"} {
		seq = e.console.AddBan(platformBan("p"+cidr[11:12], cidr))
	}
	if err := os.Remove(filepath.Join(e.cfg.StateDir, "bans.json")); err != nil {
		t.Fatal(err)
	}
	e.dp.Restart()
	calls := len(e.console.GetBansCalls())
	startAgent(t, e.cfg, e.eng, dataplane.NewClient(e.dp.Socket))
	eventually(t, "every page applied", func() bool { return e.dp.BanSequence() == seq && len(e.dp.Bans()) == 5 })
	var afters []uint64
	for _, c := range e.console.GetBansCalls()[calls:] {
		afters = append(afters, c.GetAfterSequence())
	}
	if len(afters) < 3 || afters[0] != 0 || afters[1] == 0 || afters[2] <= afters[1] {
		t.Fatalf("GetBans after_sequence per call = %v, want 0 then advancing pages", afters)
	}
}

// TestBansLiftedOwnBansAreReleased: an own ban the console lifted without
// sharing it is deleted in the data plane, retried after a failure;
// expired or invalid ones are not sent. A ban a rule made may hold a
// network (IPv4 /16-/32, IPv6 /48-/64, proto v0.29.0).
func TestBansLiftedOwnBansAreReleased(t *testing.T) {
	e := startEnrolled(t, "bans-lift", func(c *agent.Config) { c.PollInterval = 100 * time.Millisecond },
		demoSite("site-a", "site-a.test"))
	// Lifts arrive in delta pages: the node holds a sequence first.
	first := e.console.AddBan(platformBan("p1", "198.51.100.0/24"))
	eventually(t, "first ban applied", func() bool { return e.dp.BanSequence() == first })
	e.dp.FailNextReleases(1)
	own := consoleBan("own-1", "192.0.2.9/32", nodev1.BanScope_BAN_SCOPE_SITE, "site-a", nodev1.BanSource_BAN_SOURCE_AUTO, -time.Minute)
	expired := consoleBan("own-2", "192.0.2.10/32", nodev1.BanScope_BAN_SCOPE_SITE, "site-a", nodev1.BanSource_BAN_SOURCE_AUTO, -time.Hour)
	expired.ExpiresAt = timestamppb.New(time.Now().Add(-time.Second))
	invalid := consoleBan("own-3", "192.0.0.0/15", nodev1.BanScope_BAN_SCOPE_SITE, "site-a", nodev1.BanSource_BAN_SOURCE_AUTO, -time.Minute)
	// IPv6 clients are banned by their /64.
	own6 := consoleBan("own-4", "2001:db8:5:6::/64", nodev1.BanScope_BAN_SCOPE_SITE, "site-a", nodev1.BanSource_BAN_SOURCE_AUTO, -time.Minute)
	rule := consoleBan("own-5", "203.0.113.0/24", nodev1.BanScope_BAN_SCOPE_SITE, "site-a", nodev1.BanSource_BAN_SOURCE_AUTO, -time.Minute)
	e.console.LiftOwnBan(expired)
	e.console.LiftOwnBan(invalid)
	e.console.LiftOwnBan(own6)
	e.console.LiftOwnBan(rule)
	seq := e.console.LiftOwnBan(own)
	eventually(t, "lifted own bans deleted after a retry", func() bool { return len(e.dp.Released()) == 3 })
	got := e.dp.Released()
	if got[0].SiteID != "site-a" || got[0].CIDR != "2001:db8:5:6::/64" || got[1].CIDR != "203.0.113.0/24" || got[2].CIDR != "192.0.2.9/32" ||
		got[2].ExpiresAt != float64(own.GetExpiresAt().AsTime().UnixMilli())/1000 {
		t.Fatalf("released = %+v", got)
	}
	eventually(t, "sequence applied", func() bool { return e.dp.BanSequence() == seq })
	// Done once: later fetches send nothing again.
	calls := len(e.console.GetBansCalls())
	eventually(t, "more polls", func() bool { return len(e.console.GetBansCalls()) >= calls+3 })
	if n := len(e.dp.Released()); n != 3 {
		t.Fatalf("released %d times", n)
	}
}
