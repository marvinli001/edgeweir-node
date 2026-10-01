package agent_test

import (
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/agent"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/healthcheck"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeclock"
)

// activeOrigins serves /healthz for two origins told apart by their Host
// header ("one" and "two"); each answers the status stored for it.
func activeOrigins(t *testing.T) (port uint32, one, two *atomic.Int32) {
	t.Helper()
	one, two = &atomic.Int32{}, &atomic.Int32{}
	one.Store(200)
	two.Store(200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		code := one
		if r.Host == "two" {
			code = two
		}
		w.WriteHeader(int(code.Load()))
	}))
	t.Cleanup(srv.Close)
	return uint32(srv.Listener.Addr().(*net.TCPAddr).Port), one, two
}

// activeConfig serves site-a with two origins on 127.0.0.1 (allowed),
// probed every 5 s, one result changing the state; site-b has no check.
func activeConfig(port uint32) *nodev1.NodeConfig {
	a := demoSite("site-a", "site-a.test")
	a.OriginPool.Origins = []*nodev1.Origin{
		{Id: "o1", Address: "127.0.0.1", Port: port, Scheme: nodev1.OriginScheme_ORIGIN_SCHEME_HTTP, Weight: 1, HostHeader: "one"},
		{Id: "o2", Address: "127.0.0.1", Port: port, Scheme: nodev1.OriginScheme_ORIGIN_SCHEME_HTTP, Weight: 1, HostHeader: "two"},
	}
	a.OriginPool.ActiveHealthCheck = &nodev1.ActiveHealthCheck{
		Path: "/healthz", IntervalSeconds: 5, TimeoutSeconds: 2, HealthyThreshold: 1, UnhealthyThreshold: 1,
	}
	c := baseConfig(a, demoSite("site-b", "site-b.test"))
	c.OriginAllowedCidrs = []string{"127.0.0.0/8"}
	c.RequiredFeatures = []string{"active-health-v1"}
	return c
}

func activeEntries(st *nodev1.ReportStatusRequest) []*nodev1.OriginHealth {
	var out []*nodev1.OriginHealth
	for _, h := range st.GetOriginHealth() {
		if h.GetSource() == nodev1.OriginHealthSource_ORIGIN_HEALTH_SOURCE_ACTIVE {
			out = append(out, h)
		}
	}
	return out
}

func marks(dp interface {
	Active() (*dataplane.ActiveHealth, int)
}) ([]dataplane.ActiveOrigin, uint32, int) {
	a, puts := dp.Active()
	if a == nil {
		return nil, 0, puts
	}
	return a.Down, a.TTL, puts
}

// TestAgentActiveHealthChecks: the agent probes the origins of sites with
// an active check, installs the origins it finds down in the data plane
// (on every change, refreshed, again after an nginx restart) and reports
// them in ReportStatus.origin_health with source ACTIVE next to the
// passive entries.
func TestAgentActiveHealthChecks(t *testing.T) {
	port, one, two := activeOrigins(t)
	clock := fakeclock.New(time.Unix(1_800_000_000, 0))
	e := startEnrolledConfig(t, "active", func(c *agent.Config) {
		c.ActiveHealth = healthcheck.Options{Clock: clock, FirstDelay: func(time.Duration) time.Duration { return 0 }}
		c.ActiveHealthRefresh = 300 * time.Millisecond
	}, activeConfig(port))
	if !hasFeature(e.console.LastStatus(), "active-health-v1") {
		t.Fatalf("active-health-v1 not announced: %v", e.console.LastStatus().GetInfo().GetSupportedFeatures())
	}
	if tb := e.dp.Table(); !tb.Sites[0].ActiveHealth || tb.Sites[1].ActiveHealth {
		t.Fatalf("site table active_health = %v, %v", tb.Sites[0].ActiveHealth, tb.Sites[1].ActiveHealth)
	}
	// Both origins are checked; the first probes are due now.
	eventually(t, "checks scheduled", func() bool { return clock.Armed() == 2 })
	eventually(t, "empty set installed", func() bool {
		down, ttl, _ := marks(e.dp)
		return down != nil && len(down) == 0 && ttl == 90
	})

	two.Store(503)
	clock.Advance(0)
	want := []dataplane.ActiveOrigin{{SiteID: "site-a", OriginID: "o2"}}
	eventually(t, "o2 marked down", func() bool {
		down, ttl, _ := marks(e.dp)
		return slices.Equal(down, want) && ttl == 90
	})
	eventually(t, "o2 reported", func() bool { return len(activeEntries(e.console.LastStatus())) == 1 })
	h := activeEntries(e.console.LastStatus())[0]
	if h.GetSiteId() != "site-a" || h.GetOriginId() != "o2" || h.GetHealthy() || h.GetConsecutiveFailures() != 1 ||
		h.GetLastErrorCode() != "upstream_status" || !maps.Equal(h.GetLastErrorParams(), map[string]string{"status": "503"}) ||
		h.GetLastError() != "HTTP 503" || h.GetDownUntil() != nil || !h.GetLastFailureAt().AsTime().Equal(time.Unix(1_800_000_000, 0)) {
		t.Fatalf("active entry = %v", h)
	}

	// The marks are refreshed without changes.
	_, _, puts := marks(e.dp)
	eventually(t, "marks refreshed", func() bool { _, _, n := marks(e.dp); return n >= puts+2 })

	// Passive entries carry their source too.
	e.dp.SetOriginHealth(dataplane.OriginHealth{SiteID: "site-a", OriginID: "o1", Healthy: true, Failures: 1, LastError: "timeout", LastErrorCode: "timeout"})
	eventually(t, "both sources reported", func() bool {
		var sources []string
		for _, h := range e.console.LastStatus().GetOriginHealth() {
			sources = append(sources, h.GetOriginId()+" "+h.GetSource().String())
		}
		slices.Sort(sources)
		return slices.Equal(sources, []string{"o1 ORIGIN_HEALTH_SOURCE_PASSIVE", "o2 ORIGIN_HEALTH_SOURCE_ACTIVE"})
	})

	// An nginx restart loses the marks: they are installed again.
	e.dp.Restart()
	eventually(t, "marks installed after a restart", func() bool {
		down, _, _ := marks(e.dp)
		return slices.Equal(down, want) && e.dp.Table() != nil
	})

	// o2 recovers, o1 fails.
	one.Store(500)
	two.Store(204)
	clock.Advance(5 * time.Second)
	eventually(t, "o1 down, o2 up", func() bool {
		down, _, _ := marks(e.dp)
		return slices.Equal(down, []dataplane.ActiveOrigin{{SiteID: "site-a", OriginID: "o1"}})
	})
	eventually(t, "o1 reported, o2 not", func() bool {
		a := activeEntries(e.console.LastStatus())
		return len(a) == 1 && a[0].GetOriginId() == "o1" && a[0].GetLastErrorParams()["status"] == "500"
	})

	// A configuration without the check clears the marks once.
	cfg := activeConfig(port)
	cfg.Sites[0].OriginPool.ActiveHealthCheck = nil
	cfg.RequiredFeatures = nil
	rev := e.console.Publish(cfg)
	eventually(t, "revision without checks applied", statusWith(e.console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	eventually(t, "marks cleared", func() bool {
		down, _, _ := marks(e.dp)
		return down != nil && len(down) == 0
	})
	if clock.Armed() != 0 {
		t.Fatalf("%d checks still scheduled", clock.Armed())
	}
	_, _, puts = marks(e.dp)
	time.Sleep(700 * time.Millisecond)
	if _, _, n := marks(e.dp); n != puts {
		t.Fatalf("marks pushed %d more times without checks", n-puts)
	}
	if a := activeEntries(e.console.LastStatus()); len(a) != 0 {
		t.Fatalf("active entries without checks: %v", a)
	}
}

// TestAgentActiveHealthTTL: the marks live three of the longest intervals,
// at least 90 seconds.
func TestAgentActiveHealthTTL(t *testing.T) {
	port, _, _ := activeOrigins(t)
	cfg := activeConfig(port)
	cfg.Sites[0].OriginPool.ActiveHealthCheck.IntervalSeconds = 120
	e := startEnrolledConfig(t, "activettl", func(c *agent.Config) {
		c.ActiveHealth = healthcheck.Options{Clock: fakeclock.New(time.Now())}
	}, cfg)
	eventually(t, "marks installed", func() bool {
		_, ttl, _ := marks(e.dp)
		return ttl == 360
	})
}
