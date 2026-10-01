package agent

import (
	"strconv"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/healthcheck"
)

// TestMergeOriginHealth: passive entries keep their fields with source
// PASSIVE, active ones come with source ACTIVE and no down_until; beyond
// 2000 entries the unhealthy ones of either source are kept.
func TestMergeOriginHealth(t *testing.T) {
	failed := time.Unix(1_800_000_000, 0)
	got := mergeOriginHealth(
		[]dataplane.OriginHealth{{SiteID: "a", OriginID: "o1", Failures: 3, LastFailureAt: 1790000000.5, DownUntil: 1790000030,
			LastError: "HTTP 504", LastErrorCode: "upstream_status", LastErrorParams: map[string]string{"status": "504"}}},
		[]healthcheck.Status{{Key: healthcheck.Key{SiteID: "a", OriginID: "o1"}, ConsecutiveFailures: 2, LastFailureAt: failed,
			LastError: "timeout after 5s", LastErrorCode: "timeout"}},
	)
	if len(got) != 2 {
		t.Fatalf("entries = %v", got)
	}
	p, a := got[0], got[1]
	if p.GetSource() != nodev1.OriginHealthSource_ORIGIN_HEALTH_SOURCE_PASSIVE || p.GetConsecutiveFailures() != 3 ||
		p.GetDownUntil().AsTime().Unix() != 1790000030 || p.GetLastFailureAt().AsTime().UnixMilli() != 1790000000500 ||
		p.GetLastErrorParams()["status"] != "504" {
		t.Fatalf("passive entry = %v", p)
	}
	if a.GetSource() != nodev1.OriginHealthSource_ORIGIN_HEALTH_SOURCE_ACTIVE || a.GetDownUntil() != nil || a.GetHealthy() ||
		a.GetConsecutiveFailures() != 2 || !a.GetLastFailureAt().AsTime().Equal(failed) || a.GetLastErrorCode() != "timeout" {
		t.Fatalf("active entry = %v", a)
	}

	var passive []dataplane.OriginHealth
	for i := range 2100 {
		passive = append(passive, dataplane.OriginHealth{SiteID: "s", OriginID: "p" + strconv.Itoa(i), Healthy: i%500 != 0, Failures: 1})
	}
	var active []healthcheck.Status
	for i := range 10 {
		active = append(active, healthcheck.Status{Key: healthcheck.Key{SiteID: "s", OriginID: "a" + strconv.Itoa(i)}, Healthy: i >= 3, ConsecutiveFailures: 1})
	}
	got = mergeOriginHealth(passive, active)
	if len(got) != maxOriginHealth {
		t.Fatalf("%d entries, want %d", len(got), maxOriginHealth)
	}
	unhealthy := 0
	for i, h := range got {
		if !h.GetHealthy() {
			unhealthy++
			if i >= 8 {
				t.Fatalf("unhealthy entry %d after healthy ones", i)
			}
		}
	}
	if unhealthy != 5+3 {
		t.Fatalf("%d unhealthy entries kept, want 8", unhealthy)
	}
}
