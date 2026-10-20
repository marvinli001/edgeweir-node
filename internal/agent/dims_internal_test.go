package agent

import (
	"fmt"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
)

// TestConvertStatsCarriesDimensions: MinuteStats 14-24 (feature
// stats-dims-v1, ADR-0041) with their bounds and key sets.
func TestConvertStatsCarriesDimensions(t *testing.T) {
	countries := map[string]dataplane.CountryCount{"": {Requests: 30, BytesSent: 30}, "nz": {Requests: 99}, "NZL": {Requests: 99}, "ZZ": {}}
	letters := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for i := range 26 {
		for j := range 11 {
			countries[letters[i:i+1]+letters[j:j+1]] = dataplane.CountryCount{Requests: uint64(1 + i), BytesSent: 1}
		}
	}
	countries["NZ"] = dataplane.CountryCount{Requests: 1000, BytesSent: 5000}
	asns := map[string]dataplane.ASNCount{"0": {Requests: 9}, "x": {Requests: 9}, "007": {Requests: 9}, "4294967296": {Requests: 9},
		"64512": {Requests: 500, Name: "Synthetic AS64512 " + strings.Repeat("n", 200) + "\x1b"}}
	referers := map[string]uint64{"Upper.test": 9, "bad host.test": 9, "-lead.test": 9, strings.Repeat("a", 254): 9, "heavy.test": 400, "1.2.3.4": 2, "under_score.test": 1}
	for i := range 80 {
		asns[fmt.Sprint(65000+i)] = dataplane.ASNCount{Requests: uint64(i + 1)}
		referers[fmt.Sprintf("r%d.test", i)] = uint64(i + 1)
	}
	out := convertStats([]dataplane.MinuteStats{{
		Minute: 1800000000, SiteID: "s1", Requests: 10, Countries: countries, ASNs: asns, Referers: referers,
		Browsers:         map[string]uint64{"firefox": 2, "netscape": 1, "chrome": 0},
		OperatingSystems: map[string]uint64{"harmonyos": 1, "beos": 1},
		Devices:          map[string]uint64{"tablet": 1, "fridge": 1},
		HTTPVersions:     map[string]uint64{"3": 1, "0.9": 1},
		TLSVersions:      map[string]uint64{"none": 1, "1.0": 1},
		BlockReasons:     map[string]uint64{"crs": 2, "geo": 1},
		ChallengesIssued: 7, ChallengesPassed: 3,
	}, {Minute: 1800000000, SiteID: "bare"}})
	m := out[0]
	if len(m.GetCountries()) != 250 || m.GetCountries()[0].GetCountry() != "NZ" || m.GetCountries()[0].GetBytesSent() != 5000 {
		t.Errorf("countries %d, first %v", len(m.GetCountries()), m.GetCountries()[0])
	}
	unknown := false
	for _, c := range m.GetCountries() {
		if c.GetCountry() == "nz" || c.GetCountry() == "NZL" || c.GetCountry() == "ZZ" {
			t.Errorf("invalid country %v", c)
		}
		if c.GetCountry() == "" {
			unknown = c.GetRequests() == 30 && c.GetBytesSent() == 30
		}
	}
	if !unknown {
		t.Error("the unknown country is missing")
	}
	if len(m.GetAsns()) != 50 || m.GetAsns()[0].GetAsn() != 64512 || len(m.GetAsns()[0].GetName()) != 128 || strings.ContainsRune(m.GetAsns()[0].GetName(), 0x1b) {
		t.Errorf("asns %d, first %v", len(m.GetAsns()), m.GetAsns()[0])
	}
	for _, a := range m.GetAsns() {
		if a.GetAsn() == 0 || a.GetAsn() == 7 {
			t.Errorf("invalid network %v", a)
		}
	}
	if len(m.GetReferers()) != 50 || m.GetReferers()[0].GetValue() != "heavy.test" {
		t.Errorf("referers %d, first %v", len(m.GetReferers()), m.GetReferers()[0])
	}
	for _, r := range m.GetReferers() {
		if v := r.GetValue(); v == "Upper.test" || v == "bad host.test" || v == "-lead.test" || len(v) > 253 {
			t.Errorf("invalid referring host %q", v)
		}
	}
	if len(m.GetBrowsers()) != 1 || m.GetBrowsers()["firefox"] != 2 || len(m.GetOperatingSystems()) != 1 || m.GetOperatingSystems()["harmonyos"] != 1 ||
		len(m.GetDevices()) != 1 || len(m.GetHttpVersions()) != 1 || m.GetHttpVersions()["3"] != 1 || len(m.GetTlsVersions()) != 1 ||
		len(m.GetBlockReasons()) != 1 || m.GetBlockReasons()["crs"] != 2 || m.GetChallengesIssued() != 7 || m.GetChallengesPassed() != 3 {
		t.Errorf("maps %v", m)
	}
	b := out[1]
	if b.GetCountries() != nil || b.GetAsns() != nil || b.GetReferers() != nil || b.GetBrowsers() != nil || b.GetBlockReasons() != nil {
		t.Errorf("a bucket without dimensions: %v", b)
	}
}

func TestValidRefererHost(t *testing.T) {
	for host, want := range map[string]bool{
		"news.example.org": true, "1.2.3.4": true, "under_score.test": true, "a": true, strings.Repeat("a", 63) + ".test": true,
		"": false, "Upper.test": false, "a..b": false, "-a.test": false, "a-.test": false, "2001:db8::1": false,
		strings.Repeat("a", 64) + ".test": false, strings.Repeat("a.", 127) + "ab": false,
	} {
		if got := validRefererHost(host); got != want {
			t.Errorf("validRefererHost(%q) = %v", host, got)
		}
	}
}

// TestConvertStatsCarriesOrigins: MinuteStats.origins (feature
// origin-stats-v1, ADR-0052): valid ids with attempts, the 64 with the
// most, and header times only with one bucket per bound and one above.
func TestConvertStatsCarriesOrigins(t *testing.T) {
	buckets := []uint64{1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 4}
	origins := map[string]dataplane.OriginCount{
		"o-heavy":   {Requests: 500, ConnectFailures: 1, Timeouts: 2, TLSFailures: 3, InvalidResponses: 4, ServerErrors: 5, HeaderTimeBuckets: buckets, HeaderTimeMSSum: 41000},
		"o-short":   {Requests: 400, HeaderTimeBuckets: []uint64{1, 2}, HeaderTimeMSSum: 9},
		"bad|id":    {Requests: 300},
		"o-silent":  {},
		"o-no-time": {Requests: 300, ConnectFailures: 300},
	}
	for i := range 70 {
		origins[fmt.Sprintf("o%02d", i)] = dataplane.OriginCount{Requests: uint64(i + 1)}
	}
	out := convertStats([]dataplane.MinuteStats{{Minute: 1800000000, SiteID: "s1", Requests: 10, Origins: origins}, {Minute: 1800000000, SiteID: "bare"}})
	o := out[0].GetOrigins()
	if len(o) != 64 || o[0].GetOriginId() != "o-heavy" || o[1].GetOriginId() != "o-short" || o[2].GetOriginId() != "o-no-time" {
		t.Fatalf("origins %d: %v", len(o), o[:3])
	}
	h := o[0]
	if h.GetRequests() != 500 || h.GetConnectFailures() != 1 || h.GetTimeouts() != 2 || h.GetTlsFailures() != 3 || h.GetInvalidResponses() != 4 ||
		h.GetServerErrors() != 5 || fmt.Sprint(h.GetHeaderTimeBuckets()) != fmt.Sprint(buckets) || h.GetHeaderTimeMsSum() != 41000 {
		t.Errorf("heavy %v", h)
	}
	if o[1].GetHeaderTimeBuckets() != nil || o[1].GetHeaderTimeMsSum() != 0 || o[1].GetRequests() != 400 {
		t.Errorf("short buckets kept: %v", o[1])
	}
	for _, c := range o {
		if c.GetOriginId() == "bad|id" || c.GetOriginId() == "o-silent" || c.GetOriginId() == "o00" {
			t.Errorf("unexpected origin %v", c)
		}
	}
	if out[1].GetOrigins() != nil {
		t.Errorf("a bucket without origins: %v", out[1].GetOrigins())
	}
}
