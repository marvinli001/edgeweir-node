package agent

import (
	"encoding/json"
	"slices"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// TestLogsSpoolKeepsRuleIDs: the spool's batches keep the log rules that
// asked for a line (AccessLog.rule_ids, proto v0.29.0) across a restart.
func TestLogsSpoolKeepsRuleIDs(t *testing.T) {
	batches, ok := packLogs(4, []*nodev1.AccessLog{{SiteId: "s1", Path: "/", SampleRate: 10000, RuleIds: []string{"r1", "r2"}}, {SiteId: "s1"}})
	if !ok || len(batches) != 1 || batches[0].Sequence != 5 {
		t.Fatalf("batches = %v, %v", batches, ok)
	}
	raw, err := json.Marshal(batches[0])
	if err != nil {
		t.Fatal(err)
	}
	var back logsBatch
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Logs) != 2 || !slices.Equal(back.Logs[0].GetRuleIds(), []string{"r1", "r2"}) || back.Logs[1].GetRuleIds() != nil {
		t.Fatalf("spooled logs = %s", raw)
	}
}

// TestSpoolsKeepG16Fields: the spools keep the access log fields and the
// statistics dimensions of proto v0.30.0 across a restart.
func TestSpoolsKeepG16Fields(t *testing.T) {
	batches, _ := packLogs(0, []*nodev1.AccessLog{{SiteId: "s1", UserAgent: "curl/8", Country: "NZ", Asn: 64512, BlockReason: "rule",
		BlockRuleId: "r1", Query: "a=1", Headers: map[string]string{"x-trace-id": "t"}, PeerIp: "10.0.0.9", UpstreamStatus: 200}})
	raw, err := json.Marshal(batches[0])
	if err != nil {
		t.Fatal(err)
	}
	var back logsBatch
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	l := back.Logs[0]
	if l.GetUserAgent() != "curl/8" || l.GetCountry() != "NZ" || l.GetAsn() != 64512 || l.GetBlockReason() != "rule" || l.GetBlockRuleId() != "r1" ||
		l.GetQuery() != "a=1" || l.GetHeaders()["x-trace-id"] != "t" || l.GetPeerIp() != "10.0.0.9" || l.GetUpstreamStatus() != 200 {
		t.Fatalf("spooled log = %s", raw)
	}
	stats := statsBatch{Sequence: 1, Stats: []*nodev1.MinuteStats{{SiteId: "s1",
		Countries: []*nodev1.CountryCounter{{Country: "", Requests: 1, BytesSent: 2}}, Asns: []*nodev1.AsnCounter{{Asn: 64512, Name: "S", Requests: 1}},
		Referers: []*nodev1.TopCounter{{Value: "r.test", Count: 1}}, Browsers: map[string]uint64{"firefox": 1},
		BlockReasons: map[string]uint64{"rule": 1}, ChallengesIssued: 2, ChallengesPassed: 1}}}
	raw, err = json.Marshal(stats)
	if err != nil {
		t.Fatal(err)
	}
	var sb statsBatch
	if err := json.Unmarshal(raw, &sb); err != nil {
		t.Fatal(err)
	}
	m := sb.Stats[0]
	if len(m.GetCountries()) != 1 || m.GetCountries()[0].GetBytesSent() != 2 || m.GetAsns()[0].GetName() != "S" || m.GetReferers()[0].GetValue() != "r.test" ||
		m.GetBrowsers()["firefox"] != 1 || m.GetBlockReasons()["rule"] != 1 || m.GetChallengesIssued() != 2 || m.GetChallengesPassed() != 1 {
		t.Fatalf("spooled stats = %s", raw)
	}
}
