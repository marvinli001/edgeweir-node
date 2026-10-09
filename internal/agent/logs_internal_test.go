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
