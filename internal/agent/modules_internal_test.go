package agent

import (
	"fmt"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
)

func TestConvertStatsCarriesLoggedRules(t *testing.T) {
	rules := map[string]uint64{
		"0d4c2b8e-5f1a-4c3e-9b7d-2a6f8e1c0b9a": 9,
		"platform-rule":                        4,
		"not|an id":                            99,
		"":                                     7,
		"zero":                                 0,
	}
	for i := range 30 {
		rules[fmt.Sprintf("r%02d", i)] = 1
	}
	out := convertStats([]dataplane.MinuteStats{{Minute: 1800000000, SiteID: "s1", Requests: 12, LoggedRules: rules}, {Minute: 1800000000, SiteID: "s2"}})
	got := out[0].GetLoggedRules()
	if len(got) != maxLoggedRules {
		t.Fatalf("%d rules, want %d", len(got), maxLoggedRules)
	}
	want := []string{"0d4c2b8e-5f1a-4c3e-9b7d-2a6f8e1c0b9a", "platform-rule", "r00", "r01"}
	for i, id := range want {
		if got[i].GetValue() != id {
			t.Fatalf("rule %d = %s (%d), want %s", i, got[i].GetValue(), got[i].GetCount(), id)
		}
	}
	for _, c := range got {
		if c.GetValue() == "not|an id" || c.GetValue() == "" || c.GetValue() == "zero" {
			t.Fatalf("invalid rule %q reported", c.GetValue())
		}
	}
	if out[1].GetLoggedRules() != nil {
		t.Fatalf("a minute without log rule matches reports %v", out[1].GetLoggedRules())
	}
}

func TestConvertStatsCarriesCRSRules(t *testing.T) {
	rules := map[string]uint64{"949110": 7, "941100": 7, "920350": 12, "not-an-id": 99, "0": 5, "0942100": 3}
	for i := range 30 {
		rules[fmt.Sprint(930000+i)] = 1
	}
	out := convertStats([]dataplane.MinuteStats{{Minute: 1800000000, SiteID: "s1", Requests: 12, WAFRules: rules}, {Minute: 1800000000, SiteID: "s2"}})
	got := out[0].GetWafRules()
	if len(got) != maxWAFRules {
		t.Fatalf("%d rules, want %d", len(got), maxWAFRules)
	}
	want := []string{"920350", "941100", "949110", "930000"}
	for i, id := range want {
		if got[i].GetValue() != id {
			t.Fatalf("rule %d = %s (%d), want %s", i, got[i].GetValue(), got[i].GetCount(), id)
		}
	}
	for _, c := range got {
		if c.GetValue() == "not-an-id" || c.GetValue() == "0" || c.GetValue() == "0942100" {
			t.Fatalf("invalid rule id %q reported", c.GetValue())
		}
	}
	if out[1].GetWafRules() != nil {
		t.Fatalf("a minute without CRS matches reports %v", out[1].GetWafRules())
	}
}
