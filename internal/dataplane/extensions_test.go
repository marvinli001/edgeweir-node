package dataplane

import (
	"strings"
	"testing"
)

func TestExtLogFields(t *testing.T) {
	in := map[string]string{"ext.hello-header.greeting": strings.Repeat("x", 300), "ext.hello-header.verdict": "deny", "bad": "x", "ext.X.y": "x"}
	out := extLogFields(in)
	if len(out) != 2 || len(out["ext.hello-header.greeting"]) > maxExtLogValue || out["ext.hello-header.verdict"] != "deny" {
		t.Fatalf("%v", out)
	}
	if extLogFields(map[string]string{"bad": "x"}) != nil {
		t.Fatal("kept an invalid name")
	}
}

func TestExtensionBlockRuleID(t *testing.T) {
	f := logFields{BlockReason: "extension", BlockRuleID: "ext:hello-header"}.bounded()
	if f.BlockReason != "extension" || f.BlockRuleID != "ext:hello-header" {
		t.Fatalf("%+v", f)
	}
	f = logFields{BlockReason: "rule", BlockRuleID: "ext:hello-header"}.bounded()
	if f.BlockRuleID != "" {
		t.Fatalf("an extension rule id on another reason: %+v", f)
	}
}
