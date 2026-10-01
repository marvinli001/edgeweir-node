package configir

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestPolicyValidation(t *testing.T) {
	valid := &nodev1.NodeConfig{PlatformRules: []*nodev1.EdgeRule{{Id: "r", Phase: "waf-custom", Expression: &nodev1.RuleExpression{Op: "literal", ValueType: "boolean", Value: "true"}, Action: &nodev1.RuleAction{Kind: "block", StatusCode: 403}}}}
	if _, err := Build(valid, Options{}); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*nodev1.NodeConfig){
		"unknown op":  func(c *nodev1.NodeConfig) { c.PlatformRules[0].Expression.Op = "execute" },
		"wrong phase": func(c *nodev1.NodeConfig) { c.PlatformRules[0].Phase = "redirect" },
		"missing list": func(c *nodev1.NodeConfig) {
			c.PlatformRules[0].Expression = &nodev1.RuleExpression{Op: "in_list", Field: "ip.src", ValueType: "ip", Value: "missing"}
		},
		"tenant list in platform rule": func(c *nodev1.NodeConfig) {
			c.IpLists = []*nodev1.IpList{{Id: "tenant", Kind: "collection"}}
			c.PlatformRules[0].Expression = &nodev1.RuleExpression{Op: "in_list", Field: "ip.src", ValueType: "ip", Value: "tenant"}
		},
		"protected header": func(c *nodev1.NodeConfig) {
			c.PlatformRules[0].Phase = "request-transform"
			c.PlatformRules[0].Action = &nodev1.RuleAction{Kind: "request_header", Header: "host", Value: "evil"}
		},
		"missing GeoIP": func(c *nodev1.NodeConfig) {
			c.PlatformRules[0].Expression = &nodev1.RuleExpression{Op: "eq", Field: "ip.geoip.country", ValueType: "string", Value: "NZ"}
		},
		"invalid CIDR": func(c *nodev1.NodeConfig) {
			c.IpLists = []*nodev1.IpList{{Id: "list", Kind: "block", Entries: []string{"127.1"}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := proto.CloneOf(valid)
			change(c)
			if _, err := Build(c, Options{}); err == nil {
				t.Fatal("accepted invalid policy")
			}
		})
	}
	for _, test := range []struct {
		field, typ, value string
		feature, other    string
	}{
		{"ip.geoip.country", "string", "NZ", "geoip-country-v1", "geoip-asn-v1"},
		// geoip-city-v1 alone (IPinfo Lite, no City MMDB) does not cover subdivisions.
		{"ip.geoip.subdivision", "string", "AUK", "geoip-subdivision-v1", "geoip-city-v1"},
		{"ip.geoip.asnum", "number", "64512", "geoip-asn-v1", "geoip-country-v1"},
	} {
		geo := proto.CloneOf(valid)
		geo.PlatformRules[0].Expression = &nodev1.RuleExpression{Op: "eq", Field: test.field, ValueType: test.typ, Value: test.value}
		if _, err := Build(geo, Options{ExtraFeatures: []string{test.feature}}); err != nil {
			t.Fatalf("%s with %s: %v", test.field, test.feature, err)
		}
		if _, err := Build(geo, Options{ExtraFeatures: []string{test.other}}); err == nil {
			t.Fatalf("%s accepted with only %s", test.field, test.other)
		}
	}
}

// TestSharedExpressionVectors reads the console's shared vectors (a copy of
// packages/rule-engine/test/vectors.json that Lua also runs): configir accepts
// every accepted condition and value expression with its action, refuses
// every rejected pattern and IR, keeps the structured form of cache
// conditions, and for `matches` RE2 over the value's bytes (one rune per
// byte, like PCRE2 without UTF) gives the expected result, a third engine
// next to JavaScript and PCRE2. Derivation vectors are Lua's alone.
func TestSharedExpressionVectors(t *testing.T) {
	data, err := os.ReadFile("../../test/lua/expression-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Source   string          `json:"source"`
		Phase    string          `json:"phase"`
		Rejected bool            `json:"rejected"`
		Reason   string          `json:"reason"`
		Action   json.RawMessage `json:"action"`
		// ActionRejected: nodes refuse the action in this phase.
		ActionRejected bool `json:"actionRejected"`
		// IRRejected: the IR itself is refused (Value: as a value
		// expression); otherwise a rejected vector's IR holds a pattern
		// outside the subset.
		IRRejected bool                `json:"irRejected"`
		Value      bool                `json:"value"`
		Request    map[string]any      `json:"request"`
		Lists      map[string][]string `json:"lists"`
		Expected   json.RawMessage     `json:"expected"`
		IR         json.RawMessage     `json:"ir"`
		Structured *struct {
			PathPrefixes []string `json:"pathPrefixes"`
			Paths        []string `json:"paths"`
			Extensions   []string `json:"extensions"`
		} `json:"structured"`
		Derive string `json:"derive"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	features := []string{"geoip-country-v1", "geoip-subdivision-v1", "geoip-asn-v1"}
	counts := map[string]int{}
	for i, v := range vectors {
		if v.Derive != "" {
			counts["derive"]++
			continue
		}
		e := &nodev1.RuleExpression{}
		if err := protojson.Unmarshal(v.IR, e); err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		lists := map[string]bool{}
		for id := range v.Lists {
			lists[id] = true
		}
		validate := func() error {
			if v.Value {
				return validateValueExpression(e, v.Phase, features)
			}
			return validateCondition(e, v.Phase, lists, features)
		}
		err := validate()
		if v.Rejected {
			if err == nil {
				t.Errorf("vector %d accepted %s (%s)", i, v.Source, v.Reason)
			}
			if v.IRRejected {
				counts["irRejected"]++
			} else {
				counts["pattern"]++
				if e.Op != "matches" || validPattern(e.Value) {
					t.Errorf("vector %d: pattern %q of %s is not refused by validPattern", i, e.Value, v.Source)
				}
			}
			continue
		}
		if err != nil {
			t.Errorf("vector %d refused %s: %v", i, v.Source, err)
			continue
		}
		if v.Value {
			counts["value"]++
			// A string is never a condition.
			if validateCondition(e, v.Phase, lists, features) == nil {
				t.Errorf("vector %d: value %s accepted as a condition", i, v.Source)
			}
		} else {
			counts["condition"]++
		}
		if len(v.Action) > 0 {
			counts["action"]++
			a := &nodev1.RuleAction{}
			if err := protojson.Unmarshal(v.Action, a); err != nil {
				t.Fatalf("vector %d action: %v", i, err)
			}
			rule := &nodev1.EdgeRule{Id: "vector", Phase: v.Phase, Expression: e, Action: a}
			err := validateRuleSet([]*nodev1.EdgeRule{rule}, lists, features, 64)
			if v.ActionRejected && err == nil {
				t.Errorf("vector %d accepted action %s in %s (%s)", i, v.Action, v.Phase, v.Reason)
			}
			if !v.ActionRejected && err != nil {
				t.Errorf("vector %d refused action %s in %s: %v", i, v.Action, v.Phase, err)
			}
		}
		if st := v.Structured; st != nil {
			// The structured form travels unchanged: buildRule keeps every
			// entry, and the condition form is a valid cache rule too.
			counts["structured"]++
			r := &nodev1.CacheRule{Id: "vector", Action: nodev1.CacheAction_CACHE_ACTION_CACHE, Match: &nodev1.CacheRuleMatch{PathPrefixes: st.PathPrefixes, Paths: st.Paths, Extensions: st.Extensions}}
			rule, ok, why := buildRule(r)
			if !ok || len(rule.PathPrefixes) != len(st.PathPrefixes) || len(rule.Paths) != len(st.Paths) || len(rule.Extensions) != len(st.Extensions) {
				t.Errorf("vector %d: structured form of %s not kept (%s): %+v", i, v.Source, why, rule)
			}
			site := &nodev1.Site{Id: "s", CacheRules: []*nodev1.CacheRule{{Id: "c", Match: &nodev1.CacheRuleMatch{Condition: e}}}}
			if err := validateCacheRuleConditions(site, lists, features); err != nil {
				t.Errorf("vector %d: condition %s: %v", i, v.Source, err)
			}
		}
		if e.Op == "matches" && e.Field != "" { // a computed left side needs an evaluator
			var expected bool
			if err := json.Unmarshal(v.Expected, &expected); err != nil {
				t.Fatalf("vector %d: %v", i, err)
			}
			subject, _ := v.Request[e.Field].(string)
			runes := make([]rune, len(subject))
			for j := range len(subject) {
				runes[j] = rune(subject[j])
			}
			if got := regexp.MustCompile(e.Value).MatchString(string(runes)); got != expected {
				t.Errorf("vector %d: RE2 gives %v for %s on %q", i, got, v.Source, subject)
			}
		}
	}
	for _, kind := range []string{"condition", "value", "pattern", "irRejected", "action", "structured", "derive"} {
		if counts[kind] == 0 {
			t.Errorf("no %s vectors: %v", kind, counts)
		}
	}
}
