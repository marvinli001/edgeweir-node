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
// every accepted IR and refuses every rejected pattern, and for `matches` RE2
// over the value's bytes (one rune per byte, like PCRE2 without UTF) gives the
// expected result, a third engine next to JavaScript and PCRE2.
func TestSharedExpressionVectors(t *testing.T) {
	data, err := os.ReadFile("../../test/lua/expression-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Source   string              `json:"source"`
		Phase    string              `json:"phase"`
		Rejected bool                `json:"rejected"`
		Reason   string              `json:"reason"`
		Request  map[string]any      `json:"request"`
		Lists    map[string][]string `json:"lists"`
		Expected bool                `json:"expected"`
		IR       json.RawMessage     `json:"ir"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	features := []string{"geoip-country-v1", "geoip-subdivision-v1", "geoip-asn-v1"}
	accepted, rejected := 0, 0
	for i, v := range vectors {
		e := &nodev1.RuleExpression{}
		if err := protojson.Unmarshal(v.IR, e); err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		lists := map[string]bool{}
		for id := range v.Lists {
			lists[id] = true
		}
		budget := 256
		err := validateExpression(e, v.Phase, lists, features, 0, &budget)
		if v.Rejected {
			rejected++
			if err == nil {
				t.Errorf("vector %d accepted %s (%s)", i, v.Source, v.Reason)
			}
			continue
		}
		accepted++
		if err != nil {
			t.Errorf("vector %d refused %s: %v", i, v.Source, err)
			continue
		}
		if e.Op == "matches" {
			subject, _ := v.Request[e.Field].(string)
			runes := make([]rune, len(subject))
			for j := range len(subject) {
				runes[j] = rune(subject[j])
			}
			if got := regexp.MustCompile(e.Value).MatchString(string(runes)); got != v.Expected {
				t.Errorf("vector %d: RE2 gives %v for %s on %q", i, got, v.Source, subject)
			}
		}
	}
	if accepted == 0 || rejected == 0 {
		t.Fatalf("%d accepted and %d rejected vectors", accepted, rejected)
	}
}
