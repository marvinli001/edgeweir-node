package configir

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// v0290Vector reads testdata/content_hash_vector_v0290.json, a copy of the
// console's fixture: site a with every G14 feature (the waf-v2 actions, a
// log rule writing access log lines, a rate limit ban, the CRS override,
// body and crawler fields, a rules body limit, CRS exclusions by path and
// target, verified crawlers, challenge texts and failure bans), site b with
// the default rules body limit a platform rule gives it, and a platform rule
// banning at platform scope. Sites, skip targets, the exclusions' rule ids
// and targets, challenge keys and required features are reversed; the
// exclusions keep their order.
func v0290Vector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_v0290.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v hashVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	cfg := &nodev1.NodeConfig{}
	if err := protojson.Unmarshal(v.Config, cfg); err != nil {
		t.Fatal(err)
	}
	return cfg, v
}

// vectorRule returns the rule id of rules.
func vectorRule(rules []*nodev1.EdgeRule, id string) *nodev1.EdgeRule {
	for _, r := range rules {
		if r.GetId() == id {
			return r
		}
	}
	return nil
}

// TestContentHashVectorV0290 checks the proto v0.29.0 vector shared with
// the console: skip targets and the exclusions' rule ids and targets sorted,
// the exclusions in their order, every new field in the hash, and the plan.
func TestContentHashVectorV0290(t *testing.T) {
	cfg, v := v0290Vector(t)
	a := vectorSite(cfg, "a")
	if cfg.GetSites()[0].GetId() != "b" || vectorRule(a.GetRules(), "r-skip").GetAction().GetSkip()[0] != "rules" ||
		a.GetWaf().GetExclusions()[0].GetRuleIds()[0] != 942100 {
		t.Fatalf("vector is already canonical")
	}
	b, err := CanonicalBytes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ContentHash(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v.CanonicalHex != hex.EncodeToString(b) {
		t.Fatalf("canonical bytes differ from the console\n got %x\nwant %s", b, v.CanonicalHex)
	}
	if v.ContentHash != h {
		t.Fatalf("vector hash %s, Go computes %s", v.ContentHash, h)
	}
	if err := VerifyHash(cfg); err != nil {
		t.Fatal(err)
	}
	site := func(c *nodev1.NodeConfig) *nodev1.Site { return vectorSite(c, "a") }
	action := func(c *nodev1.NodeConfig, id string) *nodev1.RuleAction { return vectorRule(site(c).Rules, id).Action }
	for name, change := range map[string]func(*nodev1.NodeConfig){
		// The exclusions keep the site's order.
		"exclusion order": func(c *nodev1.NodeConfig) {
			e := site(c).Waf.Exclusions
			e[0], e[1] = e[1], e[0]
		},
		"exclusion path":    func(c *nodev1.NodeConfig) { site(c).Waf.Exclusions[0].Path = "/api/v2/" },
		"exclusion exact":   func(c *nodev1.NodeConfig) { site(c).Waf.Exclusions[0].Exact = true },
		"exclusion target":  func(c *nodev1.NodeConfig) { site(c).Waf.Exclusions[2].Targets = []string{"REQUEST_COOKIES:sid"} },
		"rules body limit":  func(c *nodev1.NodeConfig) { site(c).RulesBodyLimit = 65536 },
		"ban seconds":       func(c *nodev1.NodeConfig) { action(c, "r-ban").BanSeconds = 7200 },
		"ban prefix":        func(c *nodev1.NodeConfig) { action(c, "r-ban").BanPrefixV4 = 0 },
		"platform scope":    func(c *nodev1.NodeConfig) { c.PlatformRules[0].Action.BanScope = "" },
		"respond body":      func(c *nodev1.NodeConfig) { action(c, "r-respond").Body = "{}" },
		"error page":        func(c *nodev1.NodeConfig) { action(c, "r-page").StatusCode = 503 },
		"skip":              func(c *nodev1.NodeConfig) { action(c, "r-skip").Skip = []string{"crs"} },
		"access log":        func(c *nodev1.NodeConfig) { action(c, "r-log").AccessLog = false },
		"rate limit ban":    func(c *nodev1.NodeConfig) { action(c, "r-rate").BanSeconds = 0 },
		"crs override":      func(c *nodev1.NodeConfig) { action(c, "r-crs").Crs = "off" },
		"verified crawlers": func(c *nodev1.NodeConfig) { site(c).Protection.AllowVerifiedBots = false },
		"challenge text":    func(c *nodev1.NodeConfig) { site(c).Protection.ChallengeText.HintEn = "Wait." },
		"failure threshold": func(c *nodev1.NodeConfig) { site(c).Protection.FailureThreshold = 10 },
		"failure ban":       func(c *nodev1.NodeConfig) { site(c).Protection.FailureBanSeconds = 600 },
	} {
		c, _ := v0290Vector(t)
		change(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}
	// Reordering the sets once more changes nothing.
	c, _ := v0290Vector(t)
	slices.Reverse(action(c, "r-skip").Skip)
	slices.Reverse(site(c).Waf.Exclusions[1].Targets)
	slices.Reverse(site(c).Waf.Exclusions[0].RuleIds)
	if hc, _ := ContentHash(c); hc != h {
		t.Errorf("reordered sets change the hash")
	}

	Canonicalize(cfg)
	p, err := Build(cfg, Options{ClusterID: cfg.GetClusterId(), ExtraFeatures: []string{FeatureModSecurity}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sites) != 2 || p.Sites[0].ID != "a" || p.Sites[0].RulesBodyLimit != 131072 || p.Sites[1].RulesBodyLimit != 65536 {
		t.Fatalf("plan sites %+v", p.Sites)
	}
	waf := p.Sites[0].WAF
	if waf == nil || len(waf.Exclusions) != 3 || !slices.Equal(waf.ExcludedRuleIDs, []uint32{920350, 942100}) {
		t.Fatalf("CRS %+v", waf)
	}
	for i, want := range []WAFExclusion{
		{Path: "/api/", RuleIDs: []uint32{941100, 942100}},
		{Path: "/login", Exact: true, RuleIDs: []uint32{942100}, Targets: []string{"ARGS:next", "ARGS:password"}},
		{RuleIDs: []uint32{932100}, Targets: []string{"REQUEST_COOKIES:session"}},
	} {
		got := waf.Exclusions[i]
		if got.Path != want.Path || got.Exact != want.Exact || !slices.Equal(got.RuleIDs, want.RuleIDs) || !slices.Equal(got.Targets, want.Targets) ||
			got.Token != WAFExclusionToken("a", want.Path, want.Exact, want.RuleIDs, want.Targets) {
			t.Errorf("exclusion %d = %+v", i, got)
		}
	}
	pr := p.Sites[0].Protection
	if pr == nil || !pr.AllowVerifiedBots || pr.FailureThreshold != 5 || pr.FailureBanSeconds != 900 ||
		*pr.ChallengeText != (ChallengeText{TitleZH: "访问验证", HintZH: "请稍候，验证完成后自动继续。", TitleEN: "Checking your browser"}) {
		t.Fatalf("protection %+v", pr)
	}
	if b := p.Sites[1].Protection; b == nil || b.ChallengeText != nil || b.FailureThreshold != 0 || b.AllowVerifiedBots {
		t.Fatalf("site b protection %+v", b)
	}
	for _, f := range cfg.GetRequiredFeatures() {
		if !slices.Contains(SupportedFeatures, f) && f != FeatureModSecurity {
			t.Errorf("required feature %s is not supported", f)
		}
	}
}
