package configir

import (
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func protectedConfig() *nodev1.NodeConfig {
	s := site("site-a", "a.test")
	s.Protection = &nodev1.SiteProtection{
		UnderAttack: true, UnderAttackChallenge: "pow", PassTtlSeconds: 3600, PowDifficulty: 18, PowHighDifficulty: 22, LogJa4: true,
		Cc: &nodev1.CcPolicy{
			Enabled: true, MaxLevel: "pow", HighPowInsteadOfCaptcha: true, WindowSeconds: 20, SiteQps: 1000, UrlQps: 100, IpQps: 50,
			IpBanSeconds: 900, OriginErrorPercent: 50, OriginErrorMinRequests: 20, EscalateAfterSeconds: 5, CooldownSeconds: 120,
		},
	}
	s.Rules = []*nodev1.EdgeRule{{
		Id: "c1", Phase: "waf-custom",
		Expression: &nodev1.RuleExpression{Op: "eq", Field: "tls.ja4", ValueType: "string", Value: "t13d1516h2_8daaf6152771_e5627efa2ab1"},
		Action:     &nodev1.RuleAction{Kind: "challenge", Challenge: "captcha"},
	}, {
		Id: "rl", Phase: "ratelimit",
		Expression: &nodev1.RuleExpression{Op: "literal", ValueType: "boolean", Value: "true"},
		Action:     &nodev1.RuleAction{Kind: "rate_limit", StatusCode: 429, Limit: 10, WindowSeconds: 10, Key: "tls.ja4"},
	}}
	return &nodev1.NodeConfig{
		Sites:              []*nodev1.Site{s},
		PlatformProtection: &nodev1.PlatformProtection{UnderAttack: true, UnderAttackChallenge: "cookie302"},
		ChallengeKeys: []*nodev1.ChallengeKeyRef{
			{Id: "k-next", Role: "next"}, {Id: "k-current", Role: "current"}, {Id: "k-previous", Role: "previous"},
		},
		RequiredFeatures: []string{"challenge-v1", "ja4-v1"},
	}
}

func TestBuildProtection(t *testing.T) {
	p, err := Build(protectedConfig(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := p.Sites[0].Protection
	want := &Protection{
		UnderAttack: true, UnderAttackChallenge: "pow", PassTTL: 3600, PoW: 18, PoWHigh: 22, LogJA4: true,
		CC: &CCPolicy{MaxLevel: "pow", HighPoW: true, WindowSeconds: 20, SiteQPS: 1000, URLQPS: 100, IPQPS: 50, IPBanSeconds: 900,
			OriginErrorPercent: 50, OriginErrorMinRequests: 20, EscalateSeconds: 5, CooldownSeconds: 120},
	}
	if *got.CC != *want.CC {
		t.Fatalf("cc = %+v, want %+v", *got.CC, *want.CC)
	}
	got.CC, want.CC = nil, nil
	if *got != *want {
		t.Fatalf("protection = %+v, want %+v", *got, *want)
	}
	if *p.PlatformProtection != (PlatformProtection{UnderAttack: true, Challenge: "cookie302"}) {
		t.Fatalf("platform protection = %+v", *p.PlatformProtection)
	}
	if p.CurrentChallengeKey() != "k-current" || !slices.Equal(p.ChallengeKeyIDs(), []string{"k-next", "k-current", "k-previous"}) {
		t.Fatalf("keys = %+v", p.ChallengeKeys)
	}
	for _, f := range []string{"challenge-v1", "ja4-v1"} {
		if !slices.Contains(SupportedFeatures, f) {
			t.Fatalf("%s is not a supported feature", f)
		}
	}
}

func TestBuildProtectionDefaults(t *testing.T) {
	c := protectedConfig()
	c.Sites[0].Protection = &nodev1.SiteProtection{UnderAttack: true, Cc: &nodev1.CcPolicy{Enabled: true, SiteQps: 10}}
	c.PlatformProtection = &nodev1.PlatformProtection{}
	p, err := Build(c, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := p.Sites[0].Protection
	if got.UnderAttackChallenge != "js" || got.PassTTL != 1800 || got.PoW != 16 || got.PoWHigh != 20 {
		t.Fatalf("defaults = %+v", got)
	}
	if *got.CC != (CCPolicy{MaxLevel: "captcha", WindowSeconds: 10, SiteQPS: 10, IPBanSeconds: 600, EscalateSeconds: 10, CooldownSeconds: 60}) {
		t.Fatalf("cc defaults = %+v", *got.CC)
	}
	if p.PlatformProtection.Challenge != "js" || p.PlatformProtection.UnderAttack {
		t.Fatalf("platform defaults = %+v", p.PlatformProtection)
	}
	// A difficulty above the default high difficulty raises it.
	c.Sites[0].Protection = &nodev1.SiteProtection{PowDifficulty: 24}
	if p, err = Build(c, Options{}); err != nil || p.Sites[0].Protection.PoWHigh != 24 {
		t.Fatalf("high difficulty follows the difficulty: %+v, %v", p.Sites[0].Protection, err)
	}
	// A disabled policy is left out; nothing set stays nil.
	c.Sites[0].Protection = &nodev1.SiteProtection{Cc: &nodev1.CcPolicy{SiteQps: 10}}
	if p, err = Build(c, Options{}); err != nil || p.Sites[0].Protection.CC != nil {
		t.Fatalf("disabled policy: %+v, %v", p.Sites[0].Protection, err)
	}
	c.Sites[0].Protection, c.PlatformProtection, c.ChallengeKeys = nil, nil, nil
	if p, err = Build(c, Options{}); err != nil || p.Sites[0].Protection != nil || p.PlatformProtection != nil || p.ChallengeKeys != nil {
		t.Fatalf("no protection: %+v, %v", p, err)
	}
}

func TestBuildRejectsInvalidProtection(t *testing.T) {
	for name, change := range map[string]func(*nodev1.NodeConfig){
		"unknown Under Attack type": func(c *nodev1.NodeConfig) { c.Sites[0].Protection.UnderAttackChallenge = "slider" },
		"upper-case type":           func(c *nodev1.NodeConfig) { c.Sites[0].Protection.UnderAttackChallenge = "JS" },
		"unknown platform type":     func(c *nodev1.NodeConfig) { c.PlatformProtection.UnderAttackChallenge = "turnstile" },
		"unknown max level":         func(c *nodev1.NodeConfig) { c.Sites[0].Protection.Cc.MaxLevel = "normal" },
		"pass lifetime too short":   func(c *nodev1.NodeConfig) { c.Sites[0].Protection.PassTtlSeconds = 299 },
		"pass lifetime too long":    func(c *nodev1.NodeConfig) { c.Sites[0].Protection.PassTtlSeconds = 86401 },
		"difficulty too low":        func(c *nodev1.NodeConfig) { c.Sites[0].Protection.PowDifficulty = 7 },
		"difficulty too high":       func(c *nodev1.NodeConfig) { c.Sites[0].Protection.PowDifficulty = 25 },
		"high difficulty too high":  func(c *nodev1.NodeConfig) { c.Sites[0].Protection.PowHighDifficulty = 27 },
		"high difficulty too low":   func(c *nodev1.NodeConfig) { c.Sites[0].Protection.PowHighDifficulty = 7 },
		"high below difficulty":     func(c *nodev1.NodeConfig) { c.Sites[0].Protection.PowHighDifficulty = 17 },
		"window too short":          func(c *nodev1.NodeConfig) { c.Sites[0].Protection.Cc.WindowSeconds = 4 },
		"window too long":           func(c *nodev1.NodeConfig) { c.Sites[0].Protection.Cc.WindowSeconds = 61 },
		"ban too short":             func(c *nodev1.NodeConfig) { c.Sites[0].Protection.Cc.IpBanSeconds = 59 },
		"ban too long":              func(c *nodev1.NodeConfig) { c.Sites[0].Protection.Cc.IpBanSeconds = 86401 },
		"error rate over 100%":      func(c *nodev1.NodeConfig) { c.Sites[0].Protection.Cc.OriginErrorPercent = 101 },
		"site QPS too high":         func(c *nodev1.NodeConfig) { c.Sites[0].Protection.Cc.SiteQps = MaxCCRate + 1 },
		"escalation too slow":       func(c *nodev1.NodeConfig) { c.Sites[0].Protection.Cc.EscalateAfterSeconds = 3601 },
		"invalid disabled policy": func(c *nodev1.NodeConfig) {
			c.Sites[0].Protection.Cc.Enabled = false
			c.Sites[0].Protection.Cc.WindowSeconds = 3
		},
		"disabled site": func(c *nodev1.NodeConfig) {
			c.Sites[0].Enabled = false
			c.Sites[0].Protection.UnderAttackChallenge = "x"
		},
		"key without id":    func(c *nodev1.NodeConfig) { c.ChallengeKeys[0].Id = "" },
		"key id with a dot": func(c *nodev1.NodeConfig) { c.ChallengeKeys[0].Id = "k.1" },
		"duplicate key id":  func(c *nodev1.NodeConfig) { c.ChallengeKeys[0].Id = "k-current" },
		"unknown key role":  func(c *nodev1.NodeConfig) { c.ChallengeKeys[0].Role = "spare" },
		"two current keys":  func(c *nodev1.NodeConfig) { c.ChallengeKeys[0].Role = "current" },
		"no current key":    func(c *nodev1.NodeConfig) { c.ChallengeKeys = c.ChallengeKeys[:1] },
		"challenge outside waf-custom": func(c *nodev1.NodeConfig) {
			c.Sites[0].Rules[0].Phase = "redirect"
			c.Sites[0].Rules = c.Sites[0].Rules[:1]
		},
		"challenge without type": func(c *nodev1.NodeConfig) { c.Sites[0].Rules[0].Action.Challenge = "" },
		"unknown challenge type": func(c *nodev1.NodeConfig) { c.Sites[0].Rules[0].Action.Challenge = "slider" },
		"challenge on a block": func(c *nodev1.NodeConfig) {
			c.Sites[0].Rules[0].Action = &nodev1.RuleAction{Kind: "block", StatusCode: 403, Challenge: "js"}
		},
		"JA4 compared as a number": func(c *nodev1.NodeConfig) { c.Sites[0].Rules[0].Expression.ValueType = "number" },
		"unknown rate limit key":   func(c *nodev1.NodeConfig) { c.Sites[0].Rules[1].Action.Key = "tls.ja3" },
	} {
		t.Run(name, func(t *testing.T) {
			c := protectedConfig()
			change(c)
			if _, err := Build(c, Options{}); !errors.Is(err, ErrRejected) {
				t.Fatalf("Build = %v, want a rejection", err)
			}
		})
	}
}

func TestPlatformChallengeRule(t *testing.T) {
	c := protectedConfig()
	c.PlatformRules = []*nodev1.EdgeRule{{
		Id: "p1", Phase: "waf-custom",
		Expression: &nodev1.RuleExpression{Op: "literal", ValueType: "boolean", Value: "true"},
		Action:     &nodev1.RuleAction{Kind: "challenge", Challenge: "cookie302"},
	}}
	if _, err := Build(c, Options{}); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalizeChallengeKeys(t *testing.T) {
	c := protectedConfig()
	Canonicalize(c)
	var ids []string
	for _, k := range c.ChallengeKeys {
		ids = append(ids, k.GetId())
	}
	if !slices.Equal(ids, []string{"k-current", "k-next", "k-previous"}) {
		t.Fatalf("keys not sorted by id: %v", ids)
	}
	shuffled := protectedConfig()
	shuffled.ChallengeKeys[0], shuffled.ChallengeKeys[2] = shuffled.ChallengeKeys[2], shuffled.ChallengeKeys[0]
	a, _ := ContentHash(protectedConfig())
	b, _ := ContentHash(shuffled)
	if a != b {
		t.Fatal("content hash depends on the order of challenge keys")
	}
}

func TestApplyDiffCarriesProtection(t *testing.T) {
	base := withHash(t, &nodev1.NodeConfig{Revision: 1, ClusterId: "c1", Sites: []*nodev1.Site{site("site-a", "a.test")}})
	target := protectedConfig()
	target.Revision, target.ClusterId = 2, "c1"
	target = withHash(t, target)
	got, err := ApplyDiff(base, Diff(base, target))
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(got, target) {
		t.Fatalf("diff result differs from the target:\n%v\n%v", got, target)
	}
	// Removing the protection again: the diff carries empty fields.
	off := withHash(t, &nodev1.NodeConfig{Revision: 3, ClusterId: "c1", Sites: []*nodev1.Site{site("site-a", "a.test")}})
	got, err = ApplyDiff(target, Diff(target, off))
	if err != nil || got.PlatformProtection != nil || len(got.ChallengeKeys) != 0 {
		t.Fatalf("protection kept after removal: %v, %v", got, err)
	}
}
