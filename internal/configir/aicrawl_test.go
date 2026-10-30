package configir

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// aiCrawlVector reads testdata/content_hash_vector_ai_crawl.json, a copy
// of the console's fixture (proto v1.9.0, ADR-0070): a catalogue of three
// crawlers; site a blocks GPTBot with a 402 and its own text, charges
// ClaudeBot USD 0.01 with dynamic pricing, blocks impersonators and
// manages robots.txt; site b only manages robots.txt; site c has no
// policy. Sites, crawlers and CIDRs are reversed.
func aiCrawlVector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_ai_crawl.json"))
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

func TestContentHashVectorAICrawl(t *testing.T) {
	cfg, v := aiCrawlVector(t)
	if cfg.GetSites()[0].GetId() != "c" {
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
	for name, change := range map[string]func(*nodev1.NodeConfig){
		"action":  func(c *nodev1.NodeConfig) { vectorSite(c, "a").AiCrawl.Actions[0].Action = "block" },
		"price":   func(c *nodev1.NodeConfig) { vectorSite(c, "a").AiCrawl.PriceMicros = 20000 },
		"robots":  func(c *nodev1.NodeConfig) { vectorSite(c, "b").AiCrawl.RobotsTxt = "x\n" },
		"cidr":    func(c *nodev1.NodeConfig) { c.AiCrawlers.Crawlers[0].Cidrs = nil },
		"crawler": func(c *nodev1.NodeConfig) { c.AiCrawlers.Crawlers = c.AiCrawlers.Crawlers[1:] },
	} {
		c, _ := aiCrawlVector(t)
		change(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}

	Canonicalize(cfg)
	p, err := Build(cfg, Options{ClusterID: cfg.GetClusterId()})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.AICrawlers) != 3 || p.AICrawlers[0].ID != "claudebot" || p.AICrawlers[2].ID != "gptbot" {
		t.Fatalf("catalogue %+v", p.AICrawlers)
	}
	if g := p.AICrawlers[2]; !slices.Equal(g.CIDRs, []string{"192.0.2.0/24", "2001:db8::/48"}) {
		t.Fatalf("gptbot %+v", g)
	}
	a, b2, c := p.Sites[0], p.Sites[1], p.Sites[2]
	want := map[string]string{"gptbot": "block", "claudebot": "charge", "googlebot": "allow"}
	if a.AICrawl == nil || len(a.AICrawl.Actions) != 3 || a.AICrawl.Actions["claudebot"] != want["claudebot"] ||
		a.AICrawl.Actions["gptbot"] != want["gptbot"] || a.AICrawl.BlockStatus != 402 || a.AICrawl.PriceMicros != 10000 ||
		!a.AICrawl.DynamicPricing || a.AICrawl.Impersonators != "block" || a.AICrawl.Challenge != "" {
		t.Fatalf("site a %+v", a.AICrawl)
	}
	if b2.AICrawl == nil || len(b2.AICrawl.Actions) != 0 || !strings.Contains(b2.AICrawl.RobotsTxt, "Content-Signal") {
		t.Fatalf("site b %+v", b2.AICrawl)
	}
	if c.AICrawl != nil {
		t.Fatalf("site c %+v", c.AICrawl)
	}
	raw, _ := json.Marshal(p.Sites)
	var table []map[string]any
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	ai, ok := table[0]["ai_crawl"].(map[string]any)
	if !ok || ai["block_status"] != float64(402) || ai["price_micros"] != float64(10000) {
		t.Fatalf("site a table %v", table[0]["ai_crawl"])
	}
	if _, ok := table[2]["ai_crawl"]; ok {
		t.Fatal("site c carries ai_crawl")
	}
}

func TestAICrawlersSupported(t *testing.T) {
	if !slices.Contains(SupportedFeatures, FeatureAICrawlers) {
		t.Fatalf("SupportedFeatures lacks %s", FeatureAICrawlers)
	}
}

func TestAICrawlerCatalogueBounds(t *testing.T) {
	valid := func() *nodev1.AiCrawler {
		return &nodev1.AiCrawler{Id: "gptbot", Operator: "openai", Tokens: []string{"gptbot"}, Cidrs: []string{"192.0.2.0/24"}, Domains: []string{"openai.com"}}
	}
	if _, err := buildAICrawlers(&nodev1.AiCrawlerCatalogue{Crawlers: []*nodev1.AiCrawler{valid()}}); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*nodev1.AiCrawler){
		"id":              func(c *nodev1.AiCrawler) { c.Id = "GPTBot" },
		"operator":        func(c *nodev1.AiCrawler) { c.Operator = "" },
		"no tokens":       func(c *nodev1.AiCrawler) { c.Tokens = nil },
		"uppercase token": func(c *nodev1.AiCrawler) { c.Tokens = []string{"GPTBot"} },
		"short token":     func(c *nodev1.AiCrawler) { c.Tokens = []string{"ab"} },
		"space in token":  func(c *nodev1.AiCrawler) { c.Tokens = []string{"gpt bot"} },
		"host bits":       func(c *nodev1.AiCrawler) { c.Cidrs = []string{"192.0.2.1/24"} },
		"not a prefix":    func(c *nodev1.AiCrawler) { c.Cidrs = []string{"192.0.2.1"} },
		"domain":          func(c *nodev1.AiCrawler) { c.Domains = []string{"-x.com"} },
		"too many tokens": func(c *nodev1.AiCrawler) { c.Tokens = slices.Repeat([]string{"gptbot"}, MaxAICrawlerTokens+1) },
	} {
		c := valid()
		change(c)
		if _, err := buildAICrawlers(&nodev1.AiCrawlerCatalogue{Crawlers: []*nodev1.AiCrawler{c}}); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := buildAICrawlers(&nodev1.AiCrawlerCatalogue{Crawlers: []*nodev1.AiCrawler{valid(), valid()}}); !errors.Is(err, ErrRejected) {
		t.Errorf("duplicate id: %v", err)
	}
}

func TestAICrawlPolicyBounds(t *testing.T) {
	ids := map[string]bool{"gptbot": true}
	valid := func() *nodev1.AiCrawlPolicy {
		return &nodev1.AiCrawlPolicy{
			Actions:     []*nodev1.AiCrawlerAction{{Crawler: "gptbot", Action: "charge"}},
			BlockStatus: 403, PriceMicros: 10000, RobotsTxt: "x\n",
		}
	}
	if p, err := buildAICrawl(&nodev1.Site{AiCrawl: valid()}, ids); err != nil || p.Actions["gptbot"] != "charge" {
		t.Fatalf("%+v %v", p, err)
	}
	if p, err := buildAICrawl(&nodev1.Site{}, ids); err != nil || p != nil {
		t.Fatalf("no policy: %+v %v", p, err)
	}
	challenge := valid()
	challenge.Actions[0].Action, challenge.Challenge = "challenge", "js"
	if p, err := buildAICrawl(&nodev1.Site{AiCrawl: challenge}, ids); err != nil || p.Challenge != "js" {
		t.Fatalf("challenge: %+v %v", p, err)
	}
	for name, change := range map[string]func(*nodev1.AiCrawlPolicy){
		"unknown crawler":   func(p *nodev1.AiCrawlPolicy) { p.Actions[0].Crawler = "claudebot" },
		"unknown action":    func(p *nodev1.AiCrawlPolicy) { p.Actions[0].Action = "drop" },
		"duplicate":         func(p *nodev1.AiCrawlPolicy) { p.Actions = append(p.Actions, p.Actions[0]) },
		"impersonators":     func(p *nodev1.AiCrawlPolicy) { p.Impersonators = "allow" },
		"challenge type":    func(p *nodev1.AiCrawlPolicy) { p.Actions[0].Action, p.Challenge = "challenge", "x" },
		"status":            func(p *nodev1.AiCrawlPolicy) { p.BlockStatus = 451 },
		"body":              func(p *nodev1.AiCrawlPolicy) { p.BlockBody = strings.Repeat("x", MaxAICrawlBlockBody+1) },
		"robots newline":    func(p *nodev1.AiCrawlPolicy) { p.RobotsTxt = "x" },
		"robots size":       func(p *nodev1.AiCrawlPolicy) { p.RobotsTxt = strings.Repeat("x", MaxAICrawlRobotsTxt) + "\n" },
		"price low":         func(p *nodev1.AiCrawlPolicy) { p.PriceMicros = 999 },
		"price high":        func(p *nodev1.AiCrawlPolicy) { p.PriceMicros = MaxAICrawlPriceMicros + 1 },
		"charge, no price":  func(p *nodev1.AiCrawlPolicy) { p.PriceMicros = 0 },
		"invalid UTF-8":     func(p *nodev1.AiCrawlPolicy) { p.BlockBody = "\xff" },
		"NUL in robots.txt": func(p *nodev1.AiCrawlPolicy) { p.RobotsTxt = "\x00\n" },
	} {
		p := valid()
		change(p)
		if _, err := buildAICrawl(&nodev1.Site{AiCrawl: p}, ids); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
