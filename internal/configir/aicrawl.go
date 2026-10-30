package configir

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// FeatureAICrawlers is AI crawl control (proto vNEXT, ADR-0070):
// Site.ai_crawl (crawler actions, the managed robots.txt, pay per crawl),
// the crawler tagging of access logs and MinuteStats.crawlers /
// crawler_paths. The catalogue (NodeConfig.ai_crawlers) alone needs no
// feature.
const FeatureAICrawlers = "ai-crawlers-v1"

// Bounds of the catalogue and of a site's policy (config.proto).
const (
	MaxAICrawlers         = 256
	MaxAICrawlerTokens    = 8
	MaxAICrawlerCIDRs     = 4096
	MaxAICrawlerDomains   = 8
	MaxAICrawlBlockBody   = 2048
	MaxAICrawlRobotsTxt   = 16384
	MinAICrawlPriceMicros = 1000
	MaxAICrawlPriceMicros = 1_000_000_000
)

var (
	aiCrawlerIDRE    = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
	aiCrawlerTokenRE = regexp.MustCompile(`^[\x21-\x7e]{3,64}$`)
	aiCrawlerHostRE  = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	aiCrawlActions   = []string{"allow", "block", "challenge", "charge"}
)

// AICrawler is a crawler of the catalogue (site table field
// "ai_crawlers"; lua/edgeweir/aicrawl.lua).
type AICrawler struct {
	ID       string   `json:"id"`
	Operator string   `json:"operator"`
	Tokens   []string `json:"tokens"`
	CIDRs    []string `json:"cidrs,omitempty"`
	Domains  []string `json:"domains,omitempty"`
}

// AICrawl is a site's AI crawl control (site table field "ai_crawl").
// Actions maps crawler ids to allow, block, challenge or charge.
type AICrawl struct {
	Actions        map[string]string `json:"actions"`
	Impersonators  string            `json:"impersonators,omitempty"`
	Challenge      string            `json:"challenge,omitempty"`
	BlockStatus    uint32            `json:"block_status"`
	BlockBody      string            `json:"block_body,omitempty"`
	RobotsTxt      string            `json:"robots_txt,omitempty"`
	PriceMicros    uint64            `json:"price_micros,omitempty"`
	DynamicPricing bool              `json:"dynamic_pricing,omitempty"`
}

// buildAICrawlers validates the catalogue (nil: none).
func buildAICrawlers(c *nodev1.AiCrawlerCatalogue) ([]AICrawler, error) {
	if c == nil {
		return nil, nil
	}
	if len(c.GetCrawlers()) > MaxAICrawlers {
		return nil, fmt.Errorf("%w: more than %d AI crawlers", ErrRejected, MaxAICrawlers)
	}
	out := make([]AICrawler, 0, len(c.GetCrawlers()))
	seen := map[string]bool{}
	for _, cr := range c.GetCrawlers() {
		id := cr.GetId()
		if !aiCrawlerIDRE.MatchString(id) || !aiCrawlerIDRE.MatchString(cr.GetOperator()) || seen[id] {
			return nil, fmt.Errorf("%w: invalid AI crawler %q", ErrRejected, id)
		}
		seen[id] = true
		if n := len(cr.GetTokens()); n == 0 || n > MaxAICrawlerTokens {
			return nil, fmt.Errorf("%w: AI crawler %q has %d tokens", ErrRejected, id, n)
		}
		for _, t := range cr.GetTokens() {
			if !aiCrawlerTokenRE.MatchString(t) || t != strings.ToLower(t) {
				return nil, fmt.Errorf("%w: AI crawler %q has an invalid token", ErrRejected, id)
			}
		}
		if len(cr.GetCidrs()) > MaxAICrawlerCIDRs || len(cr.GetDomains()) > MaxAICrawlerDomains {
			return nil, fmt.Errorf("%w: AI crawler %q has too many CIDRs or domains", ErrRejected, id)
		}
		for _, p := range cr.GetCidrs() {
			prefix, err := netip.ParsePrefix(p)
			if err != nil || prefix.Masked() != prefix || prefix.String() != p {
				return nil, fmt.Errorf("%w: AI crawler %q has a CIDR not in canonical form", ErrRejected, id)
			}
		}
		for _, d := range cr.GetDomains() {
			if len(d) > 253 || !aiCrawlerHostRE.MatchString(d) {
				return nil, fmt.Errorf("%w: AI crawler %q has an invalid domain", ErrRejected, id)
			}
		}
		out = append(out, AICrawler{
			ID: id, Operator: cr.GetOperator(),
			Tokens:  slices.Clone(cr.GetTokens()),
			CIDRs:   slices.Clone(cr.GetCidrs()),
			Domains: slices.Clone(cr.GetDomains()),
		})
	}
	return out, nil
}

// buildAICrawl validates Site.ai_crawl (nil: crawlers are only tagged)
// against the catalogue's crawler ids.
func buildAICrawl(s *nodev1.Site, crawlers map[string]bool) (*AICrawl, error) {
	p := s.GetAiCrawl()
	if p == nil {
		return nil, nil
	}
	out := &AICrawl{
		Actions:        map[string]string{},
		Impersonators:  p.GetImpersonators(),
		BlockStatus:    p.GetBlockStatus(),
		BlockBody:      p.GetBlockBody(),
		RobotsTxt:      p.GetRobotsTxt(),
		PriceMicros:    p.GetPriceMicros(),
		DynamicPricing: p.GetDynamicPricing(),
	}
	challenges := out.Impersonators == "challenge"
	for _, a := range p.GetActions() {
		if !crawlers[a.GetCrawler()] {
			return nil, fmt.Errorf("%w: AI crawl action for unknown crawler %q", ErrRejected, a.GetCrawler())
		}
		if !slices.Contains(aiCrawlActions, a.GetAction()) {
			return nil, fmt.Errorf("%w: unknown AI crawl action %q", ErrRejected, a.GetAction())
		}
		if _, dup := out.Actions[a.GetCrawler()]; dup {
			return nil, fmt.Errorf("%w: duplicate AI crawl action for %q", ErrRejected, a.GetCrawler())
		}
		out.Actions[a.GetCrawler()] = a.GetAction()
		challenges = challenges || a.GetAction() == "challenge"
	}
	switch out.Impersonators {
	case "", "block", "challenge":
	default:
		return nil, fmt.Errorf("%w: unknown AI crawl impersonator action %q", ErrRejected, out.Impersonators)
	}
	if challenges {
		if !slices.Contains(ChallengeTypes, p.GetChallenge()) {
			return nil, fmt.Errorf("%w: unknown AI crawl challenge %q", ErrRejected, p.GetChallenge())
		}
		out.Challenge = p.GetChallenge()
	}
	if out.BlockStatus != 403 && out.BlockStatus != 402 {
		return nil, fmt.Errorf("%w: AI crawl block status %d", ErrRejected, out.BlockStatus)
	}
	if len(out.BlockBody) > MaxAICrawlBlockBody || !utf8.ValidString(out.BlockBody) || strings.ContainsRune(out.BlockBody, 0) {
		return nil, fmt.Errorf("%w: invalid AI crawl block body", ErrRejected)
	}
	if r := out.RobotsTxt; len(r) > MaxAICrawlRobotsTxt || !utf8.ValidString(r) || strings.ContainsRune(r, 0) || (r != "" && !strings.HasSuffix(r, "\n")) {
		return nil, fmt.Errorf("%w: invalid managed robots.txt", ErrRejected)
	}
	if out.PriceMicros != 0 && (out.PriceMicros < MinAICrawlPriceMicros || out.PriceMicros > MaxAICrawlPriceMicros) {
		return nil, fmt.Errorf("%w: pay per crawl price out of range", ErrRejected)
	}
	if out.PriceMicros == 0 {
		out.DynamicPricing = false
		for id, a := range out.Actions {
			if a == "charge" {
				return nil, fmt.Errorf("%w: AI crawl charges %q without a price", ErrRejected, id)
			}
		}
	}
	return out, nil
}

// canonicalizeAICrawlers sorts the catalogue: crawlers by id, their
// tokens, CIDRs and domains as sets.
func canonicalizeAICrawlers(c *nodev1.AiCrawlerCatalogue) {
	if c == nil {
		return
	}
	slices.SortStableFunc(c.Crawlers, func(a, b *nodev1.AiCrawler) int {
		return strings.Compare(a.GetId(), b.GetId())
	})
	for _, cr := range c.Crawlers {
		cr.Tokens = sortedSet(cr.Tokens)
		cr.Cidrs = sortedSet(cr.Cidrs)
		cr.Domains = sortedSet(cr.Domains)
	}
}
