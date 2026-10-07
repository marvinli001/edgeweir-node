package configir

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// v0250Vector reads testdata/content_hash_vector_v0250.json, a copy of the
// console's fixture: a site with every domain form (two patterns with
// order keys), a second site with a later pattern, offline hosts with a
// suffix and a pattern, and unknown host handling (default site with its
// certificate, node IP access closed, scan protection); sites, domains,
// offline hosts and required_features reversed.
func v0250Vector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_v0250.json"))
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

// TestContentHashVectorV0250 checks the proto v0.25.0 vector shared with
// the console: canonical order of domains and offline hosts by (name,
// wildcard, match), every new field in the hash, and the plan.
func TestContentHashVectorV0250(t *testing.T) {
	cfg, v := v0250Vector(t)
	if cfg.GetSites()[0].GetId() != "b" {
		t.Fatalf("vector sites are already canonical")
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
		"match": func(c *nodev1.NodeConfig) {
			for _, d := range vectorSite(c, "a").Domains {
				if d.Match == nodev1.DomainMatch_DOMAIN_MATCH_SUFFIX {
					d.Match = nodev1.DomainMatch_DOMAIN_MATCH_REGEX
				}
			}
		},
		"order": func(c *nodev1.NodeConfig) {
			for _, d := range vectorSite(c, "b").Domains {
				d.Order++
			}
		},
		"offline match": func(c *nodev1.NodeConfig) { c.OfflineHosts[0].Match = nodev1.DomainMatch_DOMAIN_MATCH_UNSPECIFIED },
		"unknown host":  func(c *nodev1.NodeConfig) { c.UnknownHosts.IpAccess = "page" },
		"scan":          func(c *nodev1.NodeConfig) { c.UnknownHosts.ScanThreshold = 99 },
		"certificate":   func(c *nodev1.NodeConfig) { c.UnknownHosts.DefaultCertificate = false },
	} {
		c, _ := v0250Vector(t)
		change(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}

	Canonicalize(cfg)
	p, err := Build(cfg, Options{ClusterID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	a := p.Sites[0]
	if a.ID != "a" {
		t.Fatalf("plan sites %v", p.Sites)
	}
	var forms []string
	for _, d := range a.Domains {
		forms = append(forms, displayMatch(d.Name, d.Wildcard, d.Match))
	}
	if want := []string{`~(www|m)\.a\.test`, "a.test", "*.a.test", `~api\d+\.test`, ".deep.test", "z.test"}; !slices.Equal(forms, want) {
		t.Fatalf("plan domains %v, want %v", forms, want)
	}
	if a.Domains[0].Order != 1_791_417_600_000*16 || a.Domains[3].Order != 1_791_417_600_000*16+1 || a.Domains[4].Order != 0 {
		t.Fatalf("plan orders %+v", a.Domains)
	}
	if want := []OfflineHost{
		{Name: `off-[0-9]+\.test`, Match: MatchRegex, Reason: "disabled"},
		{Name: "off.test", Reason: "disabled"},
		{Name: "off.test", Match: MatchSuffix, Reason: "disabled"},
	}; !slices.Equal(p.OfflineHosts, want) {
		t.Fatalf("offline hosts %+v", p.OfflineHosts)
	}
	if want := (UnknownHosts{UnknownHost: "site", IPAccess: "close", DefaultSiteID: "a", DefaultCertificate: true, ScanThreshold: 100, ScanBanSeconds: 3600}); p.UnknownHosts == nil || *p.UnknownHosts != want {
		t.Fatalf("unknown hosts %+v", p.UnknownHosts)
	}
	if len(p.Warnings) != 0 {
		t.Fatalf("warnings %v", p.Warnings)
	}
}

func domainsConfig(domains ...*nodev1.Domain) *nodev1.NodeConfig {
	return &nodev1.NodeConfig{
		Revision: 1,
		Sites: []*nodev1.Site{{
			Id: "s1", Enabled: true, Domains: domains,
			OriginPool: &nodev1.OriginPool{Origins: []*nodev1.Origin{{Id: "o1", Address: "origin.test", Port: 80}}},
		}},
	}
}

func TestBuildDomainForms(t *testing.T) {
	suffix, regex := nodev1.DomainMatch_DOMAIN_MATCH_SUFFIX, nodev1.DomainMatch_DOMAIN_MATCH_REGEX
	c := domainsConfig(
		&nodev1.Domain{Name: "a.test"},
		&nodev1.Domain{Name: "deep.test", Match: suffix},
		&nodev1.Domain{Name: `api\d+\.test`, Match: regex, Order: 7},
		// Refused: a suffix over a top-level label, a pattern outside the subset,
		// one with a quote or an escaped backslash or uppercase letters, a
		// wildcard or TLS-pending flag on a suffix.
		&nodev1.Domain{Name: "test", Match: suffix},
		&nodev1.Domain{Name: `(?i)a`, Match: regex},
		&nodev1.Domain{Name: `a"b`, Match: regex},
		&nodev1.Domain{Name: `a\\b`, Match: regex},
		&nodev1.Domain{Name: `[A-Z]\.test`, Match: regex},
		&nodev1.Domain{Name: "w.test", Match: suffix, Wildcard: true},
		&nodev1.Domain{Name: "p.test", Match: suffix, TlsPending: true},
		// Same form twice (names are lowercased like exact ones): once.
		&nodev1.Domain{Name: "Deep.test", Match: suffix},
	)
	p, err := Build(c, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := p.Sites[0].Domains
	if want := []Domain{{Name: "a.test"}, {Name: "deep.test", Match: MatchSuffix}, {Name: `api\d+\.test`, Match: MatchRegex, Order: 7}}; !slices.Equal(got, want) {
		t.Fatalf("domains %+v, want %+v", got, want)
	}
	warnings := strings.Join(p.Warnings, "\n")
	for _, w := range []string{`".test"`, `"~(?i)a"`, `"~a\"b"`, `"~a\\\\b"`, `"~[A-Z]\\.test"`, `".w.test"`, `".p.test"`} {
		if !strings.Contains(warnings, w) {
			t.Errorf("warnings %q lack %s", warnings, w)
		}
	}
	// A match this agent does not know rejects the configuration.
	if _, err := Build(domainsConfig(&nodev1.Domain{Name: "x.test", Match: nodev1.DomainMatch(7)}), Options{}); err == nil {
		t.Fatal("unknown match accepted")
	}
	// Escapes keep their letters; hex digits may be uppercase.
	if stripEscapes(`\D\x2A[a-z]`) != "[a-z]" {
		t.Fatalf("stripEscapes %q", stripEscapes(`\D\x2A[a-z]`))
	}
}

func TestBuildUnknownHosts(t *testing.T) {
	build := func(u *nodev1.UnknownHosts) (*Plan, error) {
		c := domainsConfig(&nodev1.Domain{Name: "a.test"})
		c.UnknownHosts = u
		return Build(c, Options{})
	}
	for name, u := range map[string]*nodev1.UnknownHosts{
		"action":           {UnknownHost: "redirect", IpAccess: "page"},
		"empty action":     {UnknownHost: "", IpAccess: "page"},
		"threshold":        {UnknownHost: "page", IpAccess: "page", ScanThreshold: 9, ScanBanSeconds: 60},
		"ban seconds":      {UnknownHost: "page", IpAccess: "page", ScanThreshold: 10, ScanBanSeconds: 86401},
		"half scan":        {UnknownHost: "page", IpAccess: "page", ScanThreshold: 100},
		"certificate":      {UnknownHost: "page", IpAccess: "site", DefaultSiteId: "s1", DefaultCertificate: true},
		"site without use": {UnknownHost: "page", IpAccess: "close", DefaultSiteId: "s1"},
	} {
		if _, err := build(u); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p, err := build(&nodev1.UnknownHosts{UnknownHost: "site", IpAccess: "site", DefaultSiteId: "gone", DefaultCertificate: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := (UnknownHosts{UnknownHost: "page", IPAccess: "page"}); *p.UnknownHosts != want || !strings.Contains(strings.Join(p.Warnings, "\n"), `default site "gone" is not served`) {
		t.Fatalf("missing default site: %+v %v", p.UnknownHosts, p.Warnings)
	}
	p, err = build(&nodev1.UnknownHosts{UnknownHost: "site", IpAccess: "close", DefaultSiteId: "s1", DefaultCertificate: true, ScanThreshold: 10, ScanBanSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	// The site has no certificate: unknown SNI stays refused.
	if want := (UnknownHosts{UnknownHost: "site", IPAccess: "close", DefaultSiteID: "s1", ScanThreshold: 10, ScanBanSeconds: 60}); *p.UnknownHosts != want {
		t.Fatalf("unknown hosts %+v", p.UnknownHosts)
	}
	if p, _ := build(nil); p.UnknownHosts != nil {
		t.Fatalf("defaults %+v", p.UnknownHosts)
	}
}

func TestApplyDiffUnknownHosts(t *testing.T) {
	base := domainsConfig(&nodev1.Domain{Name: "a.test"})
	target := proto.CloneOf(base)
	target.Revision = 2
	target.UnknownHosts = &nodev1.UnknownHosts{UnknownHost: "close", IpAccess: "page"}
	d := &nodev1.NodeConfigDiff{BaseRevision: 1, Revision: 2, UnknownHosts: target.UnknownHosts}
	h, _ := ContentHash(target)
	d.ContentHash = h
	out, err := ApplyDiff(base, d)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(out.GetUnknownHosts(), target.UnknownHosts) {
		t.Fatalf("unknown hosts %v", out.GetUnknownHosts())
	}
	// Diff (the fake console's) carries it too.
	target.ContentHash = h
	if out, err := ApplyDiff(base, Diff(base, target)); err != nil || !proto.Equal(out.GetUnknownHosts(), target.UnknownHosts) {
		t.Fatalf("Diff: %v, %v", out.GetUnknownHosts(), err)
	}
}

// TestHostMatcherSharedVectors runs the host lookup vectors the console
// (packages/contract) and the Lua data plane share.
func TestHostMatcherSharedVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "lua", "host-match-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Sites []struct {
			ID      string   `json:"id"`
			Created uint64   `json:"created"`
			Domains []string `json:"domains"`
		} `json:"sites"`
		Cases []struct {
			Host string  `json:"host"`
			Site *string `json:"site"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var sites []Site
	for _, s := range v.Sites {
		site := Site{ID: s.ID}
		index := uint64(0)
		for _, d := range s.Domains {
			switch {
			case strings.HasPrefix(d, "~"):
				site.Domains = append(site.Domains, Domain{Name: d[1:], Match: MatchRegex, Order: s.Created*16 + index})
				index++
			case strings.HasPrefix(d, "*."):
				site.Domains = append(site.Domains, Domain{Name: d[2:], Wildcard: true})
			case strings.HasPrefix(d, "."):
				site.Domains = append(site.Domains, Domain{Name: d[1:], Match: MatchSuffix})
			default:
				site.Domains = append(site.Domains, Domain{Name: d})
			}
			if p := site.Domains[len(site.Domains)-1]; p.Match == MatchRegex && !validPattern(p.Name) {
				t.Fatalf("vector pattern %q outside the subset", p.Name)
			}
		}
		sites = append(sites, site)
	}
	m := NewHostMatcher(sites)
	for _, c := range v.Cases {
		want := ""
		if c.Site != nil {
			want = *c.Site
		}
		if got := m.Match(c.Host); got != want {
			t.Errorf("%s: site %q, want %q", c.Host, got, want)
		}
	}
}
