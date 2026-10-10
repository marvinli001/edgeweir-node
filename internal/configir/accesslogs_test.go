package configir

import (
	"errors"
	"slices"
	"strings"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// g16Config is the v0.30.0 vector, canonical, after change.
func g16Config(t *testing.T, change func(c *nodev1.NodeConfig, a *nodev1.Site)) *nodev1.NodeConfig {
	t.Helper()
	cfg, _ := v0300Vector(t)
	Canonicalize(cfg)
	if change != nil {
		change(cfg, vectorSite(cfg, "a"))
	}
	return cfg
}

func TestG16FeaturesSupported(t *testing.T) {
	for _, f := range []string{"access-logs-v2", "stats-dims-v1"} {
		if !slices.Contains(SupportedFeatures, f) {
			t.Errorf("SupportedFeatures lacks %s: %v", f, SupportedFeatures)
		}
	}
}

// TestLogHeaders: at most 8 lowercase names of [a-z0-9-] (1-64 bytes),
// unique, never authorization, cookie or proxy-authorization; anything
// else rejects the configuration, also on a disabled site.
func TestLogHeaders(t *testing.T) {
	eight := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	long := strings.Repeat("x", 64)
	for name, headers := range map[string][]string{
		"none":         nil,
		"eight":        eight,
		"64 bytes":     {long},
		"digits, dash": {"x-trace-id", "cf-ray", "x-1"},
	} {
		p, err := Build(g16Config(t, func(_ *nodev1.NodeConfig, a *nodev1.Site) { a.LogHeaders = headers }), Options{})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !slices.Equal(p.Sites[0].LogHeaders, headers) {
			t.Errorf("%s: plan %v", name, p.Sites[0].LogHeaders)
		}
	}
	for name, headers := range map[string][]string{
		"nine":                {"a", "b", "c", "d", "e", "f", "g", "h", "i"},
		"uppercase":           {"X-Trace-Id"},
		"empty":               {""},
		"65 bytes":            {long + "x"},
		"underscore":          {"x_trace"},
		"space":               {"x trace"},
		"duplicate":           {"x-a", "x-a"},
		"authorization":       {"authorization"},
		"cookie":              {"x-a", "cookie"},
		"proxy-authorization": {"proxy-authorization"},
	} {
		_, err := Build(g16Config(t, func(_ *nodev1.NodeConfig, a *nodev1.Site) { a.LogHeaders = headers }), Options{})
		if !errors.Is(err, ErrRejected) {
			t.Errorf("%s: %v, want rejected", name, err)
		}
	}
	// A disabled site is checked too.
	_, err := Build(g16Config(t, func(c *nodev1.NodeConfig, _ *nodev1.Site) {
		b := vectorSite(c, "b")
		b.Enabled = false
		b.LogHeaders = []string{"cookie"}
	}), Options{})
	if !errors.Is(err, ErrRejected) {
		t.Errorf("disabled site: %v, want rejected", err)
	}
}

// TestLogHeadersCanonical: the console sends the names as a sorted set;
// canonicalization sorts and deduplicates them before Build sees them.
func TestLogHeadersCanonical(t *testing.T) {
	cfg, _ := v0300Vector(t)
	vectorSite(cfg, "a").LogHeaders = []string{"x-b", "x-a", "x-b"}
	Canonicalize(cfg)
	if got := vectorSite(cfg, "a").GetLogHeaders(); !slices.Equal(got, []string{"x-a", "x-b"}) {
		t.Fatalf("canonical log_headers %v", got)
	}
	if _, err := Build(cfg, Options{}); err != nil {
		t.Fatal(err)
	}
}

// TestAccessLogOptionsUnsetByDefault: a site without options has none in
// the plan, and access-logs-v2 is not needed for it.
func TestAccessLogOptionsUnsetByDefault(t *testing.T) {
	cfg := g16Config(t, func(c *nodev1.NodeConfig, a *nodev1.Site) {
		a.LogBlocked, a.LogQuery, a.LogPeer, a.LogHeaders = false, false, false, nil
		c.RequiredFeatures = []string{"access-logs-v1", "tls-v1"}
	})
	p, err := Build(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range p.Sites {
		if s.LogBlocked || s.LogQuery || s.LogPeer || s.LogHeaders != nil {
			t.Errorf("site %s: %+v", s.ID, s)
		}
	}
}
