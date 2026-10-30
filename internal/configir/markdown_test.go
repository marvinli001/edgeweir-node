package configir

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

var withMarkdown = Options{ExtraFeatures: []string{FeatureMarkdown}}

// TestMarkdownIsAnExtraFeature: markdown-v1 depends on the node's
// --markdown-workers, not on the agent version.
func TestMarkdownIsAnExtraFeature(t *testing.T) {
	if slices.Contains(SupportedFeatures, FeatureMarkdown) {
		t.Fatal("markdown-v1 is among SupportedFeatures")
	}
	md := &nodev1.Markdown{IncludePrefixes: []string{"/blog/", "/docs/"}, ExcludePrefixes: []string{"/docs/private/"}}
	cfg := g16Config(t, func(c *nodev1.NodeConfig, a *nodev1.Site) {
		a.Markdown = md
		c.RequiredFeatures = append(c.RequiredFeatures, FeatureMarkdown)
	})
	if _, err := Build(cfg, Options{}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), FeatureMarkdown) {
		t.Fatalf("without the converter: %v", err)
	}
	cfg = g16Config(t, func(_ *nodev1.NodeConfig, a *nodev1.Site) { a.Markdown = md })
	if _, err := Build(cfg, Options{}); !errors.Is(err, ErrRejected) {
		t.Fatalf("without the converter, no requirement: %v", err)
	}
	p, err := Build(cfg, withMarkdown)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(p.Sites)
	var table []map[string]any
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(table[0]["markdown"])
	if string(got) != `{"exclude":["/docs/private/"],"include":["/blog/","/docs/"]}` {
		t.Fatalf("site a table %s", got)
	}
	if _, ok := table[1]["markdown"]; ok {
		t.Fatal("site b carries markdown")
	}
	// Every path: empty lists stay lists for Lua.
	cfg = g16Config(t, func(_ *nodev1.NodeConfig, a *nodev1.Site) { a.Markdown = &nodev1.Markdown{} })
	p, err = Build(cfg, withMarkdown)
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(p.Sites[0].Markdown); string(raw) != `{"include":[],"exclude":[]}` {
		t.Fatalf("empty %s", raw)
	}
}

func TestMarkdownBounds(t *testing.T) {
	many := make([]string, MaxMarkdownPrefixes+1)
	for i := range many {
		many[i] = "/p" + strings.Repeat("a", i)
	}
	for name, md := range map[string]*nodev1.Markdown{
		"no slash":  {IncludePrefixes: []string{"docs/"}},
		"space":     {ExcludePrefixes: []string{"/a b"}},
		"non-ASCII": {IncludePrefixes: []string{"/文档"}},
		"too long":  {IncludePrefixes: []string{"/" + strings.Repeat("a", MaxMarkdownPrefixSize)}},
		"unsorted":  {IncludePrefixes: []string{"/b", "/a"}},
		"duplicate": {ExcludePrefixes: []string{"/a", "/a"}},
		"too many":  {IncludePrefixes: many},
	} {
		if _, err := Build(g16Config(t, func(_ *nodev1.NodeConfig, a *nodev1.Site) { a.Markdown = md }), withMarkdown); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ok := &nodev1.Markdown{IncludePrefixes: many[:MaxMarkdownPrefixes], ExcludePrefixes: []string{"/" + strings.Repeat("a", MaxMarkdownPrefixSize-1)}}
	if _, err := Build(g16Config(t, func(_ *nodev1.NodeConfig, a *nodev1.Site) { a.Markdown = ok }), withMarkdown); err != nil {
		t.Errorf("largest: %v", err)
	}
}
