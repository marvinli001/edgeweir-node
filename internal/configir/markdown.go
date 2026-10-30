package configir

import (
	"fmt"
	"slices"
	"strings"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// FeatureMarkdown is Markdown for Agents: HTML responses converted to
// Markdown for requests that ask for it (Site.markdown, proto
// v1.9.0) and the responses counted in
// MinuteStats.markdown_responses. Nodes announce it while their converter
// runs (--markdown-workers above 0), as an extra feature; the console
// requires it when a served site converts.
const FeatureMarkdown = "markdown-v1"

// Bounds of Markdown.
const (
	MaxMarkdownPrefixes   = 32
	MaxMarkdownPrefixSize = 256
)

// Markdown is a site's Markdown for Agents (site table field "markdown";
// lua/edgeweir/markdown.lua): path prefixes converted (empty: every
// path) and never converted.
type Markdown struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

// buildMarkdown validates Site.markdown (nil: off). Like image conversion,
// a site that converts needs the node's converter (FeatureMarkdown among
// extra) whatever its required_features say.
func buildMarkdown(s *nodev1.Site, extra []string) (*Markdown, error) {
	m := s.GetMarkdown()
	if m == nil {
		return nil, nil
	}
	if !slices.Contains(extra, FeatureMarkdown) {
		return nil, fmt.Errorf("%w: Markdown for Agents needs feature %s", ErrRejected, FeatureMarkdown)
	}
	include, err := markdownPrefixes(m.GetIncludePrefixes())
	if err != nil {
		return nil, err
	}
	exclude, err := markdownPrefixes(m.GetExcludePrefixes())
	if err != nil {
		return nil, err
	}
	return &Markdown{Include: include, Exclude: exclude}, nil
}

// markdownPrefixes checks a prefix list: at most MaxMarkdownPrefixes, each
// starting with "/", printable ASCII without spaces, at most
// MaxMarkdownPrefixSize bytes, sorted and unique.
func markdownPrefixes(list []string) ([]string, error) {
	if len(list) > MaxMarkdownPrefixes {
		return nil, fmt.Errorf("%w: Markdown for Agents has more than %d prefixes", ErrRejected, MaxMarkdownPrefixes)
	}
	for i, p := range list {
		if !strings.HasPrefix(p, "/") || len(p) > MaxMarkdownPrefixSize || strings.IndexFunc(p, func(r rune) bool { return r <= ' ' || r >= 0x7f }) >= 0 {
			return nil, fmt.Errorf("%w: invalid Markdown for Agents prefix %q", ErrRejected, p)
		}
		if i > 0 && list[i-1] >= p {
			return nil, fmt.Errorf("%w: Markdown for Agents prefixes not sorted and unique", ErrRejected)
		}
	}
	return append([]string{}, list...), nil // [] in the table, never null
}
