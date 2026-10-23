package configir

import (
	"fmt"
	"regexp"
	"strings"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// FeatureEncodedPaths (proto v1.6.0): Site.encoded_path_exemptions, raw
// paths with "%2F" or ";" path parameters under a listed prefix compared as
// an origin may read them and cached (edgeweir.uripath). Never required:
// older nodes keep treating such paths as ambiguous.
const FeatureEncodedPaths = "encoded-path-exemptions-v1"

const (
	maxEncodedPathExemptions = 32
	maxEncodedPathPrefix     = 256
)

// encodedPathPrefixRE: printable ASCII starting with "/", without spaces,
// "%", ";", "\", "#" or "?".
var encodedPathPrefixRE = regexp.MustCompile(`^/[!"$&'()*+,\-./0-9:<=>@A-Z\[\]^_` + "`" + `a-z{|}~]*$`)

// dotSegmentRE matches a "." or ".." segment.
var dotSegmentRE = regexp.MustCompile(`/\.\.?(/|$)`)

// EncodedPathExemption is one entry of Site.encoded_path_exemptions.
type EncodedPathExemption struct {
	Prefix       string `json:"prefix"`
	EncodedSlash bool   `json:"encoded_slash,omitempty"`
	Semicolon    bool   `json:"semicolon,omitempty"`
}

// validEncodedPathPrefix mirrors the console (rule-engine encoded-path): a
// raw path starting with the prefix starts with it in every reading.
func validEncodedPathPrefix(p string) bool {
	return len(p) <= maxEncodedPathPrefix && encodedPathPrefixRE.MatchString(p) &&
		!strings.Contains(p, "//") && !dotSegmentRE.MatchString(p)
}

// buildEncodedPathExemptions validates a site's encoded path exemptions: at
// most 32 valid prefixes, unique, each allowing "%2F" or ";"; anything else
// rejects the configuration.
func buildEncodedPathExemptions(s *nodev1.Site) ([]EncodedPathExemption, error) {
	list := s.GetEncodedPathExemptions()
	if len(list) > maxEncodedPathExemptions {
		return nil, fmt.Errorf("%w: more than %d encoded path exemptions", ErrRejected, maxEncodedPathExemptions)
	}
	var out []EncodedPathExemption
	seen := map[string]bool{}
	for _, e := range list {
		p := e.GetPrefix()
		if !validEncodedPathPrefix(p) {
			return nil, fmt.Errorf("%w: invalid encoded path prefix %q", ErrRejected, p)
		}
		if !e.GetEncodedSlash() && !e.GetSemicolon() {
			return nil, fmt.Errorf("%w: encoded path prefix %q allows nothing", ErrRejected, p)
		}
		if seen[p] {
			return nil, fmt.Errorf("%w: duplicate encoded path prefix %q", ErrRejected, p)
		}
		seen[p] = true
		out = append(out, EncodedPathExemption{Prefix: p, EncodedSlash: e.GetEncodedSlash(), Semicolon: e.GetSemicolon()})
	}
	return out, nil
}
