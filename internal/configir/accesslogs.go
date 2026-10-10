package configir

import (
	"fmt"
	"regexp"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// Features of proto v0.30.0 (ADR-0041). FeatureAccessLogsV2: a site's
// access log options (Site.log_blocked, log_query, log_headers, log_peer);
// the console requires it when a served site uses any of them.
// FeatureStatsDims: MinuteStats carries the bounded dimensions (countries,
// networks, referring hosts, user agent classes, HTTP and TLS versions,
// block reasons, challenges issued and passed). The console only reads
// them; no configuration requires it.
const (
	FeatureAccessLogsV2 = "access-logs-v2"
	FeatureStatsDims    = "stats-dims-v1"
)

// MaxLogHeaders bounds the request headers a site records (Site.log_headers).
const MaxLogHeaders = 8

// logHeaderRE matches the names of Site.log_headers: lowercase, like the
// console's.
var logHeaderRE = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)

// forbiddenLogHeaders never enter access logs.
var forbiddenLogHeaders = map[string]bool{"authorization": true, "cookie": true, "proxy-authorization": true}

// buildLogHeaders validates Site.log_headers (access-logs-v2): at most
// MaxLogHeaders lowercase names, no duplicates, never Authorization, Cookie
// or Proxy-Authorization. Any violation rejects the configuration.
func buildLogHeaders(s *nodev1.Site) ([]string, error) {
	names := s.GetLogHeaders()
	if len(names) > MaxLogHeaders {
		return nil, fmt.Errorf("%w: %d recorded request headers, at most %d", ErrRejected, len(names), MaxLogHeaders)
	}
	seen := make(map[string]bool, len(names))
	var out []string
	for _, name := range names {
		switch {
		case !logHeaderRE.MatchString(name):
			return nil, fmt.Errorf("%w: invalid recorded request header %q", ErrRejected, name)
		case forbiddenLogHeaders[name]:
			return nil, fmt.Errorf("%w: request header %q is never recorded", ErrRejected, name)
		case seen[name]:
			return nil, fmt.Errorf("%w: duplicate recorded request header %q", ErrRejected, name)
		}
		seen[name] = true
		out = append(out, name)
	}
	return out, nil
}
