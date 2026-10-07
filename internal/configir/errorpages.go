package configir

import (
	"fmt"
	"slices"
	"strings"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// Error page statuses and limits (SiteErrorPages, PlatformErrorPages).
// Since proto v0.24.0 (feature site-content-v1) also 400, 401, 404, 405,
// 410 and 500, and the classes 4 (4xx) and 5 (5xx).
var ErrorPageStatuses = []uint32{4, 5, 400, 401, 403, 404, 405, 410, 429, 500, 502, 503, 504}

// MaxErrorPageBytes bounds every error page template.
const MaxErrorPageBytes = 65536

// OfflineDisabled is the offline host reason (OfflineHost.reason) of a
// disabled site's domains.
const OfflineDisabled = "disabled"

// ErrorPages are a site's error pages (site table field "error_pages";
// lua/edgeweir/errorpages.lua). Pages maps a status or class
// (ErrorPageStatuses) to its page; Intercept also replaces origin
// responses that have a page.
type ErrorPages struct {
	Pages     map[uint32]ErrorPage `json:"pages"`
	Intercept bool                 `json:"intercept,omitempty"`
}

// ErrorPage is a template, or a redirect URL with placeholders; Status
// replaces the status a template page is sent with (0: the response's).
type ErrorPage struct {
	Template string `json:"template,omitempty"`
	Redirect string `json:"redirect,omitempty"`
	Status   uint32 `json:"status,omitempty"`
}

// PlatformErrorPages are the platform's templates for hosts no site serves
// and for offline hosts (site table field "platform_error_pages"); an empty
// template uses the node's built-in page.
type PlatformErrorPages struct {
	UnknownHost  string `json:"unknown_host,omitempty"`
	SiteDisabled string `json:"site_disabled,omitempty"`
}

// OfflineHost is a domain of a disabled site (site table field
// "offline_hosts"): the data plane answers it with the platform's page for
// the reason instead of the unknown host page.
type OfflineHost struct {
	Name     string `json:"name"`
	Wildcard bool   `json:"wildcard,omitempty"`
	// Match is MatchSuffix or MatchRegex (FeatureDomainsV2); empty: exact or wildcard.
	Match  string `json:"match,omitempty"`
	Reason string `json:"reason"`
}

// buildErrorPages validates a site's error pages: statuses and classes of
// ErrorPageStatuses, each at most once; a template of 1-65536 bytes or a
// redirect URL (validErrorRedirect), not both; a replacement status of
// 200-599 for templates only. Anything else rejects the configuration. No
// page means nil (intercepting origin errors needs a page).
func buildErrorPages(e *nodev1.SiteErrorPages) (*ErrorPages, error) {
	if e == nil || len(e.GetPages()) == 0 {
		return nil, nil
	}
	out := &ErrorPages{Pages: make(map[uint32]ErrorPage, len(e.GetPages())), Intercept: e.GetInterceptOriginErrors()}
	for _, p := range e.GetPages() {
		status := p.GetStatus()
		_, dup := out.Pages[status]
		switch {
		case !slices.Contains(ErrorPageStatuses, status):
			return nil, fmt.Errorf("%w: error page for unsupported status %d", ErrRejected, status)
		case dup:
			return nil, fmt.Errorf("%w: more than one error page for status %d", ErrRejected, status)
		case p.GetRedirectUrl() != "":
			if p.GetTemplate() != "" || p.GetResponseStatus() != 0 || !validErrorRedirect(p.GetRedirectUrl()) {
				return nil, fmt.Errorf("%w: invalid redirect of the error page for status %d", ErrRejected, status)
			}
		case p.GetTemplate() == "" || len(p.GetTemplate()) > MaxErrorPageBytes:
			return nil, fmt.Errorf("%w: error page for status %d must have 1-%d bytes", ErrRejected, status, MaxErrorPageBytes)
		case p.GetResponseStatus() != 0 && (p.GetResponseStatus() < 200 || p.GetResponseStatus() > 599):
			return nil, fmt.Errorf("%w: invalid response status of the error page for status %d", ErrRejected, status)
		}
		out.Pages[status] = ErrorPage{Template: p.GetTemplate(), Redirect: p.GetRedirectUrl(), Status: p.GetResponseStatus()}
	}
	return out, nil
}

// buildPlatformErrorPages validates the platform's error pages (0-65536
// bytes each); nil when every template is empty.
func buildPlatformErrorPages(p *nodev1.PlatformErrorPages) (*PlatformErrorPages, error) {
	out := &PlatformErrorPages{UnknownHost: p.GetUnknownHost(), SiteDisabled: p.GetSiteDisabled()}
	for name, t := range map[string]string{"unknown host": out.UnknownHost, "disabled site": out.SiteDisabled} {
		if len(t) > MaxErrorPageBytes {
			return nil, fmt.Errorf("%w: platform error page for the %s exceeds %d bytes", ErrRejected, name, MaxErrorPageBytes)
		}
	}
	if *out == (PlatformErrorPages{}) {
		return nil, nil
	}
	return out, nil
}

// buildOfflineHosts validates the offline hosts. An unknown reason rejects
// the configuration; invalid names (like domains: lowercase host names, no
// wildcard over a top-level label) and repeated (name, wildcard) pairs are
// skipped with a warning.
func buildOfflineHosts(hosts []*nodev1.OfflineHost) ([]OfflineHost, []string, error) {
	var out []OfflineHost
	var warnings []string
	seen := map[string]bool{}
	for _, h := range hosts {
		if r := h.GetReason(); r != OfflineDisabled {
			return nil, nil, fmt.Errorf("%w: offline host %q has unknown reason %q", ErrRejected, h.GetName(), r)
		}
		name := h.GetName()
		match, known := domainMatches[h.GetMatch()]
		display := displayMatch(name, h.GetWildcard(), match)
		switch why := domainProblem(name, h.GetWildcard(), match, known); {
		case match != "" || !known:
			if why != "" {
				warnings = append(warnings, fmt.Sprintf("offline host %q skipped: %s", display, why))
				continue
			}
		case name != strings.ToLower(name) || !ValidHostname(name):
			warnings = append(warnings, fmt.Sprintf("invalid offline host %q skipped", display))
			continue
		case h.GetWildcard() && !strings.Contains(name, "."):
			warnings = append(warnings, fmt.Sprintf("offline wildcard over a top-level label %q skipped", display))
			continue
		}
		if seen[display] {
			warnings = append(warnings, fmt.Sprintf("duplicate offline host %q skipped", display))
			continue
		}
		seen[display] = true
		out = append(out, OfflineHost{Name: name, Wildcard: h.GetWildcard(), Match: match, Reason: h.GetReason()})
	}
	return out, warnings, nil
}
