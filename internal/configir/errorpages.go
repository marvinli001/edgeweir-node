package configir

import (
	"fmt"
	"slices"
	"strings"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// Error page statuses and limits (SiteErrorPages, PlatformErrorPages).
var ErrorPageStatuses = []uint32{403, 429, 502, 503, 504}

// MaxErrorPageBytes bounds every error page template.
const MaxErrorPageBytes = 65536

// OfflineDisabled is the offline host reason (OfflineHost.reason) of a
// disabled site's domains.
const OfflineDisabled = "disabled"

// ErrorPages are a site's error page templates (site table field
// "error_pages"; lua/edgeweir/errorpages.lua). Pages maps a status (403,
// 429, 502, 503, 504) to its template; Intercept also replaces origin
// responses whose status has a page.
type ErrorPages struct {
	Pages     map[uint32]string `json:"pages"`
	Intercept bool              `json:"intercept,omitempty"`
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
	Reason   string `json:"reason"`
}

// buildErrorPages validates a site's error pages: statuses 403, 429, 502,
// 503 and 504, each at most once, templates of 1-65536 bytes. Anything
// else rejects the configuration. No page means nil (intercepting origin
// errors needs a page).
func buildErrorPages(e *nodev1.SiteErrorPages) (*ErrorPages, error) {
	if e == nil || len(e.GetPages()) == 0 {
		return nil, nil
	}
	out := &ErrorPages{Pages: make(map[uint32]string, len(e.GetPages())), Intercept: e.GetInterceptOriginErrors()}
	for _, p := range e.GetPages() {
		status := p.GetStatus()
		switch {
		case !slices.Contains(ErrorPageStatuses, status):
			return nil, fmt.Errorf("%w: error page for unsupported status %d", ErrRejected, status)
		case out.Pages[status] != "":
			return nil, fmt.Errorf("%w: more than one error page for status %d", ErrRejected, status)
		case p.GetTemplate() == "" || len(p.GetTemplate()) > MaxErrorPageBytes:
			return nil, fmt.Errorf("%w: error page for status %d must have 1-%d bytes", ErrRejected, status, MaxErrorPageBytes)
		}
		out.Pages[status] = p.GetTemplate()
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
		display := displayDomain(name, h.GetWildcard())
		switch {
		case name != strings.ToLower(name) || !ValidHostname(name):
			warnings = append(warnings, fmt.Sprintf("invalid offline host %q skipped", display))
			continue
		case h.GetWildcard() && !strings.Contains(name, "."):
			warnings = append(warnings, fmt.Sprintf("offline wildcard over a top-level label %q skipped", display))
			continue
		case seen[display]:
			warnings = append(warnings, fmt.Sprintf("duplicate offline host %q skipped", display))
			continue
		}
		seen[display] = true
		out = append(out, OfflineHost{Name: name, Wildcard: h.GetWildcard(), Reason: h.GetReason()})
	}
	return out, warnings, nil
}
