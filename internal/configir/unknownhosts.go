package configir

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// Features of proto v0.25.0. FeatureDomainsV2: site (and offline host)
// domains that match any subdomain of a suffix (Domain.match SUFFIX) or the
// whole host by a pattern (REGEX). FeatureUnknownHost: the cluster's
// handling of unknown hosts and of requests by node IP or without a Host
// (NodeConfig.unknown_hosts), the default site's certificate for unknown
// SNI and scan protection (platform-wide automatic bans).
const (
	FeatureDomainsV2   = "domains-v2"
	FeatureUnknownHost = "unknown-host-v1"
)

// Unknown host handling (UnknownHosts.unknown_host and ip_access).
const (
	UnknownHostPage  = "page"
	UnknownHostClose = "close"
	UnknownHostSite  = "site"
)

// Bounds of scan protection.
const (
	MinScanThreshold  = 10
	MaxScanThreshold  = 10000
	MinScanBanSeconds = 60
	MaxScanBanSeconds = 86400
	// ScanWindowSeconds is the window requests are counted over.
	ScanWindowSeconds = 60
)

// UnknownHosts is the validated unknown host handling. JSON tags define its
// form in the site table (edgeweir.router, edgeweir.tls).
type UnknownHosts struct {
	UnknownHost        string `json:"unknown_host"`
	IPAccess           string `json:"ip_access"`
	DefaultSiteID      string `json:"default_site_id,omitempty"`
	DefaultCertificate bool   `json:"default_certificate,omitempty"`
	ScanThreshold      uint32 `json:"scan_threshold,omitempty"`
	ScanBanSeconds     uint32 `json:"scan_ban_seconds,omitempty"`
}

// buildUnknownHosts validates NodeConfig.unknown_hosts against the served
// sites. An unknown handling or scan bounds outside 10-10000 requests and
// 60-86400 seconds reject the configuration; a default site that is not
// served (skipped by this node) hands nothing over: "site" becomes "page"
// with a warning, and so does its certificate.
func buildUnknownHosts(u *nodev1.UnknownHosts, sites []Site) (*UnknownHosts, []string, error) {
	if u == nil {
		return nil, nil, nil
	}
	valid := func(action string) bool {
		return action == UnknownHostPage || action == UnknownHostClose || action == UnknownHostSite
	}
	out := &UnknownHosts{UnknownHost: u.GetUnknownHost(), IPAccess: u.GetIpAccess(), DefaultCertificate: u.GetDefaultCertificate()}
	if !valid(out.UnknownHost) || !valid(out.IPAccess) {
		return nil, nil, fmt.Errorf("%w: unknown host handling %q / %q", ErrRejected, out.UnknownHost, out.IPAccess)
	}
	if t, s := u.GetScanThreshold(), u.GetScanBanSeconds(); t > 0 || s > 0 {
		if t < MinScanThreshold || t > MaxScanThreshold || s < MinScanBanSeconds || s > MaxScanBanSeconds {
			return nil, nil, fmt.Errorf("%w: scan protection %d requests / %d s out of bounds", ErrRejected, t, s)
		}
		out.ScanThreshold, out.ScanBanSeconds = t, s
	}
	handsOver := out.UnknownHost == UnknownHostSite || out.IPAccess == UnknownHostSite
	if out.DefaultCertificate && out.UnknownHost != UnknownHostSite {
		return nil, nil, fmt.Errorf("%w: the default site's certificate needs unknown_host %q", ErrRejected, UnknownHostSite)
	}
	if !handsOver {
		if u.GetDefaultSiteId() != "" {
			return nil, nil, fmt.Errorf("%w: default_site_id without a hand-over", ErrRejected)
		}
		return out, nil, nil
	}
	var site *Site
	for i := range sites {
		if sites[i].ID == u.GetDefaultSiteId() {
			site = &sites[i]
		}
	}
	if site == nil {
		warning := fmt.Sprintf("default site %q is not served: unknown hosts get the platform's page", u.GetDefaultSiteId())
		if out.UnknownHost == UnknownHostSite {
			out.UnknownHost = UnknownHostPage
		}
		if out.IPAccess == UnknownHostSite {
			out.IPAccess = UnknownHostPage
		}
		out.DefaultCertificate = false
		return out, []string{warning}, nil
	}
	out.DefaultSiteID = site.ID
	if out.DefaultCertificate && site.CertificateID == "" {
		out.DefaultCertificate = false
	}
	return out, nil, nil
}

// HostMatcher finds the site serving a host like edgeweir.store.lookup_host:
// an exact domain, else the wildcard over the parent, else the longest
// suffix of any depth, else the first pattern by (Domain.Order, site id).
type HostMatcher struct {
	exact, wild, suffix map[string]string
	patterns            []hostPattern
}

type hostPattern struct {
	re    *regexp.Regexp
	order uint64
	site  string
}

// NewHostMatcher indexes the domains of sites (the first owner of a name
// wins; patterns RE2 refuses never match).
func NewHostMatcher(sites []Site) *HostMatcher {
	m := &HostMatcher{exact: map[string]string{}, wild: map[string]string{}, suffix: map[string]string{}}
	for _, s := range sites {
		for _, d := range s.Domains {
			var index map[string]string
			switch {
			case d.Match == MatchRegex:
				if re, err := regexp.Compile("^(?:" + d.Name + ")$"); err == nil {
					m.patterns = append(m.patterns, hostPattern{re: re, order: d.Order, site: s.ID})
				}
				continue
			case d.Match == MatchSuffix:
				index = m.suffix
			case d.Wildcard:
				index = m.wild
			default:
				index = m.exact
			}
			if _, taken := index[d.Name]; !taken {
				index[d.Name] = s.ID
			}
		}
	}
	slices.SortStableFunc(m.patterns, func(a, b hostPattern) int {
		return cmp.Or(cmp.Compare(a.order, b.order), cmp.Compare(a.site, b.site))
	})
	return m
}

// Match returns the id of the site serving host (lowercase, no port), or "".
func (m *HostMatcher) Match(host string) string {
	if id, ok := m.exact[host]; ok {
		return id
	}
	// Node IP access ("_", an IPv4 address, an IPv6 address in brackets)
	// is matched by exact names only.
	if host == "_" || strings.HasPrefix(host, "[") || ipv4Host.MatchString(host) {
		return ""
	}
	dot := strings.IndexByte(host, '.')
	if dot > 0 {
		if id, ok := m.wild[host[dot+1:]]; ok {
			return id
		}
	}
	for dot > 0 {
		if id, ok := m.suffix[host[dot+1:]]; ok {
			return id
		}
		next := strings.IndexByte(host[dot+1:], '.')
		if next < 0 {
			break
		}
		dot += next + 1
	}
	// No pattern sees a host longer than a DNS name (nginx's guard server).
	if len(host) > MaxHost {
		return ""
	}
	for _, p := range m.patterns {
		if p.re.MatchString(host) {
			return p.site
		}
	}
	return ""
}

// MaxHost is the longest host name patterns are tried on (a DNS name).
const MaxHost = 253

var ipv4Host = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$`)
