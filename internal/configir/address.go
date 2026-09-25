package configir

import (
	"fmt"
	"net/netip"
)

// Special-purpose address ranges origins may not use unless the platform
// administrator allows them (NodeConfig.origin_allowed_cidrs): a tenant
// must not be able to reach the node itself, its local network or cloud
// metadata services through an origin. The console validates origins
// against the same list, and lua/edgeweir/ipaddr.lua checks the addresses
// again, including every DNS answer.
//
// IPv4-mapped (::ffff:0:0/96) and NAT64 (64:ff9b::/96) addresses are
// checked by their embedded IPv4 address.
var forbiddenOriginPrefixes = mustPrefixes(
	// IPv4
	"0.0.0.0/8",       // "this network"
	"10.0.0.0/8",      // private
	"100.64.0.0/10",   // shared address space (CGNAT)
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local, cloud metadata
	"172.16.0.0/12",   // private
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // documentation (TEST-NET-1)
	"192.168.0.0/16",  // private
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation (TEST-NET-2)
	"203.0.113.0/24",  // documentation (TEST-NET-3)
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, broadcast
	// IPv6
	"::/128",        // unspecified
	"::1/128",       // loopback
	"100::/64",      // discard-only
	"2001:db8::/32", // documentation
	"fc00::/7",      // unique local
	"fe80::/10",     // link-local
	"ff00::/8",      // multicast
)

var nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")

// ForbiddenOriginPrefixes returns the special-purpose ranges (a copy).
func ForbiddenOriginPrefixes() []netip.Prefix {
	return append([]netip.Prefix(nil), forbiddenOriginPrefixes...)
}

func mustPrefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, s := range list {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// AddressPolicy decides which addresses origins may use.
type AddressPolicy struct {
	allowed []netip.Prefix
}

// NewAddressPolicy builds the policy from the configuration's allow list.
// It returns the normalized (masked) valid entries and a warning for every
// entry that is not a CIDR.
func NewAddressPolicy(cidrs []string) (AddressPolicy, []string, []string) {
	var p AddressPolicy
	var normalized, warnings []string
	for _, c := range cidrs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil || pfx.Addr().Zone() != "" {
			warnings = append(warnings, fmt.Sprintf("origin allow list entry %q ignored: not a CIDR", c))
			continue
		}
		pfx = pfx.Masked()
		p.allowed = append(p.allowed, pfx)
		normalized = append(normalized, pfx.String())
	}
	return p, normalized, warnings
}

// embeddedIPv4 returns the IPv4 address inside an IPv4-mapped or NAT64
// address.
func embeddedIPv4(ip netip.Addr) (netip.Addr, bool) {
	if ip.Is4In6() {
		return ip.Unmap(), true
	}
	if ip.Is6() && nat64Prefix.Contains(ip) {
		b := ip.As16()
		return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}), true
	}
	return netip.Addr{}, false
}

// Forbidden reports whether an origin may not connect to ip: it lies in a
// special-purpose range (checked by the embedded IPv4 address for mapped
// and NAT64 addresses) and in no allow list entry.
func (p AddressPolicy) Forbidden(ip netip.Addr) bool {
	ip = ip.WithZone("")
	v4, embedded := embeddedIPv4(ip)
	for _, a := range p.allowed {
		if a.Contains(ip) || (embedded && a.Contains(v4)) {
			return false
		}
	}
	check := ip
	if embedded {
		check = v4
	}
	for _, f := range forbiddenOriginPrefixes {
		if f.Contains(check) {
			return true
		}
	}
	return false
}
