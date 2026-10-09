package agent

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/identity"
)

// TestProtectedPrefixes: nftables never drops loopback, the node's own
// addresses, the console and the platform allow lists.
func TestProtectedPrefixes(t *testing.T) {
	dir := t.TempDir()
	write := func(server string) {
		t.Helper()
		raw := `{"node_id":"node-1","cluster_id":"cl-1","server_url":"` + server + `"}`
		if err := os.WriteFile(filepath.Join(dir, identity.IdentityFile), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a := New(Config{StateDir: dir}, nil, nil, nil)
	a.applied = &nodev1.NodeConfig{IpLists: []*nodev1.IpList{
		{Id: "platform-allow", Kind: "allow", Platform: true, Entries: []string{"203.0.113.0/24", "2001:db8:7::/48"}},
		{Id: "site-allow", Kind: "allow", Entries: []string{"198.51.100.0/24"}},
		{Id: "platform-block", Kind: "block", Platform: true, Entries: []string{"198.51.101.0/24"}},
	}, ClientAddress: &nodev1.ClientAddress{Mode: "header", TrustedCidrs: []string{"192.0.2.128/25"}}}

	// Before enrollment there is no console address.
	got := a.protectedPrefixes(context.Background())
	for _, want := range []string{"127.0.0.0/8", "::1/128", "203.0.113.0/24", "2001:db8:7::/48", "192.0.2.128/25"} {
		if !slices.Contains(got, netip.MustParsePrefix(want)) {
			t.Errorf("protected set lacks %s: %v", want, got)
		}
	}
	for _, not := range []string{"198.51.100.0/24", "198.51.101.0/24"} {
		if slices.Contains(got, netip.MustParsePrefix(not)) {
			t.Errorf("protected set holds %s", not)
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			ip, _ := netip.AddrFromSlice(addr.(*net.IPNet).IP)
			ip = ip.Unmap()
			if !slices.Contains(got, netip.PrefixFrom(ip, ip.BitLen())) {
				t.Errorf("protected set lacks the interface address %s", ip)
			}
		}
	}

	write("https://192.0.2.44:8443")
	got = a.protectedPrefixes(context.Background())
	if !slices.Contains(got, netip.MustParsePrefix("192.0.2.44/32")) {
		t.Fatalf("console address missing: %v", got)
	}
	// Cached until the refresh; then resolved again (a host name here).
	write("https://localhost:8443")
	if got := a.protectedPrefixes(context.Background()); !slices.Contains(got, netip.MustParsePrefix("192.0.2.44/32")) {
		t.Fatalf("console address not cached: %v", got)
	}
	a.consoleAddrsAt = a.consoleAddrsAt.Add(-protectedRefresh)
	got = a.protectedPrefixes(context.Background())
	if slices.Contains(got, netip.MustParsePrefix("192.0.2.44/32")) ||
		!slices.ContainsFunc(got, func(p netip.Prefix) bool { return p.Addr().IsLoopback() && p.IsSingleIP() }) {
		t.Fatalf("console host name not resolved again: %v", got)
	}
}

func TestRuleBanPrefix(t *testing.T) {
	for cidr, want := range map[string]bool{"192.0.2.0/24": true, "10.0.0.0/16": true, "10.0.0.0/15": false, "192.0.2.1/32": true,
		"2001:db8::/48": true, "2001:db8::/47": false, "2001:db8::/64": true, "2001:db8::1/128": false, "::ffff:192.0.2.0/120": false} {
		if got := ruleBanPrefix(netip.MustParsePrefix(cidr)); got != want {
			t.Errorf("ruleBanPrefix(%s) = %v", cidr, got)
		}
	}
	if ruleBanPrefix(netip.MustParsePrefix("192.0.2.1/24")) {
		t.Error("host bits accepted")
	}
}

func TestConvertAutoBan(t *testing.T) {
	b, ok := convertAutoBan(dataplane.AutoBan{SiteID: "site-a", IP: "2001:DB8::7", PrefixLen: 128, CreatedAt: 1790000000.5, ExpiresAt: 1790000060.5})
	if !ok || b.GetCidr() != "2001:db8::7/128" || b.GetReason() != "cc_ip_rate" ||
		b.GetCreatedAt().AsTime().UnixMilli() != 1790000000500 || b.GetExpiresAt().AsTime().Unix() != 1790000060 {
		t.Fatalf("converted = %v, %v", b, ok)
	}
	// An IPv6 client is banned by its /64; IPv4 by its address.
	for _, c := range []struct {
		ip   string
		bits int
		want string
	}{{"2001:db8:1:2::", 64, "2001:db8:1:2::/64"}, {"192.0.2.1", 32, "192.0.2.1/32"}, {"192.0.2.1", 0, "192.0.2.1/32"}} {
		b, ok := convertAutoBan(dataplane.AutoBan{SiteID: "site-a", IP: c.ip, PrefixLen: c.bits, ExpiresAt: 1})
		if !ok || b.GetCidr() != c.want {
			t.Errorf("%s/%d converted = %v, %v; want %s", c.ip, c.bits, b, ok, c.want)
		}
	}
	// Scan protection's platform-wide bans ("*") carry no site.
	p, ok := convertAutoBan(dataplane.AutoBan{SiteID: "*", IP: "192.0.2.9", PrefixLen: 32, ExpiresAt: 1, Reason: "unknown_host_scan", Metric: "unknown_host_requests", Observed: 101, Threshold: 100, WindowSeconds: 60})
	if !ok || p.GetSiteId() != "" || p.GetScope() != nodev1.BanScope_BAN_SCOPE_PLATFORM || p.GetReason() != "unknown_host_scan" || p.GetCidr() != "192.0.2.9/32" {
		t.Fatalf("platform ban = %v, %v", p, ok)
	}
	if b, _ := convertAutoBan(dataplane.AutoBan{SiteID: "site-a", IP: "192.0.2.1", ExpiresAt: 1}); b.GetScope() != nodev1.BanScope_BAN_SCOPE_UNSPECIFIED || b.GetSiteId() != "site-a" {
		t.Fatalf("site ban = %v", b)
	}
	// Bans rules made carry the rule and may hold a network.
	for _, c := range []struct {
		site, ip string
		bits     int
		want     string
	}{{"site-a", "192.0.2.0", 24, "192.0.2.0/24"}, {"site-a", "10.20.0.0", 16, "10.20.0.0/16"}, {"*", "2001:db8::", 48, "2001:db8::/48"},
		{"site-a", "192.0.2.7", 32, "192.0.2.7/32"}, {"site-a", "2001:db8:1:2::", 64, "2001:db8:1:2::/64"}} {
		b, ok := convertAutoBan(dataplane.AutoBan{SiteID: c.site, IP: c.ip, PrefixLen: c.bits, ExpiresAt: 1, Reason: "waf_rule", RuleID: "rule-1"})
		if !ok || b.GetCidr() != c.want || b.GetRuleId() != "rule-1" || b.GetReason() != "waf_rule" {
			t.Errorf("rule ban %s/%d converted = %v, %v; want %s", c.ip, c.bits, b, ok, c.want)
		}
	}
	if b, _ := convertAutoBan(dataplane.AutoBan{SiteID: "site-a", IP: "192.0.2.1", PrefixLen: 32, ExpiresAt: 1}); b.GetRuleId() != "" {
		t.Fatalf("an automatic ban with a rule: %v", b)
	}
	for _, bad := range []dataplane.AutoBan{
		{SiteID: "site-a", IP: "192.0.0.0", PrefixLen: 15, ExpiresAt: 1, RuleID: "rule-1"},
		{SiteID: "site-a", IP: "2001:db8::", PrefixLen: 47, ExpiresAt: 1, RuleID: "rule-1"},
		{SiteID: "site-a", IP: "2001:db8::1", PrefixLen: 128, ExpiresAt: 1, RuleID: "rule-1"},
		{SiteID: "site-a", IP: "192.0.2.1", PrefixLen: 24, ExpiresAt: 1, RuleID: "rule-1"}, // host bits
		{SiteID: "site-a", IP: "192.0.2.0", PrefixLen: 24, ExpiresAt: 1, RuleID: "rule 1"},
		{SiteID: "**", IP: "192.0.2.1", ExpiresAt: 1},
		{SiteID: "site-a", IP: "not-an-ip", ExpiresAt: 1},
		{SiteID: "site a", IP: "192.0.2.1", ExpiresAt: 1},
		{SiteID: "site-a", IP: "192.0.2.1"},
		{SiteID: "site-a", IP: "192.0.2.0", PrefixLen: 24, ExpiresAt: 1},
		{SiteID: "site-a", IP: "2001:db8::", PrefixLen: 48, ExpiresAt: 1},
		{SiteID: "site-a", IP: "2001:db8::1", PrefixLen: 64, ExpiresAt: 1}, // host bits
	} {
		if _, ok := convertAutoBan(bad); ok {
			t.Errorf("accepted %+v", bad)
		}
	}
}
