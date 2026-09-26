package configir

import (
	"net/netip"
	"strings"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func TestAddressPolicyForbiddenRanges(t *testing.T) {
	p, _, _ := NewAddressPolicy(nil)
	forbidden := []string{
		"0.0.0.0", "0.1.2.3", "10.1.2.3", "100.64.0.1", "100.127.255.255", "127.0.0.1", "127.255.255.254",
		"169.254.169.254", "172.16.0.1", "172.31.255.255", "192.0.0.8", "192.0.2.1", "192.168.1.1",
		"198.18.0.1", "198.19.255.255", "198.51.100.7", "203.0.113.9", "224.0.0.1", "239.255.255.255",
		"240.0.0.1", "255.255.255.255",
		"::", "::1", "100::1", "2001:db8::1", "fc00::1", "fd12:3456::1", "fe80::1", "febf::1", "ff02::1",
		// Embedded IPv4 addresses are checked as IPv4.
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe",
	}
	allowed := []string{
		"1.1.1.1", "8.8.8.8", "100.63.255.255", "100.128.0.0", "172.15.255.255", "172.32.0.0", "192.0.1.1",
		"192.169.0.1", "198.17.255.255", "198.20.0.0", "223.255.255.255", "93.184.216.34",
		"2606:4700:4700::1111", "2001:4860::8888", "fec0::1", "::2",
		"::ffff:8.8.8.8", "64:ff9b::808:808",
	}
	for _, s := range forbidden {
		if !p.Forbidden(netip.MustParseAddr(s)) {
			t.Errorf("%s is not forbidden", s)
		}
	}
	for _, s := range allowed {
		if p.Forbidden(netip.MustParseAddr(s)) {
			t.Errorf("%s is forbidden", s)
		}
	}
	if len(ForbiddenOriginPrefixes()) != 21 {
		t.Fatalf("forbidden list has %d entries, want the 21 of the spec", len(ForbiddenOriginPrefixes()))
	}
}

func TestAddressPolicyAllowList(t *testing.T) {
	p, normalized, warnings := NewAddressPolicy([]string{"10.1.0.0/16", "127.0.0.1/32", "fd00::/8", "169.254.169.254/32", "not-a-cidr", "10.0.0.1", "192.168.1.77/24"})
	if strings.Join(normalized, ",") != "10.1.0.0/16,127.0.0.1/32,fd00::/8,169.254.169.254/32,192.168.1.0/24" {
		t.Fatalf("normalized = %v", normalized)
	}
	if len(warnings) != 2 || !strings.Contains(warnings[0], `"not-a-cidr"`) || !strings.Contains(warnings[1], `"10.0.0.1"`) {
		t.Fatalf("warnings = %v", warnings)
	}
	for _, s := range []string{"10.1.2.3", "127.0.0.1", "fd00::5", "::ffff:127.0.0.1", "::ffff:10.1.9.9", "64:ff9b::7f00:1", "192.168.1.200"} {
		if p.Forbidden(netip.MustParseAddr(s)) {
			t.Errorf("%s is allowed by the list but forbidden", s)
		}
	}
	for _, s := range []string{"10.2.0.1", "127.0.0.2", "fc00::1", "::1", "192.168.2.1"} {
		if !p.Forbidden(netip.MustParseAddr(s)) {
			t.Errorf("%s is outside the allow list but allowed", s)
		}
	}
}

func addressConfig(allowed []string, addrs ...string) *nodev1.NodeConfig {
	var origins []*nodev1.Origin
	for i, a := range addrs {
		origins = append(origins, &nodev1.Origin{Id: "o" + string(rune('a'+i)), Address: a, Port: 80})
	}
	return &nodev1.NodeConfig{
		OriginAllowedCidrs: allowed,
		Sites: []*nodev1.Site{{
			Id: "s", Enabled: true, Domains: []*nodev1.Domain{{Name: "s.test"}},
			OriginPool: &nodev1.OriginPool{Origins: origins},
		}},
	}
}

// TestBuildRefusesSpecialPurposeOrigins: IP literals in special-purpose
// ranges are refused (the site stays, so requests get 502 instead of
// 404) unless the platform allow list covers them.
func TestBuildRefusesSpecialPurposeOrigins(t *testing.T) {
	refused := []string{"127.0.0.1", "169.254.169.254", "10.1.2.3", "::1", "::ffff:127.0.0.1"}
	addrs := append(append([]string{}, refused...), "93.184.216.34", "origin.example.com")
	p, err := Build(addressConfig(nil, addrs...), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sites) != 1 {
		t.Fatalf("sites = %+v (a site with refused origins must still be served)", p.Sites)
	}
	got := map[string]bool{}
	for _, o := range p.Sites[0].Origins {
		got[o.Address] = o.Forbidden
	}
	for _, a := range refused {
		norm := netip.MustParseAddr(a).String()
		if forbidden, ok := got[norm]; !ok || !forbidden {
			t.Errorf("origin %s: present=%v forbidden=%v, want refused", norm, ok, forbidden)
		}
	}
	if got["93.184.216.34"] || got["origin.example.com"] {
		t.Errorf("public origins refused: %v", got)
	}
	if n := strings.Count(strings.Join(p.Warnings, "\n"), "special-purpose address"); n != len(refused) {
		t.Errorf("%d refusal warnings, want %d: %v", n, len(refused), p.Warnings)
	}

	// Only refused origins: the site is still served (502 in the data plane).
	p, err = Build(addressConfig(nil, "127.0.0.1"), Options{})
	if err != nil || len(p.Sites) != 1 || !p.Sites[0].Origins[0].Forbidden {
		t.Fatalf("site with only a refused origin: %+v %v", p.Sites, err)
	}

	// The platform allow list lets them through.
	p, err = Build(addressConfig([]string{"127.0.0.0/8", "169.254.169.254/32", "10.0.0.0/8", "::1/128"}, refused...), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range p.Sites[0].Origins {
		if o.Forbidden {
			t.Errorf("origin %s refused although allowed", o.Address)
		}
	}
	if strings.Join(p.OriginAllowedCIDRs, ",") != "127.0.0.0/8,169.254.169.254/32,10.0.0.0/8,::1/128" {
		t.Fatalf("plan allow list = %v", p.OriginAllowedCIDRs)
	}
}
