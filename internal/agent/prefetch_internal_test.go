package agent

import (
	"os"
	"regexp"
	"strings"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// TestPrefetchUserAgentsMatchTheCacheKey keeps the variants' User-Agents in
// sync with edgeweir.cachekey: the data plane caches a mobile object for a
// request whose User-Agent matches MOBILE_RE, a desktop one otherwise.
func TestPrefetchUserAgentsMatchTheCacheKey(t *testing.T) {
	lua, err := os.ReadFile("../../lua/edgeweir/cachekey.lua")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^local MOBILE_RE = \[\[(.*)\]\]$`).FindSubmatch(lua)
	if m == nil {
		t.Fatal("MOBILE_RE not found in lua/edgeweir/cachekey.lua")
	}
	// The Lua pattern is matched with ngx.re.find(..., "jo"): PCRE,
	// case-sensitive; this alternation means the same in RE2.
	mobileRE := regexp.MustCompile(string(m[1]))
	for v, wantMobile := range map[nodev1.DeviceVariant]bool{
		nodev1.DeviceVariant_DEVICE_VARIANT_UNSPECIFIED: false,
		nodev1.DeviceVariant_DEVICE_VARIANT_DESKTOP:     false,
		nodev1.DeviceVariant_DEVICE_VARIANT_MOBILE:      true,
	} {
		ua, ok := prefetchUserAgent(v)
		if !ok || !strings.Contains(ua, "edgeweir-node-prefetch/") {
			t.Fatalf("%v: User-Agent %q does not name the agent", v, ua)
		}
		if got := mobileRE.MatchString(ua); got != wantMobile {
			t.Errorf("%v: User-Agent %q mobile = %v, want %v (MOBILE_RE %s)", v, ua, got, wantMobile, m[1])
		}
	}
	if _, ok := prefetchUserAgent(nodev1.DeviceVariant(3)); ok {
		t.Error("an unknown variant has a User-Agent")
	}
}
