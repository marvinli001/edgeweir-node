package render

import (
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

func tierPlan(listen, lower bool) *configir.Plan {
	plan := configir.Bootstrap(80)
	plan.Tier = &configir.Tier{Port: 8444, Listen: listen, Lower: lower,
		CertPath: "/p/conf/tier/node-0123456789abcdef.crt", KeyPath: "/p/conf/tier/node-0123456789abcdef.key",
		CAPath: "/p/conf/tier/node-0123456789abcdef-ca.crt"}
	return plan
}

// TestTierServers: the tier layer for lower tiers, the TLS tier listener
// for upper tiers (client certificates of the node CA), and nothing of
// either without a tiered cache.
func TestTierServers(t *testing.T) {
	render := func(plan *configir.Plan) string {
		t.Helper()
		out, err := Render(params(), plan)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	none := render(configir.Bootstrap(80))
	for _, s := range []string{"edgeweir_tier", "X-Edgeweir-Tier", "8444"} {
		if strings.Contains(none, s) {
			t.Errorf("without a tiered cache: %q", s)
		}
	}
	lower := render(tierPlan(false, true))
	for _, s := range []string{
		"upstream edgeweir_tier_balancer", "listen unix:" + params().WithDefaults().TierSocket + ";",
		"proxy_pass https://edgeweir_tier_balancer;",
		"proxy_ssl_certificate /p/conf/tier/node-0123456789abcdef.crt;",
		"proxy_ssl_trusted_certificate /p/conf/tier/node-0123456789abcdef-ca.crt;",
		"proxy_ssl_verify on;", "proxy_ssl_name $edgeweir_ssl_name;",
		"error_page 502 504 = @edgeweir_tier_fallback;", "proxy_pass http://$edgeweir_tier_fallback;",
		"proxy_pass_header X-Accel-Expires;",
		"proxy_set_header X-Edgeweir-Tier-Key $edgeweir_tier_key;", "proxy_hide_header X-Edgeweir-Tier;",
		`set $edgeweir_tier_key "";`,
	} {
		if !strings.Contains(lower, s) {
			t.Errorf("lower tier lacks %q", s)
		}
	}
	// Both ways out of the tier layer keep the client's Host (nginx would
	// send the upstream's name, which the origin layer then forwards).
	for _, pass := range []string{"proxy_pass https://edgeweir_tier_balancer;", "proxy_pass http://$edgeweir_tier_fallback;"} {
		i := strings.Index(lower, pass)
		if i < 0 || !strings.Contains(lower[i:i+300], "proxy_set_header Host $host;") {
			t.Errorf("%s without proxy_set_header Host $host", pass)
		}
	}
	if strings.Contains(lower, "ssl_verify_client") {
		t.Error("a lower tier only has no tier listener")
	}
	upper := render(tierPlan(true, false))
	for _, s := range []string{
		"listen 8444 ssl;", "ssl_verify_client on;", "ssl_client_certificate /p/conf/tier/node-0123456789abcdef-ca.crt;",
		"ssl_verify_depth 1;", `set $edgeweir_tier_in "1";`, `require("edgeweir.tier").upper_access()`,
		"proxy_set_header X-Forwarded-For $http_x_forwarded_for;", "proxy_set_header X-Real-IP $http_x_real_ip;",
		"proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;",
		"add_header X-Edgeweir-Tier-Cache $upstream_cache_status always;",
		// The origin layers drop the tier headers before the origins.
		`proxy_set_header X-Edgeweir-Tier-Key "";`,
	} {
		if !strings.Contains(upper, s) {
			t.Errorf("upper tier lacks %q", s)
		}
	}
	if strings.Contains(upper, "upstream edgeweir_tier_balancer") {
		t.Error("an upper tier only has no tier layer")
	}
	// The public listeners keep their own client-side settings.
	if !strings.Contains(upper, "add_header X-Cache $edgeweir_x_cache always;") || !strings.Contains(upper, "proxy_set_header X-Real-IP $remote_addr;") {
		t.Error("the edge servers changed")
	}
	bad := tierPlan(true, true)
	bad.Tier.KeyPath = "/p/key with space"
	if _, err := Render(params(), bad); err == nil {
		t.Error("an unsafe path renders")
	}
}
