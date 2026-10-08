package render

import (
	"regexp"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

// httpBlock returns the http {} block of conf (without the stream block).
func httpBlock(t *testing.T, conf string) string {
	t.Helper()
	start := strings.Index(conf, "\nhttp {")
	if start < 0 {
		t.Fatal("no http block")
	}
	if end := strings.Index(conf, "\nstream {"); end > start {
		return conf[start:end]
	}
	return conf[start:]
}

// TestRenderTLSSessions: with an HTTPS listener the http block caches TLS
// sessions; ticket keys turn tickets on in the order current, previous,
// next, else tickets are off. Edge servers set nothing of their own but
// early data off.
func TestRenderTLSSessions(t *testing.T) {
	plan := compressionPlan()
	got, err := Render(params(), plan)
	if err != nil {
		t.Fatal(err)
	}
	conf := string(got)
	for directive, want := range map[string]int{
		"\n    ssl_session_cache shared:edgeweir_tls:16m;\n": 1,
		"\n    ssl_session_timeout 1h;\n":                    1,
		"\n    ssl_session_tickets off;\n":                   1,
		"ssl_session_tickets on;":                            0,
		"ssl_session_ticket_key":                             0,
		// Not per server any more.
		"\n        ssl_session_tickets": 0,
	} {
		if n := strings.Count(conf, directive); n != want {
			t.Errorf("%q appears %d times, want %d", directive, n, want)
		}
	}
	servers := strings.Count(conf, `ssl_certificate_by_lua_block { require("edgeweir.tls").certificate() }`)
	if servers < 4 {
		t.Fatalf("only %d TLS edge servers", servers)
	}
	if n := strings.Count(conf, "\n        ssl_early_data off;\n"); n != servers {
		t.Errorf("ssl_early_data off in %d of %d TLS edge servers", n, servers)
	}

	plan.TicketKeys = []string{"k2", "k1", "k3"}
	got, err = Render(params(), plan)
	if err != nil {
		t.Fatal(err)
	}
	want := "    ssl_session_tickets on;\n" +
		"    ssl_session_ticket_key /var/lib/edgeweir-node/nginx/conf/tls-tickets/k2.key;\n" +
		"    ssl_session_ticket_key /var/lib/edgeweir-node/nginx/conf/tls-tickets/k1.key;\n" +
		"    ssl_session_ticket_key /var/lib/edgeweir-node/nginx/conf/tls-tickets/k3.key;\n"
	if !strings.Contains(string(got), want) || strings.Contains(string(got), "ssl_session_tickets off;") {
		t.Fatalf("ticket keys not rendered in order:\n%s", httpBlock(t, string(got)))
	}
	if TicketKeyPath("/p", "k1") != "/p/conf/tls-tickets/k1.key" {
		t.Fatal(TicketKeyPath("/p", "k1"))
	}
	plan.TicketKeys = []string{"k 1"}
	if _, err := Render(params(), plan); err == nil {
		t.Fatal("unsafe ticket key id rendered")
	}

	// Without an HTTPS listener: no session cache and no ticket settings.
	plain := configir.Bootstrap(80)
	plain.TicketKeys = []string{"k1"}
	got, err = Render(params(), plain)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "ssl_session") {
		t.Fatal("session settings without an HTTPS listener")
	}
}

// TestRenderL4TLSKeepsSessionsOff: TLS of layer-4 applications keeps
// tickets off and has no session cache (the stream block inherits nothing
// from http {}).
func TestRenderL4TLSKeepsSessionsOff(t *testing.T) {
	plan := l4Plan()
	plan.Listeners = append(plan.Listeners, configir.Listener{Port: 443, TLS: true})
	plan.TicketKeys = []string{"k1"}
	got, err := Render(params(), plan)
	if err != nil {
		t.Fatal(err)
	}
	conf := string(got)
	stream := conf[strings.Index(conf, "\nstream {"):]
	if n := strings.Count(stream, "ssl_session_tickets off;"); n != 2 {
		t.Fatalf("stream TLS servers with tickets off: %d", n)
	}
	if strings.Contains(stream, "ssl_session_cache") || strings.Contains(stream, "ssl_session_ticket_key") || strings.Contains(stream, "ssl_early_data") {
		t.Fatal("stream block caches TLS sessions")
	}
	if !strings.Contains(httpBlock(t, conf), "ssl_session_ticket_key") {
		t.Fatal("http block without ticket keys")
	}
}

// TestNoEarlyData: TLS early data (0-RTT) is never turned on, neither in
// the template nor in any rendered configuration.
func TestNoEarlyData(t *testing.T) {
	on := regexp.MustCompile(`ssl_early_data\s+on`)
	if on.MatchString(confTemplate) {
		t.Fatal("the template turns early data on")
	}
	plans := map[string]*configir.Plan{"compression": compressionPlan(), "edge ports": edgePortsPlan(), "domains": domainsPlan(), "waf": wafPlan(), "l4": l4Plan(), "bootstrap": configir.Bootstrap(80)}
	for name, plan := range plans {
		p := params()
		if name == "waf" {
			p = wafParams()
		}
		got, err := Render(p, plan)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if on.Match(got) {
			t.Fatalf("%s: early data on", name)
		}
	}
}
