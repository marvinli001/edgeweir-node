package dataplane_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

// TestDrainLogsCarriesG16Fields: the fields of proto v0.30.0 (ADR-0041)
// with their bounds, and the site's optional fields.
func TestDrainLogsCarriesG16Fields(t *testing.T) {
	srv := fakedataplane.Start(t)
	c := dataplane.NewClient(srv.Socket)
	srv.AddLogEntry(map[string]any{
		"site_id": "s1", "time": 1800000000.25, "path": "/a", "status": 403, "sample_rate": 10000,
		"user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
		"referer":    "https://ref.test/page", "http_version": "2", "scheme": "https",
		"country": "NZ", "asn": 64512, "as_name": "Synthetic AS64512",
		"upstream_addr": "10.0.0.5:8080", "upstream_status": 200, "upstream_ms": 34,
		"request_bytes": 321, "content_type": "text/html", "tls_version": "1.3",
		"block_reason": "rule", "block_rule_id": "r-block",
		"query": "a=1&b=2", "headers": map[string]any{"x-trace-id": "trace-1", "accept-language": "en, de"}, "peer_ip": "10.0.0.9",
	})
	srv.AddLogEntry(map[string]any{
		"site_id": "s1", "time": 1800000001, "path": "/b", "status": 200,
		"user_agent": strings.Repeat("u", 600) + "\x1b[31m", "referer": "https://ref.test/p?token=secret#frag",
		"http_version": "0.9", "scheme": "ftp", "country": "nz", "asn": 0, "as_name": "orphan",
		"upstream_status": 999, "upstream_ms": 100000000, "request_bytes": 1 << 60,
		"content_type": "Text/HTML; charset=utf-8", "tls_version": "1.1",
		"block_reason": "bogus", "block_rule_id": "r1",
		"query": strings.Repeat("q", 3000), "peer_ip": "not an address",
		"headers": map[string]any{"cookie": "secret", "Bad Name": "x", "x-long": strings.Repeat("€", 200),
			"a": "1", "b": "2", "c": "3", "d": "4", "e": "5", "f": "6", "g": "7", "z1": "9"},
	})
	srv.AddLogEntry(map[string]any{"site_id": "s1", "time": 1800000002, "path": "/c", "status": 200,
		"block_reason": "challenge", "block_rule_id": "bad id"})
	logs, err := c.DrainLogs(context.Background())
	if err != nil || len(logs) != 3 {
		t.Fatalf("DrainLogs = %v, %v", logs, err)
	}
	a := logs[0]
	if a.GetUserAgent() != "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0" || a.GetReferer() != "https://ref.test/page" ||
		a.GetHttpVersion() != "2" || a.GetScheme() != "https" || a.GetCountry() != "NZ" || a.GetAsn() != 64512 ||
		a.GetAsName() != "Synthetic AS64512" || a.GetUpstreamAddr() != "10.0.0.5:8080" || a.GetUpstreamStatus() != 200 ||
		a.GetUpstreamMs() != 34 || a.GetRequestBytes() != 321 || a.GetContentType() != "text/html" || a.GetTlsVersion() != "1.3" ||
		a.GetBlockReason() != "rule" || a.GetBlockRuleId() != "r-block" || a.GetQuery() != "a=1&b=2" ||
		a.GetHeaders()["x-trace-id"] != "trace-1" || a.GetHeaders()["accept-language"] != "en, de" || a.GetPeerIp() != "10.0.0.9" {
		t.Fatalf("line = %v", a)
	}
	b := logs[1]
	if len(b.GetUserAgent()) != 512 || strings.ContainsRune(b.GetUserAgent(), 0x1b) {
		t.Errorf("user agent not bounded: %d", len(b.GetUserAgent()))
	}
	if b.GetReferer() != "https://ref.test/p" {
		t.Errorf("referer %q keeps its query", b.GetReferer())
	}
	if b.GetHttpVersion() != "" || b.GetScheme() != "" || b.GetCountry() != "" || b.GetAsName() != "" || b.GetUpstreamStatus() != 0 ||
		b.GetUpstreamMs() != 86_400_000 || b.GetRequestBytes() != 1<<53-1 || b.GetContentType() != "" || b.GetTlsVersion() != "" ||
		b.GetBlockReason() != "" || b.GetBlockRuleId() != "" || len(b.GetQuery()) != 2048 || b.GetPeerIp() != "" {
		t.Errorf("invalid values kept: %v", b)
	}
	h := b.GetHeaders()
	// At most 8 (the first by name), never cookie, values of at most 512 bytes.
	if _, z := h["z1"]; len(h) != 8 || z || h["cookie"] != "" || h["Bad Name"] != "" || h["g"] != "7" || len(h["x-long"]) != 510 {
		t.Errorf("headers = %d %v", len(h), h)
	}
	if c := logs[2]; c.GetBlockReason() != "challenge" || c.GetBlockRuleId() != "" || c.GetHeaders() != nil || c.GetUserAgent() != "" {
		t.Errorf("line = %v", c)
	}
}

func TestText(t *testing.T) {
	for in, want := range map[string]string{
		"plain":          "plain",
		"a\x00b\tc\x7fd": "abcd",
		"\xffbad":        "bad",
		"\u009b[31m":     "[31m",
	} {
		if got := dataplane.Text(in, 64); got != want {
			t.Errorf("Text(%q) = %q, want %q", in, got, want)
		}
	}
	if got := dataplane.Text("ab€€", 6); got != "ab€" {
		t.Errorf("cut inside a character: %q", got)
	}
}

// TestTap: the live view's pages, the site filter and the bounds of the
// entries' fields.
func TestTap(t *testing.T) {
	srv := fakedataplane.Start(t)
	c := dataplane.NewClient(srv.Socket)
	ctx := context.Background()
	first, err := c.Tap(ctx, 0, "")
	if err != nil || first.Seq != 1 || len(first.Entries) != 0 {
		t.Fatalf("first call = %+v, %v", first, err)
	}
	srv.AddTapEntry(map[string]any{"site_id": "s1", "time": 1800000000.5, "client_ip": "203.0.113.7", "method": "GET", "host": "a.test",
		"path": "/x", "status": 403, "bytes_sent": 120, "duration_ms": 3, "block_reason": "rule", "block_rule_id": "r1", "country": "NZ",
		"http_version": "9"})
	srv.AddTapEntry(nil)
	srv.AddTapEntry(map[string]any{"site_id": "", "time": 1800000001, "path": "/scan", "status": 404})
	page, err := c.Tap(ctx, first.Seq, "")
	if err != nil || page.Seq != 4 || page.Missed != 1 || len(page.Entries) != 2 {
		t.Fatalf("page = %+v, %v", page, err)
	}
	e := page.Entries[0]
	if e.SiteID != "s1" || e.ClientIP != "203.0.113.7" || e.Status != 403 || e.BlockReason != "rule" || e.BlockRuleID != "r1" ||
		e.Country != "NZ" || e.HTTPVersion != "" {
		t.Fatalf("entry = %+v", e)
	}
	page, err = c.Tap(ctx, first.Seq, "s1")
	if err != nil || len(page.Entries) != 1 {
		t.Fatalf("site page = %+v, %v", page, err)
	}
	calls := srv.TapCalls()
	if calls[0] != "after=0" || calls[len(calls)-1] != "after=1&site=s1" {
		t.Fatalf("calls = %v", calls)
	}
}

// TestMinuteStatsDecodesDimensions: the JSON names of the dimensions in a
// bucket of POST /v1/stats/drain (lua/edgeweir/stats.lua).
func TestMinuteStatsDecodesDimensions(t *testing.T) {
	raw := `{"minute":1800000000,"site_id":"s1","requests":3,"status_codes":{"200":3},
		"countries":{"NZ":{"requests":2,"bytes_sent":200},"":{"requests":1,"bytes_sent":10}},
		"asns":{"64512":{"requests":2,"name":"Synthetic AS64512"}},"referers":{"news.example.org":1},
		"browsers":{"firefox":2,"tool":1},"operating_systems":{"windows":2},"devices":{"desktop":2},
		"http_versions":{"2":2,"1.1":1},"tls_versions":{"1.3":2,"none":1},"block_reasons":{"rule":1},
		"challenges_issued":4,"challenges_passed":1}`
	var m dataplane.MinuteStats
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	if m.Countries["NZ"].BytesSent != 200 || m.Countries[""].Requests != 1 || m.ASNs["64512"].Name != "Synthetic AS64512" ||
		m.Referers["news.example.org"] != 1 || m.Browsers["firefox"] != 2 || m.OperatingSystems["windows"] != 2 ||
		m.Devices["desktop"] != 2 || m.HTTPVersions["2"] != 2 || m.TLSVersions["none"] != 1 || m.BlockReasons["rule"] != 1 ||
		m.ChallengesIssued != 4 || m.ChallengesPassed != 1 {
		t.Fatalf("decoded %+v", m)
	}
}
