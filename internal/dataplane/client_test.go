package dataplane_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

func TestClientAgainstFakeSocket(t *testing.T) {
	srv := fakedataplane.Start(t)
	c := dataplane.NewClient(srv.Socket)
	ctx := context.Background()

	if err := c.Health(ctx); err != nil {
		t.Fatal(err)
	}
	st, err := c.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != 0 {
		t.Fatalf("fresh data plane version = %d, want 0", st.Version)
	}

	plan := &configir.Plan{
		Revision:    9007199254740993, // > 2^53: must survive Lua's doubles as a string
		ContentHash: "abc",
		Sites: []configir.Site{{
			ID: "s1", Domains: []configir.Domain{{Name: "a.test"}}, CacheZone: "z",
			CacheGeneration: 18446744073709551615, LoadBalance: configir.LBWeighted,
			Origins:    []configir.Origin{{ID: "o", Scheme: "http", Address: "10.0.0.1", Port: 80, Weight: 1}},
			CacheRules: []configir.CacheRule{{ID: "r", Action: "cache", TTL: 60, Mode: "override", PathPrefixes: []string{"/"}}},
		}},
	}
	table := dataplane.FromPlan(plan)
	if st.InSync(table) {
		t.Fatal("empty data plane reported in sync")
	}
	got, err := c.PutSites(ctx, table)
	if err != nil {
		t.Fatal(err)
	}
	if !got.InSync(table) || got.SiteCount != 1 {
		t.Fatalf("status after push = %+v", got)
	}
	if srv.Table().Sites[0].CacheGeneration != 18446744073709551615 {
		t.Fatal("cache generation lost precision")
	}

	srv.Restart()
	st, _ = c.Status(ctx)
	if st.InSync(table) {
		t.Fatal("restarted data plane reported in sync")
	}

	srv.FailNextPuts(1)
	_, err = c.PutSites(ctx, table)
	var apiErr *dataplane.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 500 || apiErr.Message != "injected failure" {
		t.Fatalf("err = %v, want APIError 500", err)
	}

	stats, err := c.DrainStats(ctx)
	if err != nil || len(stats) != 0 {
		t.Fatalf("empty drain = %v, %v", stats, err)
	}
	srv.AddStats(dataplane.MinuteStats{Minute: 1800000000, SiteID: "s1", Requests: 3, StatusCodes: map[string]uint64{"200": 3}})
	stats, err = c.DrainStats(ctx)
	if err != nil || len(stats) != 1 || stats[0].StatusCodes["200"] != 3 {
		t.Fatalf("drain = %+v, %v", stats, err)
	}
}

func TestSiteTableJSONShape(t *testing.T) {
	table := dataplane.FromPlan(&configir.Plan{Revision: 12, ContentHash: "h"})
	b, err := json.Marshal(table)
	if err != nil {
		t.Fatal(err)
	}
	// Revision is a string (Lua numbers are doubles) and empty lists are
	// arrays, never null.
	if want := `{"revision":"12","content_hash":"h","sites":[],"origin_allowed_cidrs":[]}`; string(b) != want {
		t.Fatalf("JSON = %s, want %s", b, want)
	}
	table = dataplane.FromPlan(&configir.Plan{Revision: 1, OriginAllowedCIDRs: []string{"10.0.0.0/8"}})
	table.CDNID = dataplane.CDNID("node-1")
	b, _ = json.Marshal(table)
	if !strings.Contains(string(b), `"origin_allowed_cidrs":["10.0.0.0/8"]`) || !strings.Contains(string(b), `"cdn_id":"edgeweir-`) {
		t.Fatalf("JSON = %s", b)
	}
	site := configir.Site{ID: "s", Domains: []configir.Domain{{Name: "a.test", Wildcard: true}}, CacheGeneration: 3,
		Origins: []configir.Origin{{ID: "o", Scheme: "https", Address: "o.test", Port: 443, Weight: 2, Backup: true, HostHeader: "h.test", SNI: "s.test"}}}
	site.Origins = append(site.Origins, configir.Origin{ID: "f", Scheme: "http", Address: "127.0.0.1", Port: 80, Forbidden: true})
	b, _ = json.Marshal(site)
	for _, want := range []string{`"cache_generation":"3"`, `"wildcard":true`, `"host_header":"h.test"`, `"sni":"s.test"`, `"backup":true`, `"forbidden":true`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("site JSON %s missing %s", b, want)
		}
	}
}

func TestClientSocketMissing(t *testing.T) {
	c := dataplane.NewClient("/nonexistent/edgeweir/control.sock")
	if _, err := c.Status(context.Background()); err == nil {
		t.Fatal("status against a missing socket succeeded")
	}
}

// TestCDNID pins the CDN-Loop identifier: "edgeweir-" + the first 16 hex
// characters of sha256(node id).
func TestCDNID(t *testing.T) {
	// sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad.
	if got := dataplane.CDNID("node-1"); len(got) != len("edgeweir-")+16 || !strings.HasPrefix(got, "edgeweir-") {
		t.Fatalf("CDNID = %q", got)
	}
	if got, want := dataplane.CDNID("abc"), "edgeweir-ba7816bf8f01cfea"; got != want {
		t.Fatalf("CDNID(abc) = %q, want %q", got, want)
	}
	if dataplane.CDNID("") != "" {
		t.Fatal("CDNID of an unknown node must be empty")
	}
	st := dataplane.Status{Version: 1, Revision: 2, ContentHash: "h", CDNID: "x"}
	if st.InSync(&dataplane.SiteTable{Revision: 2, ContentHash: "h", CDNID: "y"}) {
		t.Fatal("a table with another cdn_id counts as in sync")
	}
}

func TestClientBans(t *testing.T) {
	srv := fakedataplane.Start(t)
	c := dataplane.NewClient(srv.Socket)
	ctx := context.Background()

	st, err := c.BanStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Sequence != 0 || st.Entries != 0 || st.UnappliedIDs != nil {
		t.Fatalf("fresh ban status = %+v", st)
	}
	srv.SetBanCapacity(2)
	st, err = c.PutBans(ctx, &dataplane.BanTable{Sequence: 18446744073709551615, Bans: []dataplane.Ban{
		{ID: "m1", CIDR: "198.51.100.0/24", Scope: "platform", Kind: "m", ExpiresAt: 1790000000.5},
		{ID: "m2", CIDR: "203.0.113.7/32", Scope: "site", SiteID: "site-a", Kind: "m", ExpiresAt: 1790000000},
		{ID: "m3", CIDR: "203.0.113.8/32", Scope: "site", SiteID: "site-a", Kind: "m", ExpiresAt: 1790000000},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Sequence != 18446744073709551615 || st.Entries != 2 || st.Unapplied != 1 || strings.Join(st.UnappliedIDs, ",") != "m3" {
		t.Fatalf("status after PUT = %+v", st)
	}
	_, err = c.AddBans(ctx, &dataplane.BanDelta{Base: 7, Sequence: 8})
	var apiErr *dataplane.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 409 {
		t.Fatalf("delta on the wrong base: %v", err)
	}
	st, err = c.AddBans(ctx, &dataplane.BanDelta{Base: 18446744073709551615, Sequence: 18446744073709551615,
		Remove: []dataplane.Ban{{ID: "m1", CIDR: "198.51.100.0/24", Scope: "platform"}}})
	if err != nil || st.Entries != 1 {
		t.Fatalf("delta: %+v, %v", st, err)
	}

	st, list, err := c.ListBans(ctx)
	if err != nil || st.Entries != 1 || len(list) != 1 || list[0].ID != "m2" || list[0].SiteID != "site-a" || list[0].Kind != "m" {
		t.Fatalf("list = %+v %+v, %v", st, list, err)
	}

	srv.AddAutoBans(dataplane.AutoBan{SiteID: "site-a", IP: "192.0.2.1", PrefixLen: 32, CreatedAt: 1, ExpiresAt: 61, Reason: "cc_ip_rate", Metric: "ip_qps", Observed: 150, Threshold: 100, WindowSeconds: 10})
	auto, err := c.DrainAutoBans(ctx)
	if err != nil || len(auto) != 1 || auto[0].IP != "192.0.2.1" || auto[0].WindowSeconds != 10 {
		t.Fatalf("drain = %+v, %v", auto, err)
	}
	if auto, err = c.DrainAutoBans(ctx); err != nil || auto != nil {
		t.Fatalf("empty drain = %+v, %v", auto, err)
	}
	var decoded dataplane.BanStatus
	if err := json.Unmarshal([]byte(`{"sequence":"3","entries":1,"unapplied_ids":{}}`), &decoded); err != nil || decoded.Sequence != 3 || decoded.UnappliedIDs != nil {
		t.Fatalf("lua-cjson status: %+v, %v", decoded, err)
	}
}
