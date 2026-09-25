package dataplane_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/edgeweir/edgeweir-node/internal/configir"
	"github.com/edgeweir/edgeweir-node/internal/dataplane"
	"github.com/edgeweir/edgeweir-node/internal/testutil/fakedataplane"
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
	// Revision is a string (Lua numbers are doubles) and an empty site list
	// is an array, never null.
	if want := `{"revision":"12","content_hash":"h","sites":[]}`; string(b) != want {
		t.Fatalf("JSON = %s, want %s", b, want)
	}
	site := configir.Site{ID: "s", Domains: []configir.Domain{{Name: "a.test", Wildcard: true}}, CacheGeneration: 3,
		Origins: []configir.Origin{{ID: "o", Scheme: "https", Address: "o.test", Port: 443, Weight: 2, Backup: true, HostHeader: "h.test", SNI: "s.test"}}}
	b, _ = json.Marshal(site)
	for _, want := range []string{`"cache_generation":"3"`, `"wildcard":true`, `"host_header":"h.test"`, `"sni":"s.test"`, `"backup":true`} {
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
