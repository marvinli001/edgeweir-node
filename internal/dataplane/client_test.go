package dataplane_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
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

	stats, err := c.DrainStats(ctx, false)
	if err != nil || len(stats) != 0 {
		t.Fatalf("empty drain = %v, %v", stats, err)
	}
	srv.AddStats(dataplane.MinuteStats{Minute: 1800000000, SiteID: "s1", Requests: 3, StatusCodes: map[string]uint64{"200": 3}})
	stats, err = c.DrainStats(ctx, false)
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

func TestClientChallengeAndSecurity(t *testing.T) {
	srv := fakedataplane.Start(t)
	c := dataplane.NewClient(srv.Socket)
	ctx := context.Background()

	st, err := c.ChallengeStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Current != "" || len(st.Keys) != 0 || st.Captchas != 0 {
		t.Fatalf("fresh challenge status = %+v", st)
	}
	st, err = c.PutChallengeKeys(ctx, &dataplane.ChallengeKeys{ID: "set", Current: "k2", Keys: []dataplane.ChallengeKey{{ID: "k1", Secret: "YQ=="}, {ID: "k2", Secret: "Yg=="}}})
	if err != nil || st.KeysID != "set" || st.Current != "k2" || len(st.Keys) != 2 {
		t.Fatalf("after PUT keys: %+v, %v", st, err)
	}
	st, err = c.PutCaptchas(ctx, &dataplane.CaptchaPool{ID: "pool", Images: []dataplane.Captcha{{Answer: "ABCDE", PNG: "iVBORw0KGgo="}}})
	if err != nil || st.Captchas != 1 || st.CaptchasID != "pool" {
		t.Fatalf("after PUT captchas: %+v, %v", st, err)
	}

	sec, err := c.SecurityStatus(ctx)
	if err != nil || len(sec.Sites) != 0 {
		t.Fatalf("empty security status: %+v, %v", sec, err)
	}
	events, err := c.DrainSecurity(ctx)
	if err != nil || events != nil {
		t.Fatalf("empty drain: %v, %v", events, err)
	}
	srv.SetSecurity(dataplane.SecuritySite{SiteID: "s1", Level: "js", EscalatedPaths: 1, Paths: dataplane.List[dataplane.SecurityPath]{{Path: "/login", Level: "pow"}}})
	srv.AddSecurityEvents(dataplane.SecurityEvent{ID: "b-1", SiteID: "s1", Kind: "site_level", Level: "js", PreviousLevel: "cookie302"})
	sec, err = c.SecurityStatus(ctx)
	if err != nil || len(sec.Sites) != 1 || sec.Sites[0].Paths[0].Path != "/login" || sec.PendingEvents != 1 {
		t.Fatalf("security status: %+v, %v", sec, err)
	}
	events, err = c.DrainSecurity(ctx)
	if err != nil || len(events) != 1 || events[0].ID != "b-1" {
		t.Fatalf("drain: %+v, %v", events, err)
	}
}

// lua-cjson writes empty tables as {}; the lists accept both forms.
func TestSecurityEventJSONFromLua(t *testing.T) {
	raw := `{"events":[{"id":"a1b2-7","site_id":"s1","time":1790000000.5,"kind":"ip_banned","level":"normal",` +
		`"previous_level":"normal","address":"198.51.100.23","metric":"ip_qps","observed":6.2,"threshold":5,` +
		`"top_ips":[{"value":"198.51.100.23","count":31}],"top_paths":{}}]}`
	var out struct {
		Events dataplane.List[dataplane.SecurityEvent] `json:"events"`
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	e := out.Events[0]
	if e.Kind != "ip_banned" || e.Address != "198.51.100.23" || len(e.TopIPs) != 1 || e.TopIPs[0].Count != 31 || e.TopPaths != nil {
		t.Fatalf("event = %+v", e)
	}
	if err := json.Unmarshal([]byte(`{"events":{}}`), &out); err != nil || out.Events != nil {
		t.Fatalf("{} = %v, %v", out.Events, err)
	}
}

func TestDrainLogsCarriesCRSMatches(t *testing.T) {
	srv := fakedataplane.Start(t)
	c := dataplane.NewClient(srv.Socket)
	ids := make([]any, 20)
	for i := range ids {
		ids[i] = 941100 + i
	}
	srv.AddLogEntry(map[string]any{"site_id": "s1", "time": 1800000000.5, "path": "/", "status": 403, "waf_rule_ids": ids, "waf_blocked": true})
	srv.AddLogEntry(map[string]any{"site_id": "s1", "time": 1800000001, "path": "/", "status": 200})
	logs, err := c.DrainLogs(context.Background())
	if err != nil || len(logs) != 2 {
		t.Fatalf("DrainLogs = %v, %v", logs, err)
	}
	if got := logs[0].GetWafRuleIds(); len(got) != 16 || got[0] != 941100 || got[15] != 941115 || !logs[0].GetWafBlocked() {
		t.Fatalf("CRS fields = %v %v", got, logs[0].GetWafBlocked())
	}
	if logs[1].GetWafRuleIds() != nil || logs[1].GetWafBlocked() {
		t.Fatalf("request without CRS matches: %v", logs[1])
	}
}

// TestSiteTableG4Fields pins the site table fields of proto v0.12.0: the
// Cache-Tag, error page, active health and affinity settings of a site,
// and the table's tag index lifetime, platform pages and offline hosts.
func TestSiteTableG4Fields(t *testing.T) {
	plan := &configir.Plan{
		Revision: 3,
		CacheZones: []configir.CacheZone{
			{Name: "a", InactiveSeconds: 600}, {Name: "b", InactiveSeconds: 86400}, {Name: "c", InactiveSeconds: 3600},
		},
		Sites: []configir.Site{{
			ID: "s1", KeepCacheTag: true,
			ErrorPages:        &configir.ErrorPages{Pages: map[uint32]string{503: "page {{status}}", 403: "denied"}, Intercept: true},
			ActiveHealthCheck: &configir.ActiveHealthCheck{Path: "/healthz", Method: "HEAD", ExpectedStatusMin: 200, ExpectedStatusMax: 299},
			ActiveHealth:      true,
			Affinity:          &configir.Affinity{TTL: 7200},
		}, {ID: "s2"}},
		PlatformErrorPages: &configir.PlatformErrorPages{SiteSuspended: "suspended"},
		OfflineHosts:       []configir.OfflineHost{{Name: "old.test", Reason: "disabled"}, {Name: "gone.test", Wildcard: true, Reason: "suspended"}},
	}
	table := dataplane.FromPlan(plan)
	if table.TagTTL != 86400 {
		t.Fatalf("tag_ttl = %d, want the longest inactive time 86400", table.TagTTL)
	}
	b, err := json.Marshal(table)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{
		`"keep_cache_tag":true`,
		`"error_pages":{"pages":{"403":"denied","503":"page {{status}}"},"intercept":true}`,
		`"active_health":true`,
		`"affinity":{"ttl":7200}`,
		`"tag_ttl":86400`,
		`"platform_error_pages":{"site_suspended":"suspended"}`,
		`"offline_hosts":[{"name":"old.test","reason":"disabled"},{"name":"gone.test","wildcard":true,"reason":"suspended"}]`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("site table %s\nmissing %s", got, want)
		}
	}
	// The active check's settings are for the agent's prober only.
	for _, leak := range []string{"healthz", "HEAD", "expected"} {
		if strings.Contains(got, leak) {
			t.Errorf("site table carries active health settings (%s): %s", leak, got)
		}
	}
	// A site without the v0.12.0 settings carries none of their fields.
	b, _ = json.Marshal(plan.Sites[1])
	for _, field := range []string{"keep_cache_tag", "error_pages", "active_health", "affinity"} {
		if strings.Contains(string(b), field) {
			t.Errorf("plain site JSON %s has %s", b, field)
		}
	}
}

// TestSiteTableG5Fields pins the site table fields of proto v0.13.0
// (rules-v2) that edgeweir.store, edgeweir.policy and edgeweir.rules read:
// bulk redirects, origin groups, cache rule conditions and browser TTLs,
// and rule actions in their protobuf field names. Explicitly set false and
// zero values of optional fields stay in the JSON.
func TestSiteTableG5Fields(t *testing.T) {
	no, zero := false, uint32(0)
	path := &nodev1.RuleExpression{Op: "field", Field: "http.request.uri.path", ValueType: "string"}
	yes := &nodev1.RuleExpression{Op: "literal", ValueType: "boolean", Value: "true"}
	c := &nodev1.NodeConfig{Sites: []*nodev1.Site{{
		Id: "s1", Enabled: true, Domains: []*nodev1.Domain{{Name: "a.test"}},
		OriginPool: &nodev1.OriginPool{Origins: []*nodev1.Origin{
			{Id: "o1", Address: "origin.test", Port: 80}, {Id: "o2", Address: "api.test", Port: 80, Group: "api"},
		}},
		BulkRedirects: []*nodev1.BulkRedirect{{Source: "/old", Target: "/new", StatusCode: 301, PreserveQuery: true}},
		CacheRules: []*nodev1.CacheRule{{Id: "c1", Action: nodev1.CacheAction_CACHE_ACTION_CACHE, EdgeTtlSeconds: 60, BrowserTtlSeconds: 600,
			Match: &nodev1.CacheRuleMatch{Condition: &nodev1.RuleExpression{Op: "call", Field: "starts_with", ValueType: "boolean",
				Children: []*nodev1.RuleExpression{path, {Op: "const", ValueType: "string", Value: "/img/"}}}}}},
		Rules: []*nodev1.EdgeRule{
			{Id: "r1", Phase: "redirect", Expression: yes, Action: &nodev1.RuleAction{Kind: "redirect", StatusCode: 308, Target: path,
				SetQuery: []*nodev1.QueryParam{{Name: "a", Value: "1"}}, RemoveQuery: []string{"b"}}},
			{Id: "r2", Phase: "config", Expression: yes, Action: &nodev1.RuleAction{Kind: "config", CcEnabled: &no, LogSampleRate: &zero, OriginReadTimeoutMs: 5000}},
			{Id: "r3", Phase: "origin", Expression: yes, Action: &nodev1.RuleAction{Kind: "origin", OriginGroup: "api", Port: 8080}},
			{Id: "r4", Phase: "compression", Expression: yes, Action: &nodev1.RuleAction{Kind: "compression", Compression: []string{"br"}}},
		},
	}}}
	plan, err := configir.Build(c, configir.Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(dataplane.FromPlan(plan))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{
		`"bulk_redirects":[{"source":"/old","target":"/new","status":301,"preserve_query":true}]`,
		`"id":"o2","scheme":"http","address":"api.test","port":80,"weight":1,"group":"api"`,
		`"browser_ttl":600`,
		`"condition":{"op":"call","field":"starts_with","value_type":"boolean","children":[{"op":"field","field":"http.request.uri.path","value_type":"string"},{"op":"const","value_type":"string","value":"/img/"}]}`,
		`"target":{"op":"field","field":"http.request.uri.path","value_type":"string"}`,
		`"set_query":[{"name":"a","value":"1"}],"remove_query":["b"]`,
		`"cc_enabled":false`, `"origin_read_timeout_ms":5000`, `"log_sample_rate":0`,
		`"origin_group":"api"`, `"port":8080`, `"compression":["br"]`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("site table %s\nmissing %s", got, want)
		}
	}
	// The default group's origins and plain cache rules carry none of the fields.
	if strings.Count(got, `"group"`) != 1 || strings.Contains(got, `"browser_ttl":0`) {
		t.Errorf("site table %s", got)
	}
}

func TestPurgeTagMarkerJSON(t *testing.T) {
	b, err := json.Marshal(dataplane.PurgeMarker{SiteID: "s1", Type: "tag", Tag: "product-42", Epoch: 1790000000123})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"site_id":"s1","type":"tag","tag":"product-42","epoch":1790000000123}`; string(b) != want {
		t.Fatalf("JSON = %s, want %s", b, want)
	}
	srv := fakedataplane.Start(t)
	c := dataplane.NewClient(srv.Socket)
	st, err := c.AddPurge(context.Background(), &dataplane.PurgeTable{ID: "set-1", Markers: []dataplane.PurgeMarker{
		{SiteID: "s1", Type: "tag", Tag: "a", Epoch: 10},
		{SiteID: "s1", Type: "tag", Tag: "b", Epoch: 11},
	}})
	if err != nil || st.ID != "set-1" || len(srv.Markers()) != 2 {
		t.Fatalf("tag markers: %+v %v (%v)", st, err, srv.Markers())
	}
}

func TestClientPutActiveHealth(t *testing.T) {
	srv := fakedataplane.Start(t)
	c := dataplane.NewClient(srv.Socket)
	ctx := context.Background()
	st, err := c.PutActiveHealth(ctx, &dataplane.ActiveHealth{TTL: 90, Down: []dataplane.ActiveOrigin{
		{SiteID: "s1", OriginID: "o1"}, {SiteID: "s2", OriginID: "o-2"},
	}})
	if err != nil || st.Down != 2 {
		t.Fatalf("PutActiveHealth = %+v, %v", st, err)
	}
	got, puts := srv.Active()
	if puts != 1 || got.TTL != 90 || len(got.Down) != 2 || got.Down[1].OriginID != "o-2" {
		t.Fatalf("installed = %+v (%d puts)", got, puts)
	}
	// No origin down: an empty array, never null.
	b, _ := json.Marshal(dataplane.ActiveHealth{TTL: 90, Down: []dataplane.ActiveOrigin{}})
	if want := `{"ttl":90,"down":[]}`; string(b) != want {
		t.Fatalf("JSON = %s, want %s", b, want)
	}
	if st, err = c.PutActiveHealth(ctx, &dataplane.ActiveHealth{TTL: 90}); err != nil || st.Down != 0 {
		t.Fatalf("empty set = %+v, %v", st, err)
	}
	if got, _ = srv.Active(); got.Down == nil {
		t.Fatal("nil Down was sent as null")
	}
	_, err = c.PutActiveHealth(ctx, &dataplane.ActiveHealth{TTL: 0})
	var apiErr *dataplane.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 400 {
		t.Fatalf("ttl 0: %v", err)
	}
	if _, err = c.PutActiveHealth(ctx, nil); err == nil {
		t.Fatal("nil set accepted")
	}
	srv.Restart()
	if got, _ = srv.Active(); got != nil {
		t.Fatal("marks survived an nginx restart")
	}
}

func TestDrainLogsCarriesRequestID(t *testing.T) {
	srv := fakedataplane.Start(t)
	c := dataplane.NewClient(srv.Socket)
	srv.AddLogEntry(map[string]any{"site_id": "s1", "time": 1800000000, "path": "/", "status": 502, "request_id": "0123456789abcdef0123456789abcdef"})
	srv.AddLogEntry(map[string]any{"site_id": "s1", "time": 1800000001, "path": "/", "status": 200, "request_id": strings.Repeat("r", 200)})
	srv.AddLogEntry(map[string]any{"site_id": "s1", "time": 1800000002, "path": "/", "status": 200})
	logs, err := c.DrainLogs(context.Background())
	if err != nil || len(logs) != 3 {
		t.Fatalf("DrainLogs = %v, %v", logs, err)
	}
	if got := logs[0].GetRequestId(); got != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("request id = %q", got)
	}
	if got := logs[1].GetRequestId(); len(got) != 128 {
		t.Fatalf("request id not bounded to 128 bytes: %d", len(got))
	}
	if logs[2].GetRequestId() != "" {
		t.Fatalf("request id without one: %q", logs[2].GetRequestId())
	}
}
