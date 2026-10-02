package dataplane_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

func TestL4FromPlan(t *testing.T) {
	if dataplane.L4FromPlan(configir.Bootstrap(80)) != nil {
		t.Fatal("a plan without applications has a layer-4 table")
	}
	plan := configir.Bootstrap(80)
	plan.Revision, plan.ContentHash = 12, "abc"
	plan.IPLists = []*nodev1.IpList{{Id: "l1", Kind: "allow", Entries: []string{"192.0.2.0/24"}}, {Id: "l2", Kind: "block"}, {Id: "unused", Kind: "block"}}
	plan.L4Apps = []configir.L4App{{
		ID: "app-a", Protocol: configir.L4TCP, Port: 9000, ProxyProtocolVersion: 2,
		Origins:  []configir.L4Origin{{ID: "o1", Address: "origin.test", Port: 7000, Weight: 1}, {ID: "o2", Address: "127.0.0.1", Port: 7000, Weight: 1, Forbidden: true}},
		MaxFails: 3, FailTimeout: 30, ConnectTimeoutMS: 5000, IdleTimeout: 600, AllowLists: []string{"l1"}, BlockLists: []string{"l2"},
	}}
	table := dataplane.L4FromPlan(plan)
	b, err := json.Marshal(table)
	if err != nil {
		t.Fatal(err)
	}
	// The JSON edgeweir.l4 reads: lists the applications use (never
	// null), the allow list as an array, revision as a string.
	want := `{"revision":"12","content_hash":"abc","apps":[{"id":"app-a","protocol":"tcp","port":9000,"proxy_protocol_version":2,` +
		`"origins":[{"id":"o1","address":"origin.test","port":7000,"weight":1},{"id":"o2","address":"127.0.0.1","port":7000,"weight":1,"forbidden":true}],` +
		`"max_fails":3,"fail_timeout":30,"connect_timeout_ms":5000,"idle_timeout":600,"allow_lists":["l1"],"block_lists":["l2"]}],` +
		`"ip_lists":[{"id":"l1","entries":["192.0.2.0/24"]},{"id":"l2","entries":[]}],"origin_allowed_cidrs":[]}`
	if string(b) != want {
		t.Fatalf("layer-4 table JSON\n got %s\nwant %s", b, want)
	}
}

func TestL4ClientAgainstFakeSocket(t *testing.T) {
	srv := fakedataplane.Start(t)
	c := dataplane.NewClient(srv.Socket)
	ctx := context.Background()
	st, err := c.L4Status(ctx)
	if err != nil || st.Version != 0 {
		t.Fatalf("fresh status %+v %v", st, err)
	}
	plan := configir.Bootstrap(80)
	plan.Revision, plan.ContentHash = 3, "h"
	plan.L4Apps = []configir.L4App{{ID: "app-a", Protocol: configir.L4UDP, Port: 9000, Origins: []configir.L4Origin{{ID: "o", Address: "a.test", Port: 1, Weight: 1}}}}
	table := dataplane.L4FromPlan(plan)
	st, err = c.PutL4(ctx, table)
	if err != nil || !st.InSync(table) || st.Apps != 1 {
		t.Fatalf("after put %+v %v", st, err)
	}
	other := *table
	other.ContentHash = "x"
	if st.InSync(&other) {
		t.Fatal("in sync with another table")
	}
	if stats, err := c.DrainL4Stats(ctx, false); err != nil || len(stats) != 0 {
		t.Fatalf("empty drain %v %v", stats, err)
	}
	srv.AddL4Stats(dataplane.L4MinuteStats{Minute: 60, AppID: "app-a", Connections: 2, BytesSent: 9})
	stats, err := c.DrainL4Stats(ctx, false)
	if err != nil || len(stats) != 1 || stats[0].Connections != 2 || stats[0].BytesSent != 9 {
		t.Fatalf("drain %v %v", stats, err)
	}
	if _, err := c.PutL4(ctx, nil); err == nil {
		t.Fatal("nil table sent")
	}
	srv.FailNextL4(1)
	if _, err := c.PutL4(ctx, table); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("injected failure: %v", err)
	}
}
