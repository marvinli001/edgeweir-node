package render

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func TestRateLimitPartitionBudget(t *testing.T) {
	for _, count := range []int{0, 1, 2, 3, configir.MaxPublishedSites} {
		sites := make([]configir.Site, count)
		for i := range sites {
			sites[i].ID = fmt.Sprintf("site-%d", i)
		}
		dicts, err := sharedDicts(params().WithDefaults(), sites)
		if err != nil {
			t.Fatal(err)
		}
		total, partitions := 0, 0
		seen := map[string]bool{}
		for _, dict := range dicts {
			if !strings.HasPrefix(dict.Name, configir.RateLimitDictPrefix) {
				continue
			}
			if seen[dict.Name] || dict.SizeKB != configir.RateLimitSiteKB {
				t.Fatalf("invalid partition: %+v", dict)
			}
			seen[dict.Name] = true
			partitions++
			total += dict.SizeKB
		}
		if partitions != count || total != count*configir.RateLimitSiteKB || total > configir.RateLimitBudgetKB {
			t.Fatalf("%d sites: %d partitions, %d KiB", count, partitions, total)
		}
	}
}

func TestRateLimitRuleUpdatesRemainHot(t *testing.T) {
	plan := configir.Bootstrap(80)
	plan.Sites = []configir.Site{{ID: "a"}, {ID: "b"}}
	before, err := Render(params(), plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.Sites[0].Rules = []*nodev1.EdgeRule{{Id: "requests", Phase: "ratelimit", Action: &nodev1.RuleAction{Kind: "rate_limit", Key: "ip.src", WindowSeconds: 60, Limit: 10}}}
	plan.IPLists = []*nodev1.IpList{{Id: "office", Kind: "collection", Entries: []string{"192.0.2.0/24"}}}
	plan.Sites[0], plan.Sites[1] = plan.Sites[1], plan.Sites[0]
	after, err := Render(params(), plan)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("rule/list changes or site ordering changed the rendered partitions: %v", err)
	}
	for _, want := range []string{"lua_shared_dict edgeweir_rate_61 256k;", "lua_shared_dict edgeweir_rate_62 256k;", "lua_shared_dict edgeweir_policy_logs 1m;"} {
		if !strings.Contains(string(after), want) {
			t.Fatalf("configuration lacks %q", want)
		}
	}
}

func TestRateLimitMembershipKeepsExistingPartitionSizes(t *testing.T) {
	plan := configir.Bootstrap(80)
	plan.Sites = []configir.Site{{ID: "a"}, {ID: "b"}}
	before, err := Render(params(), plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.Sites = append(plan.Sites, configir.Site{ID: "c"})
	after, err := Render(params(), plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"edgeweir_rate_61", "edgeweir_rate_62"} {
		declaration := "lua_shared_dict " + name + " 256k;"
		if !strings.Contains(string(before), declaration) || !strings.Contains(string(after), declaration) {
			t.Fatalf("adding a site changed existing partition %s", name)
		}
	}
	if strings.Contains(string(before), "edgeweir_rate_63") || !strings.Contains(string(after), "lua_shared_dict edgeweir_rate_63 256k;") {
		t.Fatal("new site did not receive its own fixed partition")
	}
}

func TestRenderPartitionAdmission(t *testing.T) {
	plan := configir.Bootstrap(80)
	plan.Sites = make([]configir.Site, configir.MaxPublishedSites+1)
	if _, err := Render(params(), plan); err == nil {
		t.Fatal("accepted too many partitions")
	}
	plan.Sites = []configir.Site{{ID: "a"}, {ID: "a"}}
	if _, err := Render(params(), plan); err == nil {
		t.Fatal("accepted duplicate partition owners")
	}
	plan.Sites = nil
	plan.CacheZones[0].Name = configir.RateLimitDictPrefix + "61"
	if _, err := Render(params(), plan); err == nil {
		t.Fatal("accepted a cache zone in the reserved counter namespace")
	}
}

func TestRenderHTTP3CustomListener(t *testing.T) {
	plan := configir.Bootstrap(80)
	plan.Listeners = []configir.Listener{{Port: 8443, TLS: true, HTTP3: true}}
	conf, err := Render(params(), plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"listen 8443 default_server ssl;", "listen 8443 quic reuseport default_server;"} {
		if !strings.Contains(string(conf), want) {
			t.Fatalf("configuration lacks %q", want)
		}
	}
}
