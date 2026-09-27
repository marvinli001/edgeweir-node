package configir

import (
	"errors"
	"fmt"
	"regexp"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"google.golang.org/protobuf/proto"
)

func TestPublishedSiteCapacity(t *testing.T) {
	cfg := vectorConfig()
	template := cfg.Sites[0]
	cfg.Sites = nil
	for i := range MaxPublishedSites {
		site := proto.CloneOf(template)
		site.Id = fmt.Sprintf("site-%d", i)
		site.Domains = []*nodev1.Domain{{Name: fmt.Sprintf("site-%d.test", i)}}
		cfg.Sites = append(cfg.Sites, site)
	}
	plan, err := Build(cfg, Options{})
	if err != nil || len(plan.Sites) != MaxPublishedSites {
		t.Fatalf("supported site count: plan=%v err=%v", plan, err)
	}
	cfg.Sites = append(cfg.Sites, &nodev1.Site{Id: "one-more"})
	if _, err := Build(cfg, Options{}); !errors.Is(err, ErrRejected) {
		t.Fatalf("over-capacity configuration: %v", err)
	}
}

func TestRateLimitDictionaryNames(t *testing.T) {
	seen := map[string]bool{}
	validName := regexp.MustCompile(`^[a-z0-9_]+$`)
	for _, id := range []string{"a", "A", "a-b", "a_b", "ab"} {
		name, err := RateLimitDictName(id)
		if err != nil || !validName.MatchString(name) || seen[name] {
			t.Fatalf("dictionary name for %q: %q, %v", id, name, err)
		}
		seen[name] = true
	}
	name, err := RateLimitDictName("a")
	if err != nil || name != "edgeweir_rate_61" {
		t.Fatalf("Lua-compatible name: %q, %v", name, err)
	}
}

func TestRateLimitDictionaryNamespaceReserved(t *testing.T) {
	for _, name := range []string{DictLimits, DictPolicyLogs, RateLimitDictPrefix + "61", RateLimitDictPrefix + "future"} {
		plan, err := Build(&nodev1.NodeConfig{CacheZones: []*nodev1.CacheZone{{Name: name}, {Name: "images"}}}, Options{})
		if err != nil || len(plan.CacheZones) != 1 || plan.CacheZones[0].Name != "images" {
			t.Fatalf("reserved name %q: plan=%v err=%v", name, plan, err)
		}
	}
}
