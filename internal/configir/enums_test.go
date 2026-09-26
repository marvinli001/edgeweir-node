package configir

import (
	"errors"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func TestRejectUnknownEnums(t *testing.T) {
	tests := map[string]*nodev1.NodeConfig{
		"listener":      {Listeners: []*nodev1.Listener{{Port: 443, Protocol: 127}}},
		"load balance":  {Sites: []*nodev1.Site{{Id: "site", OriginPool: &nodev1.OriginPool{Policy: 127}}}},
		"origin scheme": {Sites: []*nodev1.Site{{Id: "site", OriginPool: &nodev1.OriginPool{Origins: []*nodev1.Origin{{Id: "origin", Scheme: 127}}}}}},
		"cache action":  {Sites: []*nodev1.Site{{Id: "site", CacheRules: []*nodev1.CacheRule{{Id: "rule", Action: 127}}}}},
		"cache control": {Sites: []*nodev1.Site{{Id: "site", CacheRules: []*nodev1.CacheRule{{Id: "rule", OriginCacheControl: 127}}}}},
		"query mode":    {Sites: []*nodev1.Site{{Id: "site", CacheKey: &nodev1.CacheKeyPolicy{Query: 127}}}},
	}
	for name, config := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Build(config, Options{}); !errors.Is(err, ErrRejected) {
				t.Fatalf("unknown semantics must reject the entire config, got %v", err)
			}
		})
	}
}
