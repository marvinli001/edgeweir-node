package agent_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/geoip"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
	"github.com/marvinli001/edgeweir-node/internal/testutil/geofixture"
)

// Nodes installed from packages have no GeoIP database (only the node
// image bundles IPinfo Lite). The agent then serves no GeoIP socket, and
// nginx.conf must not name one: every soft lookup of a worker would try to
// connect and log a [crit] line.
func TestAgentNamesTheGeoIPSocketOnlyWhenItServesOne(t *testing.T) {
	city, asn, err := geofixture.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		paths  geoip.Paths
		served bool
	}{
		{"no database", geoip.Paths{}, false},
		{"City and ASN databases", geoip.Paths{City: city, ASN: asn}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			h := &harness{t: t, stateDir: filepath.Join(root, "state"), root: root}
			dp := fakedataplane.Start(t)
			eng := newFakeEngine()
			cfg := h.agentConfig(dp.Socket)
			cfg.GeoIP = tc.paths
			stop := startAgent(t, cfg, eng, dataplane.NewClient(dp.Socket))
			eventually(t, "bootstrap configuration loaded", func() bool {
				_, reloads, _ := eng.counts()
				return reloads >= 1
			})
			_, _, conf := eng.counts()
			socket := dp.Socket + ".geo"
			want := `geoip_socket = "",`
			if tc.served {
				want = `geoip_socket = "` + socket + `",`
			}
			if !strings.Contains(conf, want) {
				t.Errorf("nginx.conf lacks %s", want)
			}
			if !tc.served && strings.Contains(conf, socket) {
				t.Errorf("nginx.conf names %s, which the agent does not serve", socket)
			}
			fi, err := os.Stat(socket)
			if served := err == nil && fi.Mode()&os.ModeSocket != 0; served != tc.served {
				t.Errorf("GeoIP socket served = %v, want %v (stat: %v)", served, tc.served, err)
			}
			stop()
		})
	}
}
