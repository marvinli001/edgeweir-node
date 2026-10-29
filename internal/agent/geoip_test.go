package agent_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	"github.com/marvinli001/edgeweir-node/internal/geoip"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
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

// The console names the address to place the node by on its map; the node
// answers with where its GeoIP databases put it in the next heartbeat.
func TestAgentReportsWhereTheLocateAddressIs(t *testing.T) {
	city, asn, err := geofixture.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-7", ClusterID: "cl-1", NodeName: "edge-7", ReportInterval: 1})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	console.Publish(baseConfig())
	console.SetLocateAddress("203.0.113.7")
	root := t.TempDir()
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}
	dp := fakedataplane.Start(t)
	cfg := h.agentConfig(dp.Socket)
	cfg.GeoIP = geoip.Paths{City: city, ASN: asn}
	startAgent(t, cfg, newFakeEngine(), dataplane.NewClient(dp.Socket))
	console.AddToken("secret-token")
	if _, err := enroll.Run(context.Background(), enroll.Options{
		ServerURL: srv.URL, Token: "secret-token", CASHA256: console.CA.Pin(),
		StateDir: h.stateDir, Logger: testLogger(t),
	}); err != nil {
		t.Fatal(err)
	}
	located := func(address string) func() bool {
		return func() bool {
			l := console.LastStatus().GetLocation()
			return l.GetAddress() == address
		}
	}
	eventually(t, "location reported", located("203.0.113.7"))
	l := console.LastStatus().GetLocation()
	if l.GetCountry() != "NZ" || l.GetSubdivision() != "AUK" || l.GetLatitude() != -36.85 || l.GetLongitude() != 174.76 {
		t.Fatalf("location = %v", l)
	}
	// A new address is looked up again; one no database knows has no country.
	console.SetLocateAddress("192.0.2.1")
	eventually(t, "new location reported", located("192.0.2.1"))
	if l := console.LastStatus().GetLocation(); l.GetCountry() != "" || l.Latitude != nil {
		t.Fatalf("location = %v", l)
	}
}
