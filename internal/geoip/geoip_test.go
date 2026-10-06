package geoip

import (
	"context"
	"github.com/marvinli001/edgeweir-node/internal/testutil/geofixture"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestLocalMMDB(t *testing.T) {
	city, asn, err := geofixture.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(Paths{City: city, ASN: asn})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got := db.Features(); !slices.Equal(got, []string{"geoip-country-v1", "geoip-city-v1", "geoip-subdivision-v1", "geoip-asn-v1"}) {
		t.Fatal(got)
	}
	for _, ip := range []string{"203.0.113.7", "::ffff:203.0.113.7", "2001:db8::7"} {
		got, err := db.Lookup(netip.MustParseAddr(ip))
		if err != nil {
			t.Fatal(err)
		}
		if got.Country != "NZ" || got.Subdivision != "AUK" || got.ASNum != 64512 || got.ASName != "Synthetic ASN 64512" {
			t.Fatalf("%s: %+v", ip, got)
		}
	}
	for _, test := range []struct {
		path   string
		status int
	}{{"/lookup?ip=203.0.113.7", 200}, {"/lookup?ip=127.1", 400}, {"/unknown", 404}} {
		rr := httptest.NewRecorder()
		db.Handler().ServeHTTP(rr, httptest.NewRequest("GET", test.path, nil))
		if rr.Code != test.status {
			t.Fatal(rr.Code)
		}
	}
	if wrong, err := Open(Paths{City: asn, ASN: city}); err == nil {
		wrong.Close()
		t.Fatal("accepted wrong database type")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socket := filepath.Join(t.TempDir(), "geo.sock")
	l, err := db.Serve(ctx, socket)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	res, err := client.Get("http://local/lookup?ip=203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	if other, err := db.Serve(ctx, socket); err == nil {
		other.Close()
		t.Fatal("replaced active socket")
	}
}

func TestIPinfoLite(t *testing.T) {
	dir := t.TempDir()
	city, asn, err := geofixture.Write(dir)
	if err != nil {
		t.Fatal(err)
	}
	ipinfo, err := geofixture.WriteIPinfo(dir)
	if err != nil {
		t.Fatal(err)
	}
	only, err := Open(Paths{IPinfo: ipinfo})
	if err != nil {
		t.Fatal(err)
	}
	defer only.Close()
	// geoip-city-v1 is what consoles gate country rules on; no subdivisions.
	if got := only.Features(); !slices.Equal(got, []string{"geoip-country-v1", "geoip-city-v1", "geoip-asn-v1"}) {
		t.Fatal(got)
	}
	if only.IPinfoBuilt().IsZero() {
		t.Fatal("missing IPinfo build time")
	}
	all, err := Open(Paths{IPinfo: ipinfo, City: city, ASN: asn})
	if err != nil {
		t.Fatal(err)
	}
	defer all.Close()
	for _, test := range []struct {
		db   *Databases
		ip   string
		want Result
	}{
		{only, "203.0.113.7", Result{Country: "NZ", ASNum: 64512, ASName: "Synthetic AS64512"}},
		{only, "::ffff:203.0.113.7", Result{Country: "NZ", ASNum: 64512, ASName: "Synthetic AS64512"}},
		{only, "2001:db8::7", Result{Country: "AU", ASNum: 64513, ASName: "Synthetic AS64513"}},
		{only, "172.28.1.1", Result{Country: "NZ", ASNum: 64513, ASName: "Synthetic AS64513"}},
		{only, "192.0.2.1", Result{}},
		// The City database adds the subdivision where it agrees on the country.
		{all, "203.0.113.7", Result{Country: "NZ", Subdivision: "AUK", ASNum: 64512, ASName: "Synthetic AS64512"}},
		{all, "2001:db8::7", Result{Country: "AU", ASNum: 64513, ASName: "Synthetic AS64513"}},
		// IPinfo answers the ASN and its name even where the ASN database differs.
		{all, "172.28.1.1", Result{Country: "NZ", Subdivision: "AUK", ASNum: 64513, ASName: "Synthetic AS64513"}},
		{all, "192.0.2.1", Result{}},
	} {
		got, err := test.db.Lookup(netip.MustParseAddr(test.ip))
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Errorf("%s: got %+v, want %+v", test.ip, got, test.want)
		}
	}
	for _, paths := range []Paths{{IPinfo: city}, {IPinfo: asn}, {City: ipinfo}, {ASN: ipinfo}} {
		if wrong, err := Open(paths); err == nil {
			wrong.Close()
			t.Fatalf("accepted wrong database type: %+v", paths)
		}
	}
}

func TestIPinfoFallsBackToOperatorDatabases(t *testing.T) {
	dir := t.TempDir()
	city, asn, err := geofixture.Write(dir)
	if err != nil {
		t.Fatal(err)
	}
	// An IPinfo database without these networks leaves them to City / ASN.
	empty := filepath.Join(dir, "empty.mmdb")
	if err := writeEmptyIPinfo(empty); err != nil {
		t.Fatal(err)
	}
	db, err := Open(Paths{IPinfo: empty, City: city, ASN: asn})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	got, err := db.Lookup(netip.MustParseAddr("172.28.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if want := (Result{Country: "NZ", Subdivision: "AUK", ASNum: 64512, ASName: "Synthetic ASN 64512"}); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestParseASN(t *testing.T) {
	for in, want := range map[string]uint{
		"AS15169": 15169, "AS4294967295": 4294967295, "AS0": 0,
		"": 0, "15169": 0, "as15169": 0, "AS": 0, "ASx": 0, "AS-1": 0, "AS4294967296": 0,
	} {
		if got := parseASN(in); got != want {
			t.Errorf("parseASN(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestResolveIPinfo(t *testing.T) {
	dir := t.TempDir()
	bundled := filepath.Join(dir, "ipinfo_lite.mmdb")
	missing := filepath.Join(dir, "missing.mmdb")
	if err := os.WriteFile(bundled, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		setting, bundled, want string
		optional               bool
	}{
		{"auto", bundled, bundled, true},
		{"auto", missing, "", false},
		{"off", bundled, "", false},
		{"", bundled, "", false},
		{"/srv/geo/ipinfo_lite.mmdb", bundled, "/srv/geo/ipinfo_lite.mmdb", false},
	} {
		got, optional, err := resolveIPinfo(test.setting, test.bundled)
		if err != nil || got != test.want || optional != test.optional {
			t.Errorf("resolveIPinfo(%q, %q) = %q, %v, %v; want %q, %v", test.setting, test.bundled, got, optional, err, test.want, test.optional)
		}
	}
}

func TestOptionalIPinfo(t *testing.T) {
	dir := t.TempDir()
	city, _, err := geofixture.Write(dir)
	if err != nil {
		t.Fatal(err)
	}
	// The bundled database is optional: a broken file leaves the node on its
	// operator databases instead of stopping it. An explicit path must load.
	broken := filepath.Join(dir, "ipinfo_lite.mmdb")
	if err := os.WriteFile(broken, []byte("not an mmdb"), 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := Open(Paths{IPinfo: broken, IPinfoOptional: true, City: city})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if db.IPinfo != nil || db.IPinfoErr == nil {
		t.Fatalf("IPinfo = %v, IPinfoErr = %v", db.IPinfo, db.IPinfoErr)
	}
	if got := db.Features(); !slices.Equal(got, []string{"geoip-country-v1", "geoip-city-v1", "geoip-subdivision-v1"}) {
		t.Fatal(got)
	}
	for _, wrongType := range []string{broken, city} {
		if other, err := Open(Paths{IPinfo: wrongType}); err == nil {
			other.Close()
			t.Fatalf("accepted %s as an explicit IPinfo database", wrongType)
		}
	}
}

func writeEmptyIPinfo(path string) error {
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "ipinfo bundle_location_lite.mmdb", Description: map[string]string{"en": "Synthetic Edgeweir test fixture"}, RecordSize: 24, IPVersion: 6, IncludeReservedNetworks: true})
	if err != nil {
		return err
	}
	_, network, _ := net.ParseCIDR("198.51.100.0/24")
	if err := tree.Insert(network, mmdbtype.Map{"country_code": mmdbtype.String("NZ"), "asn": mmdbtype.String("AS64512")}); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	if _, err := tree.WriteTo(file); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}
