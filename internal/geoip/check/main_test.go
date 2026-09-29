package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/testutil/geofixture"
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func TestCheck(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.mmdb")
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "ipinfo bundle_location_lite.mmdb", Description: map[string]string{"en": "Synthetic Edgeweir test fixture"}, RecordSize: 24, IPVersion: 6})
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"1.1.1.0/24", "8.8.8.0/24", "2001:4860::/32"} {
		_, network, _ := net.ParseCIDR(prefix)
		if err := tree.Insert(network, mmdbtype.Map{"country_code": mmdbtype.String("US"), "asn": mmdbtype.String("AS64512")}); err != nil {
			t.Fatal(err)
		}
	}
	file, err := os.Create(good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tree.WriteTo(file); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := check(good); err != nil {
		t.Fatal(err)
	}
	// The synthetic IPinfo fixture lacks the resolvers; a City MMDB is the wrong type.
	ipinfo, err := geofixture.WriteIPinfo(dir)
	if err != nil {
		t.Fatal(err)
	}
	city, _, err := geofixture.Write(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{ipinfo, city, filepath.Join(dir, "missing.mmdb")} {
		if err := check(path); err == nil {
			t.Errorf("accepted %s", path)
		}
	}
}
