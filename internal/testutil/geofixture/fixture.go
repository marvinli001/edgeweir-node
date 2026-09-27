// Package geofixture creates synthetic MMDBs; it contains no third-party data.
package geofixture

import (
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"net"
	"os"
	"path/filepath"
)

// Prefixes are the networks every synthetic database covers.
var Prefixes = []string{"203.0.113.0/24", "2001:db8::/32", "172.28.0.0/16"}

func Write(dir string) (string, string, error) {
	city := filepath.Join(dir, "city.mmdb")
	asn := filepath.Join(dir, "asn.mmdb")
	for _, entry := range []struct {
		path, typ string
		data      mmdbtype.Map
	}{
		{city, "Synthetic-City", mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String("NZ")}, "subdivisions": mmdbtype.Slice{mmdbtype.Map{"iso_code": mmdbtype.String("AUK")}}}},
		{asn, "Synthetic-ASN", mmdbtype.Map{"autonomous_system_number": mmdbtype.Uint32(64512)}},
	} {
		if err := write(entry.path, entry.typ, map[string]mmdbtype.Map{"": entry.data}); err != nil {
			return "", "", err
		}
	}
	return city, asn, nil
}

// WriteIPinfo writes ipinfo_lite.mmdb in the IPinfo Lite schema. Against Write
// it agrees on 203.0.113.0/24 (NZ, AS64512), keeps the country but not the ASN
// on 172.28.0.0/16 (NZ, AS64513) and disagrees on 2001:db8::/32 (AU, AS64513),
// so tests can tell which database answered.
func WriteIPinfo(dir string) (string, error) {
	path := filepath.Join(dir, "ipinfo_lite.mmdb")
	record := func(code, country, asn string) mmdbtype.Map {
		return mmdbtype.Map{
			"asn": mmdbtype.String(asn), "as_name": mmdbtype.String("Synthetic " + asn), "as_domain": mmdbtype.String("example.net"),
			"country_code": mmdbtype.String(code), "country": mmdbtype.String(country),
			"continent_code": mmdbtype.String("OC"), "continent": mmdbtype.String("Oceania"),
		}
	}
	return path, write(path, "ipinfo bundle_location_lite.mmdb", map[string]mmdbtype.Map{
		"203.0.113.0/24": record("NZ", "New Zealand", "AS64512"),
		"172.28.0.0/16":  record("NZ", "New Zealand", "AS64513"),
		"2001:db8::/32":  record("AU", "Australia", "AS64513"),
	})
}

// write stores data[prefix] for each of Prefixes, falling back to data[""].
func write(path, typ string, data map[string]mmdbtype.Map) error {
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: typ, Description: map[string]string{"en": "Synthetic Edgeweir test fixture"}, RecordSize: 24, IPVersion: 6, IncludeReservedNetworks: true})
	if err != nil {
		return err
	}
	for _, prefix := range Prefixes {
		_, network, _ := net.ParseCIDR(prefix)
		value, ok := data[prefix]
		if !ok {
			value = data[""]
		}
		if err := tree.Insert(network, value); err != nil {
			return err
		}
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	_, err = tree.WriteTo(file)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}
