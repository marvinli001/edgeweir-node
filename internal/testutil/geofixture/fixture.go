// Package geofixture creates synthetic MMDBs; it contains no third-party data.
package geofixture

import (
	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"net"
	"os"
	"path/filepath"
)

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
		tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: entry.typ, Description: map[string]string{"en": "Synthetic Edgeweir test fixture"}, RecordSize: 24, IPVersion: 6, IncludeReservedNetworks: true})
		if err != nil {
			return "", "", err
		}
		for _, prefix := range []string{"203.0.113.0/24", "2001:db8::/32", "172.28.0.0/16"} {
			_, network, _ := net.ParseCIDR(prefix)
			if err := tree.Insert(network, entry.data); err != nil {
				return "", "", err
			}
		}
		file, err := os.Create(entry.path)
		if err != nil {
			return "", "", err
		}
		_, err = tree.WriteTo(file)
		closeErr := file.Close()
		if err != nil {
			return "", "", err
		}
		if closeErr != nil {
			return "", "", closeErr
		}
	}
	return city, asn, nil
}
