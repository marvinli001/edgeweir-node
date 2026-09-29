// Command check fails when the agent would not serve an IPinfo Lite MMDB. The
// image build runs it on the downloaded database, so a format change breaks
// the build instead of the nodes.
package main

import (
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/geoip"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: check IPINFO_LITE_MMDB")
		os.Exit(2)
	}
	if err := check(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "check:", err)
		os.Exit(1)
	}
}

func check(path string) error {
	db, err := geoip.Open(geoip.Paths{IPinfo: path})
	if err != nil {
		return err
	}
	defer db.Close()
	// Long-lived anycast resolvers that every real IPinfo Lite build covers:
	// an empty answer means the record layout changed.
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "2001:4860:4860::8888"} {
		r, err := db.Lookup(netip.MustParseAddr(ip))
		if err != nil {
			return err
		}
		if r.Country == "" || r.ASNum == 0 {
			return fmt.Errorf("%s: no country or ASN in %s", ip, path)
		}
	}
	fmt.Printf("IPinfo Lite database accepted (built %s)\n", db.IPinfoBuilt().Format(time.DateOnly))
	return nil
}
