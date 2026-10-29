package agent

import (
	"net/netip"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/geoip"
)

// nodeLocation is where the console's locate address is
// (ReportStatusRequest.location), from the node's GeoIP databases; nil
// without databases or before a response named an address. The lookup is
// kept until the address changes.
func (a *Agent) nodeLocation() *nodev1.NodeLocation {
	a.mu.Lock()
	db, address, cached := a.geo, a.locateAddress, a.located
	a.mu.Unlock()
	if db == nil || address == "" {
		return nil
	}
	if cached != nil && cached.GetAddress() == address {
		return cached
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return nil
	}
	place, err := db.Locate(ip)
	if err != nil {
		a.log.Debug("cannot locate the node's address", "address", address, "err", err)
		return nil
	}
	located := locationOf(address, place)
	a.mu.Lock()
	a.located = located
	a.mu.Unlock()
	return located
}

func locationOf(address string, place geoip.Place) *nodev1.NodeLocation {
	return &nodev1.NodeLocation{
		Address:     address,
		Country:     place.Country,
		Subdivision: place.Subdivision,
		Latitude:    place.Lat,
		Longitude:   place.Lng,
	}
}
