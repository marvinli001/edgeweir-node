// Package geoip serves local MMDBs: the IPinfo Lite database bundled into the
// release container image at build time, plus operator-provided City / ASN
// databases. It never downloads data or sends visitor addresses outside the node.
package geoip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

// BundledIPinfoPath is where the release container image installs the IPinfo
// Lite database downloaded when it was built. Packages do not ship one; they
// need an explicit --geoip-ipinfo path.
const BundledIPinfoPath = "/usr/share/edgeweir-node/geoip/ipinfo_lite.mmdb"

type Databases struct {
	mu                sync.RWMutex
	closed            bool
	IPinfo, City, ASN *maxminddb.Reader
	// IPinfoErr is why an optional IPinfo database was skipped.
	IPinfoErr error
}
type Result struct {
	Country     string `json:"country"`
	Subdivision string `json:"subdivision"`
	ASNum       uint   `json:"asnum"`
	// ASName (ip.geoip.as_name, rules-v3) is the name of ASNum from the same
	// database: IPinfo Lite's as_name, an ASN MMDB's
	// autonomous_system_organization.
	ASName string `json:"as_name"`
}

// Paths selects the databases to load; an empty path leaves that source off.
type Paths struct {
	// IPinfo is an IPinfo Lite MMDB (country and ASN). When IPinfoOptional is
	// set (the bundled database), a file that fails to load is skipped and
	// recorded in Databases.IPinfoErr instead of failing Open.
	IPinfo         string
	IPinfoOptional bool
	// City is a City MMDB (country and subdivision), ASN an ASN MMDB.
	City, ASN string
}

// ResolveIPinfo turns the --geoip-ipinfo setting into Paths.IPinfo and
// Paths.IPinfoOptional: "auto" picks the bundled database when the build
// included one (optional), "off" (or empty) disables IPinfo, anything else is
// an explicit path that must load.
func ResolveIPinfo(setting string) (path string, optional bool, err error) {
	return resolveIPinfo(setting, BundledIPinfoPath)
}

func resolveIPinfo(setting, bundled string) (string, bool, error) {
	switch setting {
	case "", "off":
		return "", false, nil
	case "auto":
		if _, err := os.Stat(bundled); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return "", false, nil
			}
			return "", false, err
		}
		return bundled, true, nil
	}
	return setting, false, nil
}

func Open(p Paths) (*Databases, error) {
	d := &Databases{}
	open := func(path, name string, accepts func(databaseType string) bool) (*maxminddb.Reader, error) {
		if path == "" {
			return nil, nil
		}
		db, err := maxminddb.Open(path)
		if err != nil {
			return nil, err
		}
		if err = db.Verify(); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if !accepts(strings.ToLower(db.Metadata.DatabaseType)) {
			db.Close()
			return nil, fmt.Errorf("%s: expected %s MMDB, got %q", path, name, db.Metadata.DatabaseType)
		}
		return db, nil
	}
	var err error
	if d.IPinfo, err = open(p.IPinfo, "IPinfo Lite", func(t string) bool {
		return strings.Contains(t, "ipinfo") && strings.Contains(t, "lite")
	}); err != nil {
		if !p.IPinfoOptional {
			return nil, err
		}
		d.IPinfoErr = err
	}
	if d.City, err = open(p.City, "City", func(t string) bool { return strings.Contains(t, "city") }); err != nil {
		d.Close()
		return nil, err
	}
	if d.ASN, err = open(p.ASN, "ASN", func(t string) bool { return strings.Contains(t, "asn") }); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}
func (d *Databases) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	for _, db := range []*maxminddb.Reader{d.IPinfo, d.City, d.ASN} {
		if db != nil {
			db.Close()
		}
	}
}

// Features reports what the loaded databases can answer. Consoles gate
// country (and subdivision) rules on geoip-city-v1, so it keeps its name and
// now means country data from IPinfo or a City MMDB; geoip-country-v1 tells
// them that subdivisions are reported separately as geoip-subdivision-v1
// (City only). geoip-asn-v1 comes from IPinfo or an ASN MMDB.
func (d *Databases) Features() []string {
	var out []string
	if d.IPinfo != nil || d.City != nil {
		out = append(out, "geoip-country-v1", "geoip-city-v1")
	}
	if d.City != nil {
		out = append(out, "geoip-subdivision-v1")
	}
	if d.IPinfo != nil || d.ASN != nil {
		out = append(out, "geoip-asn-v1")
	}
	return out
}

// IPinfoBuilt is the build time of the loaded IPinfo database (zero if none).
func (d *Databases) IPinfoBuilt() time.Time {
	if d.IPinfo == nil {
		return time.Time{}
	}
	return time.Unix(int64(d.IPinfo.Metadata.BuildEpoch), 0).UTC()
}

// Lookup takes country and ASN from IPinfo when it has a record and falls back
// to the City / ASN databases. A subdivision only comes from the City database
// and only when that database agrees on the country; the AS name comes with
// the ASN from the database that answered it.
func (d *Databases) Lookup(ip netip.Addr) (Result, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	var out Result
	if d.closed {
		return out, fmt.Errorf("database closed")
	}
	if !ip.IsValid() {
		return out, fmt.Errorf("invalid IP")
	}
	ip = ip.Unmap()
	if d.IPinfo != nil {
		var record struct {
			Country string `maxminddb:"country_code"`
			ASN     string `maxminddb:"asn"`
			ASName  string `maxminddb:"as_name"`
		}
		if err := d.IPinfo.Lookup(ip).Decode(&record); err != nil {
			return out, err
		}
		out.Country = record.Country
		out.ASNum = parseASN(record.ASN)
		if out.ASNum != 0 {
			out.ASName = record.ASName
		}
	}
	if d.City != nil {
		var record struct {
			Country struct {
				Code string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
			Subdivisions []struct {
				Code  string            `maxminddb:"iso_code"`
				Names map[string]string `maxminddb:"names"`
			} `maxminddb:"subdivisions"`
		}
		if err := d.City.Lookup(ip).Decode(&record); err != nil {
			return out, err
		}
		if out.Country == "" {
			out.Country = record.Country.Code
		}
		if record.Country.Code == out.Country && len(record.Subdivisions) > 0 {
			out.Subdivision = record.Subdivisions[0].Code
			if out.Subdivision == "" {
				out.Subdivision = record.Subdivisions[0].Names["en"]
			}
		}
	}
	if d.ASN != nil && out.ASNum == 0 {
		var record struct {
			Number       uint   `maxminddb:"autonomous_system_number"`
			Organization string `maxminddb:"autonomous_system_organization"`
		}
		if err := d.ASN.Lookup(ip).Decode(&record); err != nil {
			return out, err
		}
		out.ASNum, out.ASName = record.Number, record.Organization
	}
	return out, nil
}

// parseASN reads IPinfo's "AS15169" form; anything else counts as no record.
func parseASN(s string) uint {
	digits, ok := strings.CutPrefix(s, "AS")
	if !ok {
		return 0
	}
	n, err := strconv.ParseUint(digits, 10, 32)
	if err != nil {
		return 0
	}
	return uint(n)
}
func (d *Databases) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/lookup" {
			http.Error(w, "not found", 404)
			return
		}
		ip, err := netip.ParseAddr(r.URL.Query().Get("ip"))
		if err != nil {
			http.Error(w, "invalid IP", 400)
			return
		}
		result, err := d.Lookup(ip)
		if err != nil {
			http.Error(w, "database unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
}

// Serve starts a protected local listener. The caller owns the returned listener
// and must close it before closing the MMDB readers.
func (d *Databases) Serve(ctx context.Context, path string) (net.Listener, error) {
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("GeoIP path is not a socket")
		}
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err == nil {
			conn.Close()
			return nil, fmt.Errorf("GeoIP socket in use")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		l.Close()
		return nil, err
	}
	server := &http.Server{Handler: d.Handler(), ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
	go func() { <-ctx.Done(); _ = server.Close() }()
	go func() { _ = server.Serve(l) }()
	return l, nil
}
