// Package geoip serves operator-provided MMDBs locally. It never downloads data
// or sends visitor addresses outside the node.
package geoip

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

type Databases struct {
	mu        sync.RWMutex
	closed    bool
	City, ASN *maxminddb.Reader
}
type Result struct {
	Country     string `json:"country"`
	Subdivision string `json:"subdivision"`
	ASNum       uint   `json:"asnum"`
}

func Open(cityPath, asnPath string) (*Databases, error) {
	d := &Databases{}
	open := func(path, kind string) (*maxminddb.Reader, error) {
		if path == "" {
			return nil, nil
		}
		db, err := maxminddb.Open(path)
		if err != nil {
			return nil, err
		}
		if err = db.Verify(); err != nil {
			db.Close()
			return nil, err
		}
		if !strings.Contains(strings.ToLower(db.Metadata.DatabaseType), kind) {
			db.Close()
			return nil, fmt.Errorf("expected %s MMDB", kind)
		}
		return db, nil
	}
	var err error
	if d.City, err = open(cityPath, "city"); err != nil {
		return nil, err
	}
	if d.ASN, err = open(asnPath, "asn"); err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}
func (d *Databases) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	if d.City != nil {
		d.City.Close()
	}
	if d.ASN != nil {
		d.ASN.Close()
	}
}
func (d *Databases) Features() []string {
	var out []string
	if d.City != nil {
		out = append(out, "geoip-city-v1")
	}
	if d.ASN != nil {
		out = append(out, "geoip-asn-v1")
	}
	return out
}
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
		out.Country = record.Country.Code
		if len(record.Subdivisions) > 0 {
			out.Subdivision = record.Subdivisions[0].Code
			if out.Subdivision == "" {
				out.Subdivision = record.Subdivisions[0].Names["en"]
			}
		}
	}
	if d.ASN != nil {
		var record struct {
			Number uint `maxminddb:"autonomous_system_number"`
		}
		if err := d.ASN.Lookup(ip).Decode(&record); err != nil {
			return out, err
		}
		out.ASNum = record.Number
	}
	return out, nil
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
