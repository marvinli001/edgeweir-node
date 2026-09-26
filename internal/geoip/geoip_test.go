package geoip

import (
	"context"
	"github.com/marvinli001/edgeweir-node/internal/testutil/geofixture"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalMMDB(t *testing.T) {
	city, asn, err := geofixture.Write(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := Open(city, asn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if len(db.Features()) != 2 {
		t.Fatal(db.Features())
	}
	for _, ip := range []string{"203.0.113.7", "::ffff:203.0.113.7", "2001:db8::7"} {
		got, err := db.Lookup(netip.MustParseAddr(ip))
		if err != nil {
			t.Fatal(err)
		}
		if got.Country != "NZ" || got.Subdivision != "AUK" || got.ASNum != 64512 {
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
	if wrong, err := Open(asn, city); err == nil {
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
