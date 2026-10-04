package healthcheck

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/pki/pkitest"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeclock"
	"github.com/marvinli001/edgeweir-node/internal/version"
)

type resolverFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

type dialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// to dials addr whatever address the probe asks for, recording the asked
// addresses.
func to(addr string, asked *[]string, mu *sync.Mutex) dialerFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		*asked = append(*asked, address)
		mu.Unlock()
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
}

func refuse(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
}

var baseCheck = configir.ActiveHealthCheck{
	Path: "/healthz?deep=1", Method: "GET", ExpectedStatusMin: 200, ExpectedStatusMax: 399,
	Interval: 10 * time.Second, Timeout: 2 * time.Second, HealthyThreshold: 2, UnhealthyThreshold: 2,
}

func origin(id, address string, port uint32) configir.Origin {
	return configir.Origin{ID: id, Scheme: configir.SchemeHTTP, Address: address, Port: port, Weight: 1}
}

// site returns a site with the active check c (nil: none) over origins.
func site(id string, c *configir.ActiveHealthCheck, origins ...configir.Origin) configir.Site {
	return configir.Site{ID: id, TLSVerify: true, Origins: origins, ActiveHealthCheck: c, ActiveHealth: c != nil}
}

func checkWith(f func(*configir.ActiveHealthCheck)) *configir.ActiveHealthCheck {
	c := baseCheck
	if f != nil {
		f(&c)
	}
	return &c
}

// onlySpec returns the one probe spec of plan.
func onlySpec(t *testing.T, plan *configir.Plan) spec {
	t.Helper()
	all := specs(plan)
	if len(all) != 1 {
		t.Fatalf("specs = %+v", all)
	}
	for _, sp := range all {
		return sp
	}
	panic("unreachable")
}

func policy(cidrs ...string) configir.AddressPolicy {
	p, _, _ := configir.NewAddressPolicy(cidrs)
	return p
}

// TestStateThresholds: an origin starts healthy, turns unhealthy after
// unhealthy_threshold consecutive failures and healthy after
// healthy_threshold consecutive successes; the last failure is kept.
func TestStateThresholds(t *testing.T) {
	s := state{healthy: true}
	now := time.Unix(1_800_000_000, 0)
	fail := failure(CodeUpstreamStatus, map[string]string{"status": "503"}, "HTTP 503")
	ok := result{ok: true}
	// Both thresholds are 2.
	steps := []struct {
		r        result
		changed  bool
		healthy  bool
		failures uint32
	}{
		{fail, false, true, 1},
		{ok, false, true, 0}, // a success resets the failures
		{fail, false, true, 1},
		{fail, true, false, 2}, // the second failure in a row
		{fail, false, false, 3},
		{ok, false, false, 0}, // 1 of 2 successes
		{fail, false, false, 1},
		{ok, false, false, 0},
		{ok, true, true, 0}, // the second success in a row
		{ok, false, true, 0},
	}
	for i, st := range steps {
		now = now.Add(time.Second)
		changed := s.record(st.r, now, 2, 2)
		if changed != st.changed || s.healthy != st.healthy || s.failures != st.failures {
			t.Fatalf("step %d: changed %v healthy %v failures %d, want %v %v %d", i, changed, s.healthy, s.failures, st.changed, st.healthy, st.failures)
		}
	}
	if s.lastCode != CodeUpstreamStatus || s.lastError != "HTTP 503" || s.lastParams["status"] != "503" ||
		!s.lastFailureAt.Equal(time.Unix(1_800_000_007, 0)) {
		t.Fatalf("last failure = %+v", s)
	}
	// Threshold 1: one result flips the state.
	s = state{healthy: true}
	if !s.record(fail, now, 1, 1) || s.healthy || !s.record(ok, now, 1, 1) || !s.healthy {
		t.Fatal("thresholds of 1")
	}
}

// TestSpecsSkipS3AndForbiddenOrigins: only origins of sites with an active
// check are probed, S3 origins and refused ones never; Host and SNI follow
// the origin's settings.
func TestSpecsSkipS3AndForbiddenOrigins(t *testing.T) {
	s3 := origin("s3", "bucket.example.com", 443)
	s3.S3 = &configir.S3Auth{Region: "us-east-1", CredentialID: "c"}
	forbidden := origin("bad", "10.0.0.1", 80)
	forbidden.Forbidden = true
	tlsOrigin := origin("tls", "2001:db8::1", 8443)
	tlsOrigin.Scheme = configir.SchemeHTTPS
	withHost := origin("hh", "origin.example.com", 8080)
	withHost.HostHeader = "www.Example.com:8080"
	withHost.Scheme = configir.SchemeHTTPS
	withSNI := origin("sni", "origin.example.com", 443)
	withSNI.Scheme, withSNI.HostHeader, withSNI.SNI = configir.SchemeHTTPS, "www.example.com", "sni.example.com"
	insecure := site("site-c", &baseCheck, origin("o", "c.example.com", 80))
	insecure.TLSVerify = false
	plan := &configir.Plan{Sites: []configir.Site{
		site("site-a", &baseCheck, origin("plain", "origin.example.com", 80), s3, forbidden, tlsOrigin, withHost, withSNI),
		site("site-b", nil, origin("o", "b.example.com", 80)),
		site("site-h", checkWith(func(c *configir.ActiveHealthCheck) { c.Host = "health.example.com" }), origin("o", "h.example.com", 80)),
		insecure,
	}}
	got := specs(plan)
	want := map[Key]struct{ host, sni string }{
		{"site-a", "plain"}: {"origin.example.com", "origin.example.com"},
		{"site-a", "tls"}:   {"[2001:db8::1]:8443", "2001:db8::1"},
		{"site-a", "hh"}:    {"www.Example.com:8080", "www.example.com"},
		{"site-a", "sni"}:   {"www.example.com", "sni.example.com"},
		{"site-h", "o"}:     {"health.example.com", "h.example.com"},
		{"site-c", "o"}:     {"c.example.com", "c.example.com"},
	}
	if len(got) != len(want) {
		t.Fatalf("specs = %+v", got)
	}
	for k, w := range want {
		sp, ok := got[k]
		if !ok || sp.host != w.host || sp.sni != w.sni {
			t.Errorf("%v: %+v, want host %q sni %q", k, sp, w.host, w.sni)
		}
	}
	if !got[Key{"site-c", "o"}].insecure || got[Key{"site-a", "plain"}].insecure {
		t.Error("skip_tls_verify not carried")
	}
	if hostOf("10.1.2.3", 443, configir.SchemeHTTPS) != "10.1.2.3" || hostOf("10.1.2.3", 80, configir.SchemeHTTPS) != "10.1.2.3:80" {
		t.Error("default ports")
	}
}

// TestProbeAddressPolicy: names resolve with the resolver, special-purpose
// answers outside the allow list are dropped, the probe connects to a
// checked address (the next one when a connection fails), and refusals
// carry dns_failed or address_forbidden.
func TestProbeAddressPolicy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	answers := map[string][]netip.Addr{
		"mixed.test":  {netip.MustParseAddr("10.0.0.5"), netip.MustParseAddr("93.184.216.34")},
		"inside.test": {netip.MustParseAddr("10.0.0.6"), netip.MustParseAddr("::ffff:192.168.1.1")},
		"two.test":    {netip.MustParseAddr("93.184.216.1"), netip.MustParseAddr("93.184.216.2")},
	}
	v6 := map[string][]netip.Addr{"v6only.test": {netip.MustParseAddr("2606:2800:220:1::1")}}
	var lookups []string
	resolver := resolverFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
		lookups = append(lookups, network+" "+host)
		src := answers
		if network == "ip6" {
			src = v6
		}
		if a, ok := src[host]; ok {
			return a, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	})
	var mu sync.Mutex
	var asked []string
	working := to(srv.Listener.Addr().String(), &asked, &mu)
	dialer := dialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "93.184.216.1:80" {
			mu.Lock()
			asked = append(asked, address)
			mu.Unlock()
			return refuse(ctx, network, address)
		}
		return working(ctx, network, address)
	})
	c := New(Options{Resolver: resolver, Dialer: dialer})
	defer c.Close()
	probe := func(address string, ipv6 bool, allowed ...string) result {
		c.opts.IPv6 = ipv6
		asked, lookups = nil, nil
		return c.probe(context.Background(), onlySpec(t, &configir.Plan{Sites: []configir.Site{site("s", &baseCheck, origin("o", address, 80))}}), policy(allowed...))
	}

	if r := probe("mixed.test", false); !r.ok || !slices.Equal(asked, []string{"93.184.216.34:80"}) {
		t.Fatalf("mixed answers: %+v, dialed %v", r, asked)
	}
	if r := probe("two.test", false); !r.ok || !slices.Equal(asked, []string{"93.184.216.1:80", "93.184.216.2:80"}) {
		t.Fatalf("second address: %+v, dialed %v", r, asked)
	}
	r := probe("inside.test", false)
	if r.code != CodeAddressForbidden || !maps.Equal(r.params, map[string]string{"address": "10.0.0.6"}) || len(asked) != 0 ||
		r.err != "dns inside.test: every address (e.g. 10.0.0.6) is a special-purpose address outside the origin allow list" {
		t.Fatalf("only special-purpose answers: %+v, dialed %v", r, asked)
	}
	if r := probe("inside.test", false, "10.0.0.0/8"); !r.ok || !slices.Equal(asked, []string{"10.0.0.6:80"}) {
		t.Fatalf("allow-listed answer: %+v, dialed %v", r, asked)
	}
	r = probe("10.9.9.9", false)
	if r.code != CodeAddressForbidden || r.params["address"] != "10.9.9.9" || len(asked) != 0 || len(lookups) != 0 {
		t.Fatalf("forbidden literal: %+v, dialed %v, lookups %v", r, asked, lookups)
	}
	if r := probe("10.9.9.9", false, "10.9.0.0/16"); !r.ok || !slices.Equal(asked, []string{"10.9.9.9:80"}) {
		t.Fatalf("allowed literal: %+v, dialed %v", r, asked)
	}
	r = probe("missing.test", false)
	if r.code != CodeDNSFailed || !maps.Equal(r.params, map[string]string{"host": "missing.test"}) || !strings.HasPrefix(r.err, "dns missing.test: ") ||
		!slices.Equal(lookups, []string{"ip4 missing.test"}) {
		t.Fatalf("unresolvable: %+v, lookups %v", r, lookups)
	}
	if r := probe("v6only.test", false); r.code != CodeDNSFailed {
		t.Fatalf("AAAA without IPv6: %+v", r)
	}
	if r := probe("v6only.test", true); !r.ok || !slices.Equal(lookups, []string{"ip4 v6only.test", "ip6 v6only.test"}) ||
		!slices.Equal(asked, []string{"[2606:2800:220:1::1]:80"}) {
		t.Fatalf("AAAA with IPv6: %+v, lookups %v, dialed %v", r, lookups, asked)
	}
	c.opts.Dialer = dialerFunc(refuse)
	if r := probe("93.184.216.34", false); r.code != CodeConnectFailed || !strings.Contains(r.err, "connection refused") {
		t.Fatalf("refused: %+v", r)
	}
}

// countingConn counts the bytes read from a connection.
type countingConn struct {
	net.Conn
	n *atomic.Int64
}

func (c countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// TestProbeRequest: method, path and Host of the probe, the expected
// status range (redirects are not followed), at most 64 KiB of the body,
// timeouts and broken responses.
func TestProbeRequest(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.RequestURI()+" "+r.Host+" "+r.UserAgent())
		mu.Unlock()
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
		case "/unavailable":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/big":
			_, _ = w.Write(make([]byte, 4<<20))
		case "/slow":
			select {
			case <-time.After(5 * time.Second):
			case <-r.Context().Done():
			}
		}
	}))
	t.Cleanup(srv.Close)
	var read atomic.Int64
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, network, srv.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return countingConn{conn, &read}, nil
	}
	c := New(Options{Dialer: dialerFunc(dial)})
	defer c.Close()
	probe := func(f func(*configir.ActiveHealthCheck), o configir.Origin) result {
		mu.Lock()
		seen = nil
		mu.Unlock()
		return c.probe(context.Background(), onlySpec(t, &configir.Plan{Sites: []configir.Site{site("s", checkWith(f), o)}}), policy())
	}
	last := func() string {
		mu.Lock()
		defer mu.Unlock()
		if len(seen) != 1 {
			return strings.Join(seen, " | ")
		}
		return seen[0]
	}
	ua := "edgeweir-node-healthcheck/" + version.Version

	if r := probe(nil, origin("o", "93.184.216.34", 8080)); !r.ok || last() != "GET /healthz?deep=1 93.184.216.34:8080 "+ua {
		t.Fatalf("default probe: %+v, origin saw %q", r, last())
	}
	hh := origin("o", "93.184.216.34", 80)
	hh.HostHeader = "www.example.com"
	if r := probe(func(c *configir.ActiveHealthCheck) { c.Method, c.Path = "HEAD", "/" }, hh); !r.ok || last() != "HEAD / www.example.com "+ua {
		t.Fatalf("HEAD with the origin's Host: %+v, origin saw %q", r, last())
	}
	if r := probe(func(c *configir.ActiveHealthCheck) { c.Host = "health.example.com" }, hh); !r.ok || last() != "GET /healthz?deep=1 health.example.com "+ua {
		t.Fatalf("the check's Host: %+v, origin saw %q", r, last())
	}
	if r := probe(func(c *configir.ActiveHealthCheck) { c.Path = "/redirect" }, hh); !r.ok || last() != "GET /redirect www.example.com "+ua {
		t.Fatalf("302 within 200-399, not followed: %+v, origin saw %q", r, last())
	}
	r := probe(func(c *configir.ActiveHealthCheck) { c.Path, c.ExpectedStatusMax = "/redirect", 299 }, hh)
	if r.code != CodeUpstreamStatus || !maps.Equal(r.params, map[string]string{"status": "302"}) || r.err != "HTTP 302" {
		t.Fatalf("302 outside 200-299: %+v", r)
	}
	if r := probe(func(c *configir.ActiveHealthCheck) { c.Path = "/unavailable" }, hh); r.code != CodeUpstreamStatus || r.params["status"] != "503" {
		t.Fatalf("503: %+v", r)
	}
	if r := probe(func(c *configir.ActiveHealthCheck) {
		c.Path, c.ExpectedStatusMin, c.ExpectedStatusMax = "/unavailable", 500, 599
	}, hh); !r.ok {
		t.Fatalf("503 expected: %+v", r)
	}
	read.Store(0)
	if r := probe(func(c *configir.ActiveHealthCheck) { c.Path = "/big" }, hh); !r.ok || read.Load() > 64<<10+16<<10 {
		t.Fatalf("4 MiB body: %+v, %d bytes read", r, read.Load())
	}
	start := time.Now()
	r = probe(func(c *configir.ActiveHealthCheck) { c.Path, c.Timeout = "/slow", 200*time.Millisecond }, hh)
	if r.code != CodeTimeout || r.err != "timeout after 200ms" || time.Since(start) > 2*time.Second {
		t.Fatalf("slow origin: %+v after %v", r, time.Since(start))
	}

	// Not HTTP at all.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = bufio.NewReader(conn).ReadString('\n')
			_, _ = io.WriteString(conn, "SSH-2.0-OpenSSH_9.6\r\n")
			_ = conn.Close()
		}
	}()
	c.opts.Dialer = dialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, ln.Addr().String())
	})
	if r := probe(nil, hh); r.code != CodeConnectFailed || !strings.HasPrefix(r.err, "read response: ") {
		t.Fatalf("not HTTP: %+v", r)
	}
}

// TestProbeTLS: HTTPS probes send the origin's SNI (else its Host header,
// else its address) and verify the certificate against the trust store
// unless the pool skips verification.
func TestProbeTLS(t *testing.T) {
	ca, err := pkitest.NewCA("origin CA")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueServer([]string{"origin.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var snis []string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		snis = append(snis, r.TLS.ServerName+" "+r.Host)
		mu.Unlock()
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the failed handshakes are expected
	srv.StartTLS()
	t.Cleanup(srv.Close)
	var asked []string
	c := New(Options{Dialer: to(srv.Listener.Addr().String(), &asked, &mu), RootCAs: ca.Pool()})
	defer c.Close()
	probe := func(o configir.Origin, verify bool) result {
		mu.Lock()
		snis = nil
		mu.Unlock()
		s := site("s", &baseCheck, o)
		s.TLSVerify = verify
		return c.probe(context.Background(), onlySpec(t, &configir.Plan{Sites: []configir.Site{s}}), policy())
	}
	saw := func() string {
		mu.Lock()
		defer mu.Unlock()
		return strings.Join(snis, " | ")
	}
	o := origin("o", "93.184.216.34", 443)
	o.Scheme = configir.SchemeHTTPS

	withSNI := o
	withSNI.SNI, withSNI.HostHeader = "origin.test", "www.example.com"
	if r := probe(withSNI, true); !r.ok || saw() != "origin.test www.example.com" {
		t.Fatalf("SNI: %+v, origin saw %q", r, saw())
	}
	fromHost := o
	fromHost.HostHeader = "origin.test:443"
	if r := probe(fromHost, true); !r.ok || saw() != "origin.test origin.test:443" {
		t.Fatalf("SNI from the Host header: %+v, origin saw %q", r, saw())
	}
	wrong := o
	wrong.SNI = "wrong.test"
	r := probe(wrong, true)
	if r.code != CodeTLSFailed || !strings.Contains(r.err, "TLS handshake: ") || !strings.Contains(r.err, "wrong.test") {
		t.Fatalf("wrong name: %+v", r)
	}
	if r := probe(wrong, false); !r.ok {
		t.Fatalf("wrong name, verification skipped: %+v", r)
	}
	if r := probe(o, true); r.code != CodeTLSFailed {
		t.Fatalf("an IP address the certificate does not name: %+v", r)
	}
	c.opts.RootCAs = x509.NewCertPool()
	if r := probe(withSNI, true); r.code != CodeTLSFailed || !strings.Contains(r.err, "unknown authority") {
		t.Fatalf("untrusted CA: %+v", r)
	}
}

// TestProbeHTTP2: the origins of pools that send their requests over
// HTTP/2 are probed over HTTP/2, with prior knowledge for HTTP origins and
// ALPN h2 for HTTPS ones, with the same method, path, Host (:authority)
// and User-Agent as over HTTP/1.1. An origin that does not speak HTTP/2
// fails the probe, as it fails the data plane's requests.
func TestProbeHTTP2(t *testing.T) {
	ca, err := pkitest.NewCA("origin CA")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueServer([]string{"origin.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Proto+" "+r.Method+" "+r.URL.RequestURI()+" "+r.Host+" "+r.UserAgent())
		mu.Unlock()
		if r.URL.Path == "/unavailable" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	quiet := log.New(io.Discard, "", 0) // refused protocols are expected
	h2c := httptest.NewUnstartedServer(handler)
	h2c.Config.Protocols = new(http.Protocols)
	h2c.Config.Protocols.SetUnencryptedHTTP2(true)
	h2c.Start()
	t.Cleanup(h2c.Close)
	h2 := httptest.NewUnstartedServer(handler)
	h2.EnableHTTP2 = true
	h2.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	h2.StartTLS()
	t.Cleanup(h2.Close)
	h1 := httptest.NewUnstartedServer(handler) // HTTPS with ALPN http/1.1 only
	h1.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	h1.Config.ErrorLog = quiet
	h1.StartTLS()
	t.Cleanup(h1.Close)
	plain := httptest.NewUnstartedServer(handler) // HTTP/1.1 only
	plain.Config.ErrorLog = quiet
	plain.Start()
	t.Cleanup(plain.Close)
	// HTTPS without ALPN: the handshake succeeds, nothing is negotiated.
	noALPN, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = noALPN.Close() })
	go func() {
		for {
			conn, err := noALPN.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, io.LimitReader(conn, 64))
			}()
		}
	}()

	var asked []string
	var askedMu sync.Mutex
	probe := func(addr string, o configir.Origin, f func(*configir.ActiveHealthCheck)) result {
		mu.Lock()
		seen = nil
		mu.Unlock()
		c := New(Options{Dialer: to(addr, &asked, &askedMu), RootCAs: ca.Pool()})
		defer c.Close()
		s := site("s", checkWith(f), o)
		s.OriginHTTP2 = true
		sp := onlySpec(t, &configir.Plan{Sites: []configir.Site{s}})
		if !sp.http2 {
			t.Fatal("spec without HTTP/2")
		}
		return c.probe(context.Background(), sp, policy())
	}
	saw := func() string {
		mu.Lock()
		defer mu.Unlock()
		return strings.Join(seen, " | ")
	}
	ua := "edgeweir-node-healthcheck/" + version.Version

	o := origin("o", "93.184.216.34", 8080)
	if r := probe(h2c.Listener.Addr().String(), o, nil); !r.ok || saw() != "HTTP/2.0 GET /healthz?deep=1 93.184.216.34:8080 "+ua {
		t.Fatalf("h2c: %+v, origin saw %q", r, saw())
	}
	head := func(c *configir.ActiveHealthCheck) { c.Method, c.Path = "HEAD", "/" }
	if r := probe(h2c.Listener.Addr().String(), o, head); !r.ok || saw() != "HTTP/2.0 HEAD / 93.184.216.34:8080 "+ua {
		t.Fatalf("h2c HEAD: %+v, origin saw %q", r, saw())
	}
	unavailable := func(c *configir.ActiveHealthCheck) { c.Path = "/unavailable" }
	if r := probe(h2c.Listener.Addr().String(), o, unavailable); r.code != CodeUpstreamStatus || r.params["status"] != "503" {
		t.Fatalf("h2c 503: %+v", r)
	}
	if r := probe(plain.Listener.Addr().String(), o, nil); r.code != CodeConnectFailed || !strings.HasPrefix(r.err, "HTTP/2 request: ") {
		t.Fatalf("HTTP/1.1-only origin: %+v", r)
	}

	tlsOrigin := origin("o", "93.184.216.34", 443)
	tlsOrigin.Scheme, tlsOrigin.SNI, tlsOrigin.HostHeader = configir.SchemeHTTPS, "origin.test", "www.example.com"
	if r := probe(h2.Listener.Addr().String(), tlsOrigin, nil); !r.ok || saw() != "HTTP/2.0 GET /healthz?deep=1 www.example.com "+ua {
		t.Fatalf("h2: %+v, origin saw %q", r, saw())
	}
	if r := probe(h1.Listener.Addr().String(), tlsOrigin, nil); r.code != CodeTLSFailed || !strings.Contains(r.err, "application protocol") {
		t.Fatalf("HTTPS origin with ALPN http/1.1 only: %+v", r)
	}
	if r := probe(noALPN.Addr().String(), tlsOrigin, nil); r.code != CodeConnectFailed || r.err != `origin does not speak HTTP/2 (ALPN "")` {
		t.Fatalf("HTTPS origin without ALPN: %+v", r)
	}
	if saw() != "" {
		t.Fatalf("requests reached origins without HTTP/2: %q", saw())
	}
}

// harness is a checker on a manual clock whose probes reach a test origin
// that answers /healthz with the status of the origin's id.
type harness struct {
	t       *testing.T
	clock   *fakeclock.Clock
	c       *Checker
	changes atomic.Int32
	mu      sync.Mutex
	status  map[string]int // origin id -> status
	delays  []time.Duration
	probes  map[string]int
}

func newHarness(t *testing.T, concurrency int, block chan struct{}) *harness {
	t.Helper()
	h := &harness{t: t, clock: fakeclock.New(time.Unix(1_800_000_000, 0)), status: map[string]int{}, probes: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if block != nil {
			<-block
		}
		h.mu.Lock()
		id := r.Host
		h.probes[id]++
		code := h.status[id]
		h.mu.Unlock()
		w.WriteHeader(cmpOr(code, 200))
	}))
	t.Cleanup(srv.Close)
	addr := srv.Listener.Addr().String()
	h.c = New(Options{
		Clock:       h.clock,
		Concurrency: concurrency,
		Dialer: dialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		}),
		FirstDelay: func(interval time.Duration) time.Duration {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.delays = append(h.delays, interval)
			return interval / 2
		},
		OnChange: func() { h.changes.Add(1) },
	})
	t.Cleanup(h.c.Close)
	return h
}

func cmpOr(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

// probeOrigin is an origin of the harness: the Host header names it.
func probeOrigin(id string) configir.Origin {
	o := origin(id, "93.184.216.34", 80)
	o.HostHeader = id
	return o
}

func (h *harness) setStatus(id string, code int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status[id] = code
}

func (h *harness) probed(id string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.probes[id]
}

// advance moves the clock by d and waits until the probes that came due
// are done (their next probe is armed again).
func (h *harness) advance(d time.Duration, armed int) {
	h.t.Helper()
	h.clock.Advance(d)
	eventually(h.t, "probes done", func() bool { return h.clock.Armed() == armed })
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestCheckerSchedule: a new check probes first after its first delay
// within the interval, then every interval; the down set follows the
// thresholds and OnChange reports its changes.
func TestCheckerSchedule(t *testing.T) {
	h := newHarness(t, 0, nil)
	plan := &configir.Plan{Sites: []configir.Site{site("site-a", &baseCheck, probeOrigin("o1"), probeOrigin("o2"))}}
	h.c.Update(plan)
	if !slices.Equal(h.delays, []time.Duration{10 * time.Second, 10 * time.Second}) ||
		!slices.Equal(h.clock.Delays(), []time.Duration{5 * time.Second, 5 * time.Second}) || !h.c.Active() {
		t.Fatalf("first delays asked for %v, armed %v", h.delays, h.clock.Delays())
	}
	h.advance(4*time.Second, 2)
	if h.probed("o1") != 0 {
		t.Fatal("probed before the first delay")
	}
	h.setStatus("o2", 503)
	h.advance(time.Second, 2) // t=5s: first probes
	if h.probed("o1") != 1 || h.probed("o2") != 1 || !slices.Equal(h.clock.Delays(), []time.Duration{10 * time.Second, 10 * time.Second}) {
		t.Fatalf("probes %v, next %v", h.probes, h.clock.Delays())
	}
	st := h.c.Statuses()
	if len(st) != 1 || st[0].Key != (Key{"site-a", "o2"}) || !st[0].Healthy || st[0].ConsecutiveFailures != 1 ||
		st[0].LastErrorCode != CodeUpstreamStatus || !st[0].LastFailureAt.Equal(time.Unix(1_800_000_005, 0)) || len(h.c.Down()) != 0 {
		t.Fatalf("after one failure: %+v, down %v", st, h.c.Down())
	}
	h.advance(10*time.Second, 2) // second failure: unhealthy
	if down := h.c.Down(); !slices.Equal(down, []Key{{"site-a", "o2"}}) || h.changes.Load() != 1 {
		t.Fatalf("down %v, changes %d", down, h.changes.Load())
	}
	if st := h.c.Statuses(); len(st) != 1 || st[0].Healthy || st[0].ConsecutiveFailures != 2 || st[0].LastErrorParams["status"] != "503" {
		t.Fatalf("unhealthy: %+v", st)
	}
	h.setStatus("o2", 200)
	h.advance(10*time.Second, 2) // 1 of 2 successes
	if len(h.c.Down()) != 1 || h.changes.Load() != 1 {
		t.Fatal("healthy after one success (threshold 2)")
	}
	if st := h.c.Statuses(); len(st) != 1 || st[0].Healthy || st[0].ConsecutiveFailures != 0 {
		t.Fatalf("recovering: %+v", st)
	}
	h.advance(10*time.Second, 2)
	if len(h.c.Down()) != 0 || h.changes.Load() != 2 || len(h.c.Statuses()) != 0 {
		t.Fatalf("recovered: down %v, changes %d, statuses %+v", h.c.Down(), h.changes.Load(), h.c.Statuses())
	}
	if h.c.TTL() != 90*time.Second {
		t.Fatalf("TTL = %v", h.c.TTL())
	}
}

// TestCheckerReconcile: unchanged checks keep their state and schedule,
// changed ones start over healthy, removed ones stop; S3 and refused
// origins are never checked.
func TestCheckerReconcile(t *testing.T) {
	h := newHarness(t, 0, nil)
	plan := func(c *configir.ActiveHealthCheck, more ...configir.Site) *configir.Plan {
		return &configir.Plan{Sites: append([]configir.Site{site("site-a", c, probeOrigin("o1"), probeOrigin("o2"))}, more...)}
	}
	h.setStatus("o1", 500)
	h.setStatus("o2", 500)
	h.c.Update(plan(&baseCheck))
	h.advance(5*time.Second, 2)
	h.advance(10*time.Second, 2)
	if len(h.c.Down()) != 2 || h.changes.Load() != 2 {
		t.Fatalf("down %v, changes %d", h.c.Down(), h.changes.Load())
	}

	// The same plan again: nothing restarts.
	h.c.Update(plan(&baseCheck))
	if len(h.delays) != 2 || len(h.c.Down()) != 2 || !slices.Equal(h.clock.Delays(), []time.Duration{10 * time.Second, 10 * time.Second}) {
		t.Fatalf("unchanged plan: delays %v, down %v, armed %v", h.delays, h.c.Down(), h.clock.Delays())
	}

	// Another site with an S3 and a refused origin: neither is checked.
	s3 := probeOrigin("s3")
	s3.S3 = &configir.S3Auth{Region: "us-east-1", CredentialID: "c"}
	refused := probeOrigin("refused")
	refused.Forbidden = true
	h.c.Update(plan(&baseCheck, site("site-b", &baseCheck, s3, refused)))
	if h.clock.Armed() != 2 || len(h.delays) != 2 {
		t.Fatalf("S3 or refused origins scheduled: armed %d", h.clock.Armed())
	}

	// A changed check starts over: healthy, with a new first delay.
	changed := checkWith(func(c *configir.ActiveHealthCheck) { c.Interval = 20 * time.Second })
	h.c.Update(plan(changed))
	if len(h.c.Down()) != 0 || h.changes.Load() != 3 || !slices.Equal(h.delays[2:], []time.Duration{20 * time.Second, 20 * time.Second}) ||
		!slices.Equal(h.clock.Delays(), []time.Duration{10 * time.Second, 10 * time.Second}) {
		t.Fatalf("changed check: down %v, changes %d, delays %v, armed %v", h.c.Down(), h.changes.Load(), h.delays, h.clock.Delays())
	}
	if h.c.TTL() != 90*time.Second {
		t.Fatalf("TTL = %v", h.c.TTL())
	}
	h.c.Update(plan(checkWith(func(c *configir.ActiveHealthCheck) { c.Interval = 45 * time.Second })))
	if h.c.TTL() != 135*time.Second {
		t.Fatalf("TTL = %v, want 3 intervals", h.c.TTL())
	}

	// Removed: the timers stop and nothing is down.
	h.c.Update(&configir.Plan{})
	if h.clock.Armed() != 0 || h.c.Active() || len(h.c.Statuses()) != 0 || h.c.TTL() != 90*time.Second {
		t.Fatalf("no checks: armed %d, active %v", h.clock.Armed(), h.c.Active())
	}
	h.c.Update(plan(&baseCheck))
	h.c.Close()
	h.c.Update(plan(&baseCheck))
	if h.clock.Armed() != 0 || h.c.Active() {
		t.Fatal("checks run after Close")
	}
}

// TestCheckerConcurrency: no more probes than Concurrency run at a time.
func TestCheckerConcurrency(t *testing.T) {
	block := make(chan struct{})
	h := newHarness(t, 2, block)
	var running, peak atomic.Int32
	inner := h.c.opts.Dialer
	h.c.opts.Dialer = dialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		n := running.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		conn, err := inner.DialContext(ctx, network, address)
		if err != nil {
			running.Add(-1)
			return nil, err
		}
		return closeHook{conn, func() { running.Add(-1) }}, nil
	})
	var origins []configir.Origin
	for i := range 6 {
		origins = append(origins, probeOrigin("o"+strconv.Itoa(i)))
	}
	h.c.Update(&configir.Plan{Sites: []configir.Site{site("site-a", &baseCheck, origins...)}})
	h.clock.Advance(5 * time.Second)
	eventually(t, "two probes waiting for the origin", func() bool { return running.Load() == 2 })
	time.Sleep(50 * time.Millisecond)
	if running.Load() != 2 {
		t.Fatalf("%d probes at a time, want 2", running.Load())
	}
	close(block)
	eventually(t, "all probes done", func() bool { return h.clock.Armed() == 6 })
	if peak.Load() != 2 {
		t.Fatalf("peak %d probes at a time, want 2", peak.Load())
	}
}

type closeHook struct {
	net.Conn
	f func()
}

func (c closeHook) Close() error {
	c.f()
	return c.Conn.Close()
}

// TestFirstDelayIsRandomWithinTheInterval: by default checks start at
// random points of their interval.
func TestFirstDelayIsRandomWithinTheInterval(t *testing.T) {
	c := New(Options{})
	defer c.Close()
	seen := map[time.Duration]bool{}
	for range 200 {
		d := c.opts.FirstDelay(5 * time.Second)
		if d < 0 || d >= 5*time.Second {
			t.Fatalf("first delay %v outside [0, 5s)", d)
		}
		seen[d] = true
	}
	if len(seen) < 100 {
		t.Fatalf("%d distinct first delays of 200", len(seen))
	}
}
