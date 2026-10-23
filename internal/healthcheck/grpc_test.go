package healthcheck

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/pki/pkitest"
)

// grpcHealthHandler answers grpc.health.v1.Health/Check like a gRPC
// server: "" and "e2e.Echo" are SERVING, "down" NOT_SERVING, "empty"
// answers an empty message (UNKNOWN), "missing" is a trailers-only
// NOT_FOUND, "bare" leaves out grpc-status. seen records the service, the
// protocol, :authority and the te header of every call.
func grpcHealthHandler(seen *[]string, mu *sync.Mutex) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		service := ""
		if len(body) >= 5 {
			msg := body[5:]
			for len(msg) > 0 {
				num, typ, n := protowire.ConsumeTag(msg)
				msg = msg[n:]
				if num == 1 && typ == protowire.BytesType {
					v, n := protowire.ConsumeString(msg)
					service, msg = v, msg[n:]
					continue
				}
				msg = msg[protowire.ConsumeFieldValue(num, typ, msg):]
			}
		}
		mu.Lock()
		*seen = append(*seen, strings.Join([]string{r.Proto, r.Method, r.URL.Path, r.Host, r.Header.Get("Content-Type"), r.Header.Get("Te"), service}, " "))
		mu.Unlock()
		if r.URL.Path != grpcHealthPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		switch service {
		case "missing":
			w.Header().Set("Grpc-Status", "5")
			w.Header().Set("Grpc-Message", "unknown service")
			w.WriteHeader(http.StatusOK)
			return
		case "bare":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(response(1))
			return
		}
		w.Header().Set("Trailer", "Grpc-Status")
		status := map[string]uint64{"": 1, "e2e.Echo": 1, "down": 2, "empty": 0}[service]
		_, _ = w.Write(response(status))
		w.Header().Set("Grpc-Status", "0")
	})
}

// response is the length-prefixed HealthCheckResponse with status (0, the
// default, encodes as an empty message).
func response(status uint64) []byte {
	var msg []byte
	if status != 0 {
		msg = protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), status)
	}
	out := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(out[1:], uint32(len(msg)))
	return append(out, msg...)
}

// TestProbeGRPC: gRPC checks call grpc.health.v1.Health/Check over HTTP/2
// (prior knowledge to HTTP origins, ALPN h2 to HTTPS ones) whatever the
// pool's protocol, with the check's service; only SERVING with
// grpc-status 0 is healthy.
func TestProbeGRPC(t *testing.T) {
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
	handler := grpcHealthHandler(&seen, &mu)
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

	var asked []string
	var askedMu sync.Mutex
	probe := func(addr string, o configir.Origin, service string) result {
		mu.Lock()
		seen = nil
		mu.Unlock()
		c := New(Options{Dialer: to(addr, &asked, &askedMu), RootCAs: ca.Pool()})
		defer c.Close()
		// An HTTP/1.1 pool: gRPC checks use HTTP/2 anyway.
		s := site("s", checkWith(func(c *configir.ActiveHealthCheck) { c.GRPC, c.GRPCService = true, service }), o)
		return c.probe(context.Background(), onlySpec(t, &configir.Plan{Sites: []configir.Site{s}}), policy())
	}
	saw := func() string {
		mu.Lock()
		defer mu.Unlock()
		return strings.Join(seen, " | ")
	}

	o := origin("o", "93.184.216.34", 50051)
	if r := probe(h2c.Listener.Addr().String(), o, ""); !r.ok || saw() != "HTTP/2.0 POST /grpc.health.v1.Health/Check 93.184.216.34:50051 application/grpc trailers " {
		t.Fatalf("h2c overall: %+v, origin saw %q", r, saw())
	}
	if r := probe(h2c.Listener.Addr().String(), o, "e2e.Echo"); !r.ok || !strings.HasSuffix(saw(), " e2e.Echo") {
		t.Fatalf("h2c service: %+v, origin saw %q", r, saw())
	}
	for service, want := range map[string]result{
		"down":    {code: CodeGRPCNotServing, params: map[string]string{"status": "NOT_SERVING"}},
		"empty":   {code: CodeGRPCNotServing, params: map[string]string{"status": "UNKNOWN"}},
		"missing": {code: CodeGRPCStatus, params: map[string]string{"status": "5"}},
		"bare":    {code: CodeGRPCStatus, params: map[string]string{"status": "2"}},
	} {
		r := probe(h2c.Listener.Addr().String(), o, service)
		if r.ok || r.code != want.code || r.params["status"] != want.params["status"] {
			t.Errorf("%s: %+v, want %s %v", service, r, want.code, want.params)
		}
	}
	if r := probe(h2c.Listener.Addr().String(), o, "missing"); !strings.Contains(r.err, "unknown service") {
		t.Errorf("grpc-message not in the error: %q", r.err)
	}

	tlsOrigin := origin("o", "93.184.216.34", 443)
	tlsOrigin.Scheme, tlsOrigin.SNI, tlsOrigin.HostHeader = configir.SchemeHTTPS, "origin.test", "grpc.example.com"
	if r := probe(h2.Listener.Addr().String(), tlsOrigin, "e2e.Echo"); !r.ok || saw() != "HTTP/2.0 POST /grpc.health.v1.Health/Check grpc.example.com application/grpc trailers e2e.Echo" {
		t.Fatalf("h2: %+v, origin saw %q", r, saw())
	}

	// Not a gRPC server: an HTTP status other than 200 fails as upstream_status.
	plain := httptest.NewUnstartedServer(http.NotFoundHandler())
	plain.Config.Protocols = new(http.Protocols)
	plain.Config.Protocols.SetUnencryptedHTTP2(true)
	plain.Start()
	t.Cleanup(plain.Close)
	if r := probe(plain.Listener.Addr().String(), o, ""); r.code != CodeUpstreamStatus || r.params["status"] != "404" {
		t.Fatalf("not a gRPC server: %+v", r)
	}
}

func TestGRPCServingStatus(t *testing.T) {
	for _, tc := range []struct {
		body []byte
		want uint64
		err  bool
	}{
		{body: response(1), want: 1},
		{body: response(0), want: 0},
		// Unknown fields are skipped.
		{body: func() []byte {
			msg := protowire.AppendString(protowire.AppendTag(nil, 7, protowire.BytesType), "x")
			msg = protowire.AppendVarint(protowire.AppendTag(msg, 1, protowire.VarintType), 2)
			return append([]byte{0, 0, 0, 0, byte(len(msg))}, msg...)
		}(), want: 2},
		{body: nil, err: true},
		{body: []byte{1, 0, 0, 0, 0}, err: true},       // compressed
		{body: []byte{0, 0, 0, 0, 9, 8}, err: true},    // short
		{body: []byte{0, 0, 0, 0, 1, 0x08}, err: true}, // truncated varint
	} {
		got, err := grpcServingStatus(tc.body)
		if (err != nil) != tc.err || (!tc.err && got != tc.want) {
			t.Errorf("grpcServingStatus(%x) = %d, %v", tc.body, got, err)
		}
	}
	if got := grpcHealthRequest(""); string(got) != "\x00\x00\x00\x00\x00" {
		t.Errorf("overall request %x", got)
	}
	if got := grpcHealthRequest("a.B"); string(got) != "\x00\x00\x00\x00\x05\x0a\x03a.B" {
		t.Errorf("service request %x", got)
	}
}

// ppListener expects every connection to start with header and hands the
// rest of it on; got records what the connections started with.
type ppListener struct {
	net.Listener
	header string
	mu     sync.Mutex
	got    []string
}

func (l *ppListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, len(l.header))
	_, err = io.ReadFull(conn, buf)
	l.mu.Lock()
	l.got = append(l.got, string(buf))
	l.mu.Unlock()
	if err != nil || string(buf) != l.header {
		_ = conn.Close()
	}
	return conn, nil
}

// TestProbeProxyProtocol: probes of origins the pool sends PROXY protocol
// start with "PROXY UNKNOWN" (v1) or the LOCAL command (v2), before TLS
// and HTTP/2 too; other origins get no header.
func TestProbeProxyProtocol(t *testing.T) {
	ca, err := pkitest.NewCA("origin CA")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueServer([]string{"origin.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if proxyHeader(0) != "" || proxyHeader(1) != "PROXY UNKNOWN\r\n" ||
		proxyHeader(2) != "\r\n\r\n\x00\r\nQUIT\n\x20\x00\x00\x00" {
		t.Fatalf("headers %q %q", proxyHeader(1), proxyHeader(2))
	}
	var mu sync.Mutex
	var seen []string
	serve := func(header string, h2c, withTLS bool) (*ppListener, string) {
		raw, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l := &ppListener{Listener: raw, header: header}
		srv := &http.Server{Handler: grpcHealthHandler(&seen, &mu)}
		if h2c {
			srv.Protocols = new(http.Protocols)
			srv.Protocols.SetUnencryptedHTTP2(true)
		}
		var ln net.Listener = l
		if withTLS {
			ln = tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2"}})
		}
		go func() { _ = srv.Serve(ln) }()
		t.Cleanup(func() { _ = srv.Close() })
		return l, raw.Addr().String()
	}
	var asked []string
	var askedMu sync.Mutex
	probe := func(addr string, o configir.Origin, grpc bool) result {
		c := New(Options{Dialer: to(addr, &asked, &askedMu), RootCAs: ca.Pool()})
		defer c.Close()
		s := site("s", checkWith(func(c *configir.ActiveHealthCheck) { c.Path, c.GRPC = grpcHealthPath, grpc }), o)
		return c.probe(context.Background(), onlySpec(t, &configir.Plan{Sites: []configir.Site{s}}), policy())
	}

	// HTTP/1.1 to a v1 origin: POST-only handler paths answer 404 to GET,
	// so the check expects it.
	v1, addr := serve("PROXY UNKNOWN\r\n", false, false)
	o := origin("o", "93.184.216.34", 80)
	o.ProxyProtocol = 1
	c := New(Options{Dialer: to(addr, &asked, &askedMu)})
	s := site("s", checkWith(func(c *configir.ActiveHealthCheck) { c.Path = grpcHealthPath; c.ExpectedStatusMax = 499 }), o)
	if r := c.probe(context.Background(), onlySpec(t, &configir.Plan{Sites: []configir.Site{s}}), policy()); !r.ok {
		t.Fatalf("v1 HTTP/1.1: %+v (origin got %q)", r, v1.got)
	}
	c.Close()

	// gRPC over TLS to a v2 origin: the header comes before the handshake.
	v2, addr := serve(proxyHeader(2), false, true)
	tlsOrigin := origin("o", "93.184.216.34", 443)
	tlsOrigin.Scheme, tlsOrigin.SNI, tlsOrigin.ProxyProtocol = configir.SchemeHTTPS, "origin.test", 2
	if r := probe(addr, tlsOrigin, true); !r.ok {
		t.Fatalf("v2 gRPC over TLS: %+v (origin got %q)", r, v2.got)
	}
	// h2c gRPC to a v2 origin.
	v2c, addr := serve(proxyHeader(2), true, false)
	o.ProxyProtocol = 2
	if r := probe(addr, o, true); !r.ok {
		t.Fatalf("v2 h2c gRPC: %+v (origin got %q)", r, v2c.got)
	}
	// Without PROXY protocol the origin that expects it closes the connection.
	o.ProxyProtocol = 0
	if r := probe(addr, o, true); r.ok || r.code != CodeConnectFailed {
		t.Fatalf("no header to a PROXY origin: %+v", r)
	}
}
