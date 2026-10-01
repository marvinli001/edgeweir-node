package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

const (
	tcp   = nodev1.ProbeMethod_PROBE_METHOD_TCP
	httpM = nodev1.ProbeMethod_PROBE_METHOD_HTTP
	https = nodev1.ProbeMethod_PROBE_METHOD_HTTPS
)

// target returns a target for the host:port of a URL or listener address.
func target(t *testing.T, hostport string, method nodev1.ProbeMethod, proxy bool) *nodev1.ProbeTarget {
	t.Helper()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(hostport, "http://"), "https://"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatal(err)
	}
	return &nodev1.ProbeTarget{NodeId: "node-1", Address: host, Port: uint32(p), Method: method, ProxyProtocol: proxy}
}

// healthHandler answers the health request like a node and records what it saw.
type healthHandler struct {
	mu       sync.Mutex
	status   int
	requests []*http.Request
}

func (h *healthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.requests = append(h.requests, r)
	status := h.status
	h.mu.Unlock()
	if r.URL.Path != HealthPath || r.Host != HealthHost || r.Method != http.MethodGet {
		status = http.StatusNotFound
	}
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, "ok")
}

func (h *healthHandler) seen() []*http.Request {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*http.Request(nil), h.requests...)
}

func check(t *testing.T, r *nodev1.ProbeResult, sent, lost uint32, code string) {
	t.Helper()
	if r.GetSent() != sent || r.GetLost() != lost || r.GetError() != code {
		t.Fatalf("result sent=%d lost=%d error=%q, want sent=%d lost=%d error=%q", r.GetSent(), r.GetLost(), r.GetError(), sent, lost, code)
	}
	if lost < sent && r.GetRttMs() == 0 {
		t.Fatal("successful attempts but rtt_ms 0")
	}
	if lost == sent && r.GetRttMs() != 0 {
		t.Fatalf("every attempt failed but rtt_ms %d", r.GetRttMs())
	}
}

func TestProbeTCP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	var p Prober
	r := p.Probe(context.Background(), target(t, l.Addr().String(), tcp, false), time.Second, 3)
	check(t, r, 3, 0, "")
	if r.GetNodeId() != "node-1" || r.GetAddress() != "127.0.0.1" || r.GetMethod() != tcp {
		t.Fatalf("result does not echo the target: %v", r)
	}
	deadline := time.Now().Add(2 * time.Second)
	for accepted.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := accepted.Load(); n != 3 {
		t.Fatalf("connections = %d, want 3", n)
	}
}

func TestProbeTCPRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	var p Prober
	check(t, p.Probe(context.Background(), target(t, addr, tcp, false), time.Second, 2), 2, 2, ErrRefused)
}

func TestProbeConnectTimeout(t *testing.T) {
	p := Prober{Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done() // a black-holed SYN
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: ctx.Err()}
	}}
	start := time.Now()
	check(t, p.Probe(context.Background(), &nodev1.ProbeTarget{Address: "192.0.2.1", Port: 80, Method: tcp}, 50*time.Millisecond, 2), 2, 2, ErrTimeout)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("two attempts with a 50ms timeout took %v", d)
	}
}

func TestProbeHTTP(t *testing.T) {
	h := &healthHandler{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	var p Prober
	check(t, p.Probe(context.Background(), target(t, srv.URL, httpM, false), time.Second, 3), 3, 0, "")
	seen := h.seen()
	if len(seen) != 3 {
		t.Fatalf("requests = %d, want 3", len(seen))
	}
	for _, r := range seen {
		if r.Host != HealthHost || r.URL.Path != HealthPath || r.Method != http.MethodGet || r.TLS != nil {
			t.Fatalf("request %s %s Host %s (TLS %v)", r.Method, r.URL, r.Host, r.TLS != nil)
		}
		if !strings.HasPrefix(r.UserAgent(), "edgeweir-probe/") {
			t.Fatalf("User-Agent %q", r.UserAgent())
		}
	}
}

func TestProbeHTTPStatus(t *testing.T) {
	srv := httptest.NewServer(&healthHandler{status: http.StatusServiceUnavailable})
	defer srv.Close()
	var p Prober
	check(t, p.Probe(context.Background(), target(t, srv.URL, httpM, false), time.Second, 3), 3, 3, ErrStatus)
}

func TestProbeHTTPNotHTTP(t *testing.T) {
	l := serve(t, func(c net.Conn) {
		_, _ = io.WriteString(c, "SSH-2.0-OpenSSH_9.6\r\n")
		time.Sleep(50 * time.Millisecond)
	})
	var p Prober
	check(t, p.Probe(context.Background(), target(t, l, httpM, false), time.Second, 1), 1, 1, ErrStatus)
}

func TestProbeHTTPReadTimeout(t *testing.T) {
	l := serve(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) }) // never answers
	var p Prober
	start := time.Now()
	check(t, p.Probe(context.Background(), target(t, l, httpM, false), 100*time.Millisecond, 2), 2, 2, ErrTimeout)
	if d := time.Since(start); d > 900*time.Millisecond {
		t.Fatalf("two attempts with a 100ms timeout took %v", d)
	}
}

func TestProbeHTTPReset(t *testing.T) {
	l := serve(t, func(c net.Conn) {
		// Read the request, then reset the connection.
		_, _ = http.ReadRequest(bufio.NewReader(c))
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
	})
	var p Prober
	check(t, p.Probe(context.Background(), target(t, l, httpM, false), time.Second, 2), 2, 2, ErrReset)
}

func TestProbeHTTPS(t *testing.T) {
	h := &healthHandler{}
	var sni []string
	var mu sync.Mutex
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		mu.Lock()
		sni = append(sni, hello.ServerName)
		mu.Unlock()
		return nil, nil
	}}
	srv.StartTLS()
	defer srv.Close()
	var p Prober
	// httptest's certificate is for example.com: only an unverified
	// handshake succeeds.
	check(t, p.Probe(context.Background(), target(t, srv.URL, https, false), time.Second, 2), 2, 0, "")
	for _, r := range h.seen() {
		if r.TLS == nil || r.Host != HealthHost || r.URL.Path != HealthPath {
			t.Fatalf("request %s Host %s TLS %v", r.URL, r.Host, r.TLS != nil)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sni) != 2 || sni[0] != HealthHost {
		t.Fatalf("SNI = %v, want %s twice", sni, HealthHost)
	}
}

func TestProbeHTTPSHandshakeFailure(t *testing.T) {
	// A plain HTTP listener cannot complete a TLS handshake.
	srv := httptest.NewServer(&healthHandler{})
	defer srv.Close()
	var p Prober
	check(t, p.Probe(context.Background(), target(t, srv.URL, https, false), time.Second, 2), 2, 2, ErrTLS)
	// A listener that aborts the handshake (a node without the health
	// certificate rejects unknown SNI).
	l := serve(t, func(c net.Conn) { _, _ = c.Read(make([]byte, 512)) })
	check(t, p.Probe(context.Background(), target(t, l, https, false), time.Second, 1), 1, 1, ErrTLS)
}

func TestProbeHTTPSHandshakeTimeout(t *testing.T) {
	l := serve(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	var p Prober
	check(t, p.Probe(context.Background(), target(t, l, https, false), 100*time.Millisecond, 1), 1, 1, ErrTimeout)
}

// proxyServer accepts connections that start with a PROXY protocol v1 line,
// records the line and answers the health request (over TLS when cfg is
// set).
type proxyServer struct {
	addr  string
	mu    sync.Mutex
	lines []string
	peers []string
}

func newProxyServer(t *testing.T, cfg *tls.Config) *proxyServer {
	s := &proxyServer{}
	s.addr = serve(t, func(c net.Conn) {
		br := bufio.NewReader(c)
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		s.mu.Lock()
		s.lines = append(s.lines, line)
		s.peers = append(s.peers, c.RemoteAddr().String()+" "+c.LocalAddr().String())
		s.mu.Unlock()
		var conn net.Conn = &bufConn{Conn: c, r: br}
		if cfg != nil {
			conn = tls.Server(conn, cfg)
		}
		rd := bufio.NewReader(conn)
		req, err := http.ReadRequest(rd)
		if err != nil {
			return
		}
		status := "404 Not Found"
		if req.URL.Path == HealthPath && req.Host == HealthHost {
			status = "200 OK"
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 "+status+"\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	return s
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (s *proxyServer) check(t *testing.T, n int) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.lines) != n {
		t.Fatalf("PROXY lines = %d, want %d", len(s.lines), n)
	}
	for i, line := range s.lines {
		var client, server string
		fmt.Sscan(s.peers[i], &client, &server)
		ch, cp, _ := net.SplitHostPort(client)
		sh, sp, _ := net.SplitHostPort(server)
		want := "PROXY TCP4 " + ch + " " + sh + " " + cp + " " + sp + "\r\n"
		if line != want {
			t.Fatalf("PROXY line %q, want %q", line, want)
		}
	}
}

func TestProbeProxyProtocol(t *testing.T) {
	var p Prober
	for _, m := range []nodev1.ProbeMethod{httpM, tcp} {
		s := newProxyServer(t, nil)
		check(t, p.Probe(context.Background(), target(t, s.addr, m, true), time.Second, 2), 2, 0, "")
		if m == httpM {
			s.check(t, 2)
		}
	}
	// TCP sends the line too before closing.
	s := newProxyServer(t, nil)
	check(t, p.Probe(context.Background(), target(t, s.addr, tcp, true), time.Second, 1), 1, 0, "")
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		n := len(s.lines)
		s.mu.Unlock()
		if n == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.check(t, 1)

	// A listener that needs the PROXY line rejects the request without it.
	s = newProxyServer(t, nil)
	r := p.Probe(context.Background(), target(t, s.addr, httpM, false), 200*time.Millisecond, 1)
	if r.GetLost() != 1 {
		t.Fatalf("health request without the PROXY line succeeded: %v", r)
	}
}

func TestProbeProxyProtocolHTTPS(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.StartTLS() // only for its certificate
	cfg := srv.TLS.Clone()
	srv.Close()
	s := newProxyServer(t, cfg)
	var p Prober
	check(t, p.Probe(context.Background(), target(t, s.addr, https, true), time.Second, 2), 2, 0, "")
	s.check(t, 2)
}

func TestProbeAllKeepsOrderAndBoundsConcurrency(t *testing.T) {
	var cur, peak atomic.Int32
	p := Prober{Concurrency: 4, Dial: func(ctx context.Context, _, addr string) (net.Conn, error) {
		n := cur.Add(1)
		defer cur.Add(-1)
		for {
			old := peak.Load()
			if n <= old || peak.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		if strings.HasPrefix(addr, "192.0.2.") {
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
		}
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}}
	var targets []*nodev1.ProbeTarget
	for i := range 40 {
		addr := "198.51.100." + strconv.Itoa(i)
		if i%3 == 0 {
			addr = "192.0.2." + strconv.Itoa(i)
		}
		targets = append(targets, &nodev1.ProbeTarget{NodeId: "n" + strconv.Itoa(i), Address: addr, Port: 80, Method: tcp})
	}
	results := p.ProbeAll(context.Background(), targets, time.Second, 2)
	if len(results) != len(targets) {
		t.Fatalf("results = %d", len(results))
	}
	for i, r := range results {
		if r.GetNodeId() != targets[i].GetNodeId() || r.GetAddress() != targets[i].GetAddress() {
			t.Fatalf("result %d is for %s/%s, want %s/%s", i, r.GetNodeId(), r.GetAddress(), targets[i].GetNodeId(), targets[i].GetAddress())
		}
		if i%3 == 0 {
			check(t, r, 2, 2, ErrRefused)
		} else {
			check(t, r, 2, 0, "")
		}
	}
	if n := peak.Load(); n > 4 || n < 2 {
		t.Fatalf("peak concurrency %d, want 2..4", n)
	}
	if got := p.ProbeAll(context.Background(), nil, time.Second, 3); len(got) != 0 {
		t.Fatalf("no targets: %v", got)
	}
}

func TestProbeStopsWhenCancelled(t *testing.T) {
	l := serve(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	var p Prober
	start := time.Now()
	r := p.Probe(ctx, target(t, l, httpM, false), 5*time.Second, 10)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("cancelled probe took %v", d)
	}
	if r.GetSent() != 1 {
		t.Fatalf("attempts after cancellation: %v", r)
	}
}

func TestMedianMillis(t *testing.T) {
	ms := time.Millisecond
	for _, c := range []struct {
		in   []time.Duration
		want uint32
	}{
		{nil, 0},
		{[]time.Duration{3 * ms}, 3},
		{[]time.Duration{10 * ms, ms, 2 * ms}, 2},
		{[]time.Duration{ms, 2 * ms}, 2},                  // 1.5 ms rounds up
		{[]time.Duration{ms, 2 * ms, 4 * ms, 40 * ms}, 3}, // (2+4)/2
		{[]time.Duration{100 * time.Microsecond}, 1},      // a success is never 0
		{[]time.Duration{1400 * time.Microsecond}, 1},
		{[]time.Duration{time.Hour * 24 * 365 * 200}, 1<<32 - 1},
	} {
		if got := MedianMillis(c.in); got != c.want {
			t.Errorf("MedianMillis(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{nil, ""},
		{context.DeadlineExceeded, ErrTimeout},
		{&net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, ErrTimeout},
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}, ErrRefused},
		{&net.OpError{Op: "read", Err: os.NewSyscallError("read", syscall.ECONNRESET)}, ErrReset},
		{&net.OpError{Op: "write", Err: os.NewSyscallError("write", syscall.EPIPE)}, ErrReset},
		{io.EOF, ErrReset},
		{fmt.Errorf("x: %w", io.ErrUnexpectedEOF), ErrReset},
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}, ErrUnreachable},
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}, ErrUnreachable},
		{errors.New("something else"), ErrUnreachable},
	} {
		if got := Classify(c.err); got != c.want {
			t.Errorf("Classify(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

func TestSupported(t *testing.T) {
	ok := []*nodev1.ProbeTarget{
		{Address: "203.0.113.7", Port: 80, Method: httpM},
		{Address: "2001:db8::1", Port: 443, Method: https},
		{Address: "198.51.100.1", Port: 65535, Method: tcp},
	}
	bad := []*nodev1.ProbeTarget{
		{Address: "edge.example.com", Port: 80, Method: httpM}, // names are never resolved
		{Address: "", Port: 80, Method: tcp},
		{Address: "203.0.113.7", Port: 0, Method: tcp},
		{Address: "203.0.113.7", Port: 70000, Method: tcp},
		{Address: "203.0.113.7", Port: 80, Method: nodev1.ProbeMethod_PROBE_METHOD_UNSPECIFIED},
		{Address: "203.0.113.7", Port: 80, Method: nodev1.ProbeMethod(42)},
	}
	for _, tg := range ok {
		if !Supported(tg) {
			t.Errorf("Supported(%v) = false", tg)
		}
	}
	for _, tg := range bad {
		if Supported(tg) {
			t.Errorf("Supported(%v) = true", tg)
		}
	}
}

func TestProxyV1Header(t *testing.T) {
	tcpAddr := func(s string) net.Addr {
		a, err := net.ResolveTCPAddr("tcp", s)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	for _, c := range []struct {
		local, remote net.Addr
		want          string
	}{
		{tcpAddr("192.0.2.10:40000"), tcpAddr("203.0.113.7:8081"), "PROXY TCP4 192.0.2.10 203.0.113.7 40000 8081\r\n"},
		{tcpAddr("[2001:db8::10]:40001"), tcpAddr("[2001:db8::7]:443"), "PROXY TCP6 2001:db8::10 2001:db8::7 40001 443\r\n"},
		{tcpAddr("[::ffff:192.0.2.10]:40002"), tcpAddr("203.0.113.7:80"), "PROXY TCP4 192.0.2.10 203.0.113.7 40002 80\r\n"},
		{tcpAddr("[fe80::1%lo0]:40003"), tcpAddr("[fe80::2%lo0]:80"), "PROXY TCP6 fe80::1 fe80::2 40003 80\r\n"},
		{tcpAddr("192.0.2.10:40000"), tcpAddr("[2001:db8::7]:443"), "PROXY UNKNOWN\r\n"},
		{nil, tcpAddr("203.0.113.7:80"), "PROXY UNKNOWN\r\n"},
		{&net.UnixAddr{Name: "/x", Net: "unix"}, tcpAddr("203.0.113.7:80"), "PROXY UNKNOWN\r\n"},
	} {
		if got := ProxyV1Header(c.local, c.remote); got != c.want {
			t.Errorf("ProxyV1Header(%v, %v) = %q, want %q", c.local, c.remote, got, c.want)
		}
	}
}

// serve accepts connections on a loopback listener and runs handle for
// each (the connection is closed afterwards); it returns the address.
func serve(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		_ = l.Close()
		wg.Wait()
	})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				handle(c)
			}()
		}
	}()
	return l.Addr().String()
}
