// Package probe measures, for the console's scheduling, whether the
// scheduling addresses of edge nodes answer (ProbeService, proto v0.14.0).
// `edgeweir-node probe` runs it with a probe identity; a node the console
// lets probe its peers runs it with its node identity.
//
// One attempt per method:
//
//	TCP    connect, then close; the RTT is the connect time.
//	HTTP   connect, GET /.edgeweir/health with Host health.edgeweir.invalid;
//	       success only on status 200.
//	HTTPS  connect, TLS with SNI health.edgeweir.invalid, then the same GET.
//
// For HTTP and HTTPS the RTT is the time from sending the request to the
// status line: one round trip on the established connection, like TCP's
// connect time, so the values of all methods compare. With proxy_protocol a
// PROXY protocol v1 line built from the socket's own addresses comes first.
//
// HTTPS never verifies the node's certificate (InsecureSkipVerify): nodes
// answer SNI health.edgeweir.invalid with a self-signed certificate each
// generates for itself, so there is nothing a probe could verify it against.
// The probe only measures reachability: it sends no secret, and nothing but
// the status line of the answer is used.
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/version"
)

// The health endpoint nodes answer before any site lookup (feature
// probe-health-v1).
const (
	HealthPath = "/.edgeweir/health"
	// HealthHost is the Host of health requests and the SNI of HTTPS
	// probes; nodes answer it with their self-signed health certificate.
	HealthHost = "health.edgeweir.invalid"
)

// Error codes of ProbeResult.error.
const (
	ErrTimeout     = "timeout"
	ErrRefused     = "refused"
	ErrReset       = "reset"
	ErrTLS         = "tls"
	ErrStatus      = "status"
	ErrUnreachable = "unreachable"
)

// DefaultConcurrency is the number of targets probed at the same time.
const DefaultConcurrency = 32

// Prober probes targets.
type Prober struct {
	// Dial opens TCP connections (default: net.Dialer).
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// Concurrency bounds the targets probed at the same time (default 32).
	Concurrency int
}

func (p *Prober) dial(ctx context.Context, address string) (net.Conn, error) {
	if p != nil && p.Dial != nil {
		return p.Dial(ctx, "tcp", address)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", address)
}

// Supported reports whether a target can be probed: an IP literal, a port
// and a known method. Other targets are left out of a round.
func Supported(t *nodev1.ProbeTarget) bool {
	if _, err := netip.ParseAddr(t.GetAddress()); err != nil {
		return false
	}
	if t.GetPort() == 0 || t.GetPort() > 65535 {
		return false
	}
	switch t.GetMethod() {
	case nodev1.ProbeMethod_PROBE_METHOD_TCP, nodev1.ProbeMethod_PROBE_METHOD_HTTP, nodev1.ProbeMethod_PROBE_METHOD_HTTPS:
		return true
	}
	return false
}

// ProbeAll probes every target (at most Concurrency at a time) and returns
// the results in the order of targets.
func (p *Prober) ProbeAll(ctx context.Context, targets []*nodev1.ProbeTarget, timeout time.Duration, attempts int) []*nodev1.ProbeResult {
	results := make([]*nodev1.ProbeResult, len(targets))
	n := DefaultConcurrency
	if p != nil && p.Concurrency > 0 {
		n = p.Concurrency
	}
	next := make(chan int)
	var wg sync.WaitGroup
	for range min(n, len(targets)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				results[i] = p.Probe(ctx, targets[i], timeout, attempts)
			}
		}()
	}
	for i := range targets {
		next <- i
	}
	close(next)
	wg.Wait()
	return results
}

// Probe makes attempts attempts one after another (fewer when ctx ends) and
// summarizes them: sent, lost, the median RTT of the successful ones and
// the error code of the last failure.
func (p *Prober) Probe(ctx context.Context, t *nodev1.ProbeTarget, timeout time.Duration, attempts int) *nodev1.ProbeResult {
	r := &nodev1.ProbeResult{NodeId: t.GetNodeId(), Address: t.GetAddress(), Port: t.GetPort(), Method: t.GetMethod()}
	var rtts []time.Duration
	for range attempts {
		if ctx.Err() != nil {
			break
		}
		rtt, code := p.attempt(ctx, t, timeout)
		r.Sent++
		if code != "" {
			r.Lost++
			r.Error = code
			continue
		}
		rtts = append(rtts, rtt)
	}
	r.RttMs = MedianMillis(rtts)
	return r
}

// MedianMillis is the median of rtts in milliseconds, rounded, and at least
// 1 when there is any RTT (0 means "no successful attempt").
func MedianMillis(rtts []time.Duration) uint32 {
	if len(rtts) == 0 {
		return 0
	}
	s := slices.Clone(rtts)
	slices.Sort(s)
	m := s[len(s)/2]
	if len(s)%2 == 0 {
		m = (s[len(s)/2-1] + m) / 2
	}
	ms := (m + time.Millisecond/2) / time.Millisecond
	return uint32(min(max(ms, 1), 1<<32-1))
}

// attempt makes one attempt within timeout and returns its RTT or the error
// code of its failure.
func (p *Prober) attempt(ctx context.Context, t *nodev1.ProbeTarget, timeout time.Duration) (time.Duration, string) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	address := net.JoinHostPort(t.GetAddress(), strconv.FormatUint(uint64(t.GetPort()), 10))
	start := time.Now()
	conn, err := p.dial(ctx, address)
	if err != nil {
		return 0, Classify(err)
	}
	connected := time.Since(start)
	defer conn.Close()
	// The deadline bounds every read and write; cancelling ctx (shutdown)
	// ends them at once.
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()

	if t.GetProxyProtocol() {
		if _, err := io.WriteString(conn, ProxyV1Header(conn.LocalAddr(), conn.RemoteAddr())); err != nil {
			return 0, Classify(err)
		}
	}
	switch t.GetMethod() {
	case nodev1.ProbeMethod_PROBE_METHOD_TCP:
		return connected, ""
	case nodev1.ProbeMethod_PROBE_METHOD_HTTPS:
		tc := tls.Client(conn, &tls.Config{
			ServerName: HealthHost,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
			// Reachability only (see the package comment): the node's health
			// certificate is self-signed and nothing secret is sent.
			InsecureSkipVerify: true, //nolint:gosec // see above
		})
		if err := tc.HandshakeContext(ctx); err != nil {
			if code := Classify(err); code == ErrTimeout {
				return 0, code
			}
			return 0, ErrTLS
		}
		conn = tc
	}
	return healthRequest(conn)
}

// request is the health request of HTTP and HTTPS attempts.
var request = "GET " + HealthPath + " HTTP/1.1\r\nHost: " + HealthHost + "\r\nUser-Agent: edgeweir-probe/" +
	version.Version + "\r\nAccept: */*\r\nConnection: close\r\n\r\n"

func healthRequest(conn net.Conn) (time.Duration, string) {
	sent := time.Now()
	if _, err := io.WriteString(conn, request); err != nil {
		return 0, Classify(err)
	}
	resp, err := http.ReadResponse(bufio.NewReaderSize(conn, 1024), nil)
	if err != nil {
		switch code := Classify(err); code {
		case ErrTimeout, ErrReset, ErrRefused:
			return 0, code
		}
		return 0, ErrStatus // not an HTTP answer
	}
	rtt := time.Since(sent)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, ErrStatus
	}
	return rtt, ""
}

// Classify maps a connection error to an error code.
func Classify(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &ne) && ne.Timeout():
		return ErrTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		return ErrRefused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ECONNABORTED), errors.Is(err, syscall.EPIPE),
		errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, net.ErrClosed):
		return ErrReset
	default:
		return ErrUnreachable
	}
}

// ProxyV1Header is the PROXY protocol v1 line for a connection from local
// to remote: "PROXY TCP4|TCP6 <src> <dst> <sport> <dport>\r\n", or
// "PROXY UNKNOWN\r\n" when the addresses are not TCP addresses of one
// family.
func ProxyV1Header(local, remote net.Addr) string {
	src, ok1 := tcpAddrPort(local)
	dst, ok2 := tcpAddrPort(remote)
	if !ok1 || !ok2 {
		return "PROXY UNKNOWN\r\n"
	}
	family := ""
	switch {
	case src.Addr().Is4() && dst.Addr().Is4():
		family = "TCP4"
	case src.Addr().Is6() && dst.Addr().Is6():
		family = "TCP6"
	default:
		return "PROXY UNKNOWN\r\n"
	}
	return "PROXY " + family + " " + src.Addr().WithZone("").String() + " " + dst.Addr().WithZone("").String() + " " +
		strconv.Itoa(int(src.Port())) + " " + strconv.Itoa(int(dst.Port())) + "\r\n"
}

func tcpAddrPort(a net.Addr) (netip.AddrPort, bool) {
	ta, ok := a.(*net.TCPAddr)
	if !ok || ta == nil {
		return netip.AddrPort{}, false
	}
	ap := ta.AddrPort()
	if !ap.IsValid() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}
