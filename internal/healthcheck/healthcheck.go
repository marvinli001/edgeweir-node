// Package healthcheck runs the active origin health checks
// (OriginPool.active_health_check, feature active-health-v1).
//
// The agent probes every origin of the sites whose pool has an active
// check (S3 origins and origins refused by the address policy are not
// probed) and pushes the origins it finds unhealthy to the data plane,
// which takes them out of rotation like the passive check's marks: an
// origin that either check marks down takes no traffic.
//
//   - Schedule: a new check probes first after a random delay within its
//     interval (checks of a fresh configuration do not all start at
//     once), then every interval; at most Concurrency probes run at a
//     time. Every applied plan reconciles the checks: unchanged checks
//     keep their state and schedule, changed ones start over.
//   - Address policy: host names are resolved with the system resolver
//     (A records; AAAA only without them and when IPv6 is used, like the
//     data plane), special-purpose addresses outside the plan's origin
//     allow list are dropped, and the probe connects to an address it
//     checked: no second resolution can point it elsewhere. Without an
//     address: dns_failed {host} or address_forbidden {address}.
//   - Probe: the check's method and path (with query), Host the check's
//     host, else the origin's host_header, else its address; HTTPS with
//     SNI the origin's sni, else its host_header (without port), else its
//     address, verified against the node's trust store unless the pool
//     skips verification. HTTP/1.1, or HTTP/2 for pools that send their
//     requests over it (ALPN h2 over TLS, prior knowledge otherwise; an
//     origin that does not negotiate h2 fails the probe). Redirects are
//     not followed, at most 64 KiB of the body is read, the whole probe
//     gets the check's timeout. A status within the expected range is a
//     success; failures are connect_failed, timeout, tls_failed and
//     upstream_status {status}, the codes of the passive check.
//   - State: an origin starts healthy, becomes unhealthy after
//     unhealthy_threshold consecutive failures and healthy again after
//     healthy_threshold consecutive successes.
package healthcheck

import (
	"bufio"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/version"
)

// Error codes of failed probes (OriginHealth.last_error_code), as the
// passive check reports them.
const (
	CodeConnectFailed    = "connect_failed"
	CodeTimeout          = "timeout"
	CodeTLSFailed        = "tls_failed"
	CodeUpstreamStatus   = "upstream_status"   // status
	CodeDNSFailed        = "dns_failed"        // host
	CodeAddressForbidden = "address_forbidden" // address
)

const (
	// DefaultConcurrency bounds the probes running at a time.
	DefaultConcurrency = 64
	// maxBody is how much of a response body a probe reads.
	maxBody = 64 << 10
	// minMarkTTL is the shortest lifetime of the data plane's marks.
	minMarkTTL = 90 * time.Second
)

// Key identifies an origin of a site.
type Key struct {
	SiteID   string
	OriginID string
}

// Status is the state of a checked origin.
type Status struct {
	Key
	Healthy             bool
	ConsecutiveFailures uint32
	// LastFailureAt, LastError, LastErrorCode and LastErrorParams describe
	// the last failed probe (zero before the first one).
	LastFailureAt   time.Time
	LastError       string
	LastErrorCode   string
	LastErrorParams map[string]string
}

// Resolver resolves origin host names (*net.Resolver).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Dialer opens TCP connections (*net.Dialer).
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Clock is the time source of the schedule and of failure times.
type Clock interface {
	Now() time.Time
	// AfterFunc calls f in its own goroutine after d; stop cancels it.
	AfterFunc(d time.Duration, f func()) (stop func() bool)
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) AfterFunc(d time.Duration, f func()) func() bool {
	return time.AfterFunc(d, f).Stop
}

// Options configure a Checker; zero values take the defaults.
type Options struct {
	// Resolver resolves origin host names (default net.DefaultResolver);
	// IPv6 also looks up AAAA records for names without A records.
	Resolver Resolver
	IPv6     bool
	// Dialer connects to origins (default a net.Dialer).
	Dialer Dialer
	// RootCAs verify HTTPS origins (nil: the system roots).
	RootCAs *x509.CertPool
	// Clock schedules the probes (default real time).
	Clock Clock
	// Concurrency bounds the probes running at a time (default 64).
	Concurrency int
	// FirstDelay is the delay before the first probe of a new check
	// (default uniformly random within the interval).
	FirstDelay func(interval time.Duration) time.Duration
	// OnChange is called, from a probe's goroutine, whenever the set of
	// unhealthy origins changes.
	OnChange func()
}

// Checker runs the active health checks of the applied plan.
type Checker struct {
	opts   Options
	sem    chan struct{}
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	checks map[Key]*check
	policy configir.AddressPolicy
	closed bool
}

// spec is everything a probe of an origin depends on: a check with a
// different spec starts over.
type spec struct {
	check    configir.ActiveHealthCheck
	scheme   string
	address  string
	port     uint32
	host     string // Host header
	sni      string
	insecure bool // the pool skips certificate verification
	http2    bool // the pool sends its requests over HTTP/2
}

type check struct {
	key   Key
	spec  spec
	state state
	stop  func() bool
	gone  bool // removed from the checker; callbacks do nothing
}

// New returns a checker without checks; Update installs them.
func New(opts Options) *Checker {
	if opts.Resolver == nil {
		opts.Resolver = net.DefaultResolver
	}
	if opts.Dialer == nil {
		opts.Dialer = &net.Dialer{}
	}
	if opts.Clock == nil {
		opts.Clock = realClock{}
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}
	if opts.FirstDelay == nil {
		opts.FirstDelay = func(interval time.Duration) time.Duration { return rand.N(max(interval, 1)) }
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Checker{opts: opts, sem: make(chan struct{}, opts.Concurrency), ctx: ctx, cancel: cancel, checks: map[Key]*check{}}
}

// specs returns the checks a plan asks for.
func specs(plan *configir.Plan) map[Key]spec {
	out := map[Key]spec{}
	if plan == nil {
		return out
	}
	for _, s := range plan.Sites {
		if s.ActiveHealthCheck == nil {
			continue
		}
		for _, o := range s.Origins {
			if o.S3 != nil || o.Forbidden {
				continue
			}
			sp := spec{check: *s.ActiveHealthCheck, scheme: o.Scheme, address: o.Address, port: o.Port, insecure: !s.TLSVerify, http2: s.OriginHTTP2}
			sp.host = cmp.Or(sp.check.Host, o.HostHeader, hostOf(o.Address, o.Port, o.Scheme))
			sp.sni = cmp.Or(o.SNI, hostname(o.HostHeader), o.Address)
			out[Key{SiteID: s.ID, OriginID: o.ID}] = sp
		}
	}
	return out
}

// hostOf is the Host header for an origin address: IPv6 literals in
// brackets, a port other than the scheme's default appended.
func hostOf(address string, port uint32, scheme string) string {
	host := address
	if ip, err := netip.ParseAddr(address); err == nil && ip.Is6() {
		host = "[" + address + "]"
	}
	if (scheme == configir.SchemeHTTPS && port != 443) || (scheme != configir.SchemeHTTPS && port != 80) {
		host += ":" + strconv.Itoa(int(port))
	}
	return host
}

// hostname strips the port (and the brackets of an IPv6 literal) from a
// Host header value.
func hostname(h string) string {
	if h == "" {
		return ""
	}
	if ap, err := netip.ParseAddrPort(h); err == nil {
		return ap.Addr().String()
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return ip.String()
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return strings.ToLower(h)
}

// Update reconciles the checks with plan (nil: none): checks that are
// gone or changed stop, new and changed ones start, unchanged ones keep
// their state and schedule.
func (c *Checker) Update(plan *configir.Plan) {
	want := specs(plan)
	var allowed []string
	if plan != nil {
		allowed = plan.OriginAllowedCIDRs
	}
	policy, _, _ := configir.NewAddressPolicy(allowed)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.policy = policy
	changed := false
	for k, ch := range c.checks {
		if sp, ok := want[k]; ok && sp == ch.spec {
			continue
		}
		ch.gone = true
		ch.stop()
		delete(c.checks, k)
		changed = changed || !ch.state.healthy
	}
	for _, k := range slices.SortedFunc(maps.Keys(want), compareKeys) {
		if _, ok := c.checks[k]; ok {
			continue
		}
		ch := &check{key: k, spec: want[k], state: state{healthy: true}}
		c.checks[k] = ch
		c.scheduleLocked(ch, c.opts.FirstDelay(ch.spec.check.Interval))
	}
	c.mu.Unlock()
	if changed {
		c.changed()
	}
}

func compareKeys(a, b Key) int {
	return cmp.Or(strings.Compare(a.SiteID, b.SiteID), strings.Compare(a.OriginID, b.OriginID))
}

func (c *Checker) changed() {
	if c.opts.OnChange != nil {
		c.opts.OnChange()
	}
}

// scheduleLocked arms the next probe of ch after d; c.mu must be held.
func (c *Checker) scheduleLocked(ch *check, d time.Duration) {
	ch.stop = c.opts.Clock.AfterFunc(d, func() { c.run(ch) })
}

// run probes ch once (waiting for a free slot) and schedules the next
// probe one interval after this one started.
func (c *Checker) run(ch *check) {
	select {
	case c.sem <- struct{}{}:
	case <-c.ctx.Done():
		return
	}
	defer func() { <-c.sem }()
	c.mu.Lock()
	if ch.gone {
		c.mu.Unlock()
		return
	}
	sp, policy := ch.spec, c.policy
	c.mu.Unlock()

	start := c.opts.Clock.Now()
	r := c.probe(c.ctx, sp, policy)

	c.mu.Lock()
	if ch.gone || c.ctx.Err() != nil {
		c.mu.Unlock()
		return
	}
	changed := ch.state.record(r, c.opts.Clock.Now(), sp.check.HealthyThreshold, sp.check.UnhealthyThreshold)
	c.scheduleLocked(ch, max(sp.check.Interval-c.opts.Clock.Now().Sub(start), 0))
	c.mu.Unlock()
	if changed {
		c.changed()
	}
}

// Close stops every check; probes in flight are abandoned.
func (c *Checker) Close() {
	c.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	for k, ch := range c.checks {
		ch.gone = true
		ch.stop()
		delete(c.checks, k)
	}
}

// Active reports whether any origin is checked.
func (c *Checker) Active() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.checks) > 0
}

// Down returns the unhealthy origins, sorted.
func (c *Checker) Down() []Key {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Key
	for k, ch := range c.checks {
		if !ch.state.healthy {
			out = append(out, k)
		}
	}
	slices.SortFunc(out, compareKeys)
	return out
}

// Statuses returns the checked origins that are unhealthy or have
// consecutive failures, sorted.
func (c *Checker) Statuses() []Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Status
	for k, ch := range c.checks {
		st := ch.state
		if st.healthy && st.failures == 0 {
			continue
		}
		out = append(out, Status{
			Key: k, Healthy: st.healthy, ConsecutiveFailures: st.failures, LastFailureAt: st.lastFailureAt,
			LastError: st.lastError, LastErrorCode: st.lastCode, LastErrorParams: maps.Clone(st.lastParams),
		})
	}
	slices.SortFunc(out, func(a, b Status) int { return compareKeys(a.Key, b.Key) })
	return out
}

// TTL is how long the data plane keeps the marks of a push: three of the
// longest intervals, at least 90 seconds, so that the marks of an agent
// that stopped pushing expire while a live agent refreshes them in time.
func (c *Checker) TTL() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	ttl := minMarkTTL
	for _, ch := range c.checks {
		ttl = max(ttl, 3*ch.spec.check.Interval)
	}
	return ttl
}

// state is the health of a checked origin.
type state struct {
	healthy             bool
	failures, successes uint32 // consecutive
	lastFailureAt       time.Time
	lastError, lastCode string
	lastParams          map[string]string
}

// record applies a probe result and reports whether the origin turned
// healthy or unhealthy.
func (s *state) record(r result, now time.Time, healthyThreshold, unhealthyThreshold uint32) bool {
	if r.ok {
		s.failures = 0
		s.successes = min(s.successes+1, healthyThreshold)
		if !s.healthy && s.successes >= healthyThreshold {
			s.healthy = true
			return true
		}
		return false
	}
	s.successes = 0
	if s.failures < ^uint32(0) {
		s.failures++
	}
	s.lastFailureAt, s.lastError, s.lastCode, s.lastParams = now, r.err, r.code, r.params
	if s.healthy && s.failures >= unhealthyThreshold {
		s.healthy = false
		return true
	}
	return false
}

// result is the outcome of one probe.
type result struct {
	ok     bool
	code   string
	params map[string]string
	err    string
}

func failure(code string, params map[string]string, format string, args ...any) result {
	return result{code: code, params: params, err: fmt.Sprintf(format, args...)}
}

// timedOut reports whether err ends a probe because its time ran out.
func timedOut(ctx context.Context, err error) bool {
	var netErr net.Error
	return ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}

// probe checks an origin once.
func (c *Checker) probe(parent context.Context, sp spec, policy configir.AddressPolicy) result {
	ctx, cancel := context.WithTimeout(parent, sp.check.Timeout)
	defer cancel()
	timeout := failure(CodeTimeout, nil, "timeout after %s", sp.check.Timeout)

	addrs, fail := c.addresses(ctx, sp.address, policy)
	if fail != nil {
		return *fail
	}
	var conn net.Conn
	var dialErr error
	for _, ip := range addrs {
		conn, dialErr = c.opts.Dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(ip, uint16(sp.port)).String())
		if dialErr == nil || ctx.Err() != nil {
			break
		}
	}
	if conn == nil {
		if timedOut(ctx, dialErr) {
			return timeout
		}
		return failure(CodeConnectFailed, nil, "connect: %v", dialErr)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	alpn := "http/1.1"
	if sp.http2 {
		alpn = "h2"
	}
	if sp.scheme == configir.SchemeHTTPS {
		tc := tls.Client(conn, &tls.Config{
			ServerName:         sp.sni,
			RootCAs:            c.opts.RootCAs,
			InsecureSkipVerify: sp.insecure, //nolint:gosec // the pool's skip_tls_verify
			NextProtos:         []string{alpn},
		})
		if err := tc.HandshakeContext(ctx); err != nil {
			if timedOut(ctx, err) {
				return timeout
			}
			return failure(CodeTLSFailed, nil, "TLS handshake: %v", err)
		}
		// The data plane offers h2 alone and has no fallback either.
		if got := tc.ConnectionState().NegotiatedProtocol; sp.http2 && got != "h2" {
			return failure(CodeConnectFailed, nil, "origin does not speak HTTP/2 (ALPN %q)", got)
		}
		conn = tc
	}
	var resp *http.Response
	var err error
	if sp.http2 {
		resp, err = roundTripHTTP2(ctx, conn, sp)
	} else {
		resp, err = roundTripHTTP1(conn, sp)
	}
	if err != nil {
		if timedOut(ctx, err) {
			return timeout
		}
		return failure(CodeConnectFailed, nil, "%v", err)
	}
	// Closing the body would read it to the end; the deferred close of
	// the connection ends it instead.
	_, _ = io.CopyN(io.Discard, resp.Body, maxBody)
	if code := uint32(resp.StatusCode); code < sp.check.ExpectedStatusMin || code > sp.check.ExpectedStatusMax {
		return failure(CodeUpstreamStatus, map[string]string{"status": strconv.Itoa(resp.StatusCode)}, "HTTP %d", resp.StatusCode)
	}
	return result{ok: true}
}

// userAgent is the User-Agent of the probes.
var userAgent = "edgeweir-node-healthcheck/" + version.Version

// roundTripHTTP1 sends the probe's request over conn with HTTP/1.1 and
// reads the response header.
func roundTripHTTP1(conn net.Conn, sp spec) (*http.Response, error) {
	// Method, path and Host were validated (configir): printable ASCII
	// without spaces.
	req := sp.check.Method + " " + sp.check.Path + " HTTP/1.1\r\nHost: " + sp.host +
		"\r\nUser-Agent: " + userAgent + "\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: sp.check.Method})
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return resp, nil
}

// roundTripHTTP2 sends the probe's request over conn (TLS with h2
// negotiated, or plain for prior knowledge) with HTTP/2 and reads the
// response header. The path goes out as it is (:path), the Host as
// :authority.
func roundTripHTTP2(ctx context.Context, conn net.Conn, sp spec) (*http.Response, error) {
	var protocols http.Protocols
	dial := func(context.Context, string, string) (net.Conn, error) { return conn, nil }
	t := &http.Transport{Protocols: &protocols, DisableCompression: true}
	scheme := "http"
	if sp.scheme == configir.SchemeHTTPS {
		scheme = "https"
		protocols.SetHTTP2(true)
		t.DialTLSContext = dial
	} else {
		protocols.SetUnencryptedHTTP2(true)
		t.DialContext = dial
	}
	defer t.CloseIdleConnections()
	req := (&http.Request{
		Method: sp.check.Method,
		URL:    &url.URL{Scheme: scheme, Host: sp.host, Opaque: sp.check.Path},
		Header: http.Header{"User-Agent": {userAgent}, "Accept": {"*/*"}},
		Host:   sp.host,
	}).WithContext(ctx)
	resp, err := t.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP/2 request: %w", err)
	}
	return resp, nil
}

// addresses returns the addresses a probe of host may connect to, or the
// failure: dns_failed when the name does not resolve, address_forbidden
// when every address is a special-purpose one outside the allow list.
func (c *Checker) addresses(ctx context.Context, host string, policy configir.AddressPolicy) ([]netip.Addr, *result) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if policy.Forbidden(ip) {
			r := failure(CodeAddressForbidden, map[string]string{"address": ip.String()},
				"address %s is a special-purpose address outside the origin allow list", ip)
			return nil, &r
		}
		return []netip.Addr{ip}, nil
	}
	addrs, err := c.opts.Resolver.LookupNetIP(ctx, "ip4", host)
	if (err != nil || len(addrs) == 0) && c.opts.IPv6 {
		addrs, err = c.opts.Resolver.LookupNetIP(ctx, "ip6", host)
	}
	if err == nil && len(addrs) == 0 {
		err = errors.New("no address")
	}
	if err != nil {
		r := failure(CodeDNSFailed, map[string]string{"host": host}, "dns %s: %v", host, err)
		return nil, &r
	}
	var allowed []netip.Addr
	for _, ip := range addrs {
		if ip = ip.Unmap(); !policy.Forbidden(ip) {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		first := addrs[0].Unmap()
		r := failure(CodeAddressForbidden, map[string]string{"address": first.String()},
			"dns %s: every address (e.g. %s) is a special-purpose address outside the origin allow list", host, first)
		return nil, &r
	}
	return allowed, nil
}
