package mdconv

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Defaults of the node's converter flags.
const (
	DefaultMemory  int64 = 512 << 20
	DefaultTimeout       = 5 * time.Second
	// TransientTTL caps how long HTML answered for want of a conversion
	// slot stays cached under the Markdown variant's key.
	TransientTTL = 60
	// slotWait is how long a conversion waits for a slot.
	slotWait = time.Second
)

// DefaultWorkers is min(4, max(1, CPUs / 2)).
func DefaultWorkers() int {
	return min(4, max(1, runtime.NumCPU()/2))
}

// Estimate returns the memory a conversion of n bytes of HTML is assumed to
// need: the parsed tree, its Markdown and the Go runtime (measured peaks of
// real pages plus margin).
func Estimate(n int64) int64 {
	return 24*n + 48<<20
}

// Config configures a Server.
type Config struct {
	// Upstreams maps the origin layers' upstream names to their sockets.
	Upstreams map[string]string
	// Workers bounds concurrent conversions, Memory the sum of their
	// estimates; Timeout bounds one conversion (the child is killed).
	Workers int
	Memory  int64
	Timeout time.Duration
	// Command returns the child process for args (the agent's own binary
	// with ChildCommand) bound to ctx; tests run their own.
	Command func(ctx context.Context, args []string) *exec.Cmd
	Log     *slog.Logger
}

// Server is the Markdown converter's HTTP handler.
type Server struct {
	cfg       Config
	transport *http.Transport
	lim       *limiter
	// buffers bounds the HTML read into memory before a slot is taken
	// (Memory bytes in all).
	buffers *limiter
}

// New returns a Server.
func New(cfg Config) *Server {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	s := &Server{cfg: cfg, lim: newLimiter(cfg.Workers, cfg.Memory), buffers: newLimiter(math.MaxInt, cfg.Memory)}
	s.transport = &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			sock, ok := cfg.Upstreams[host]
			if !ok {
				return nil, fmt.Errorf("unknown origin layer %q", host)
			}
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		// The origin layer closes connections on purpose (stale-if-error);
		// a cached connection would turn that into a retry.
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 256 << 10,
	}
	return s
}

// Close releases idle connections.
func (s *Server) Close() { s.transport.CloseIdleConnections() }

// hopHeaders are not copied between the hops.
var hopHeaders = []string{"Connection", "Keep-Alive", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

// conditionalHeaders would let the origin answer with less than the whole
// document; a Markdown variant has no validators of its own to compare.
var conditionalHeaders = []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since", "Accept-Encoding"}

// dropOnConverted are headers of the HTML that do not describe its
// Markdown (validators included: conditional requests cannot be honoured
// for converted responses).
var dropOnConverted = []string{"Content-Length", "Content-Type", "Content-Encoding", "Content-Range", "Accept-Ranges",
	"Etag", "Last-Modified", "Content-Md5", "Content-Digest", "Repr-Digest", "Digest"}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	upstream, err := ParseHeader(r.Header.Get(Header))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if _, ok := s.cfg.Upstreams[upstream]; !ok {
		http.Error(w, "unknown origin layer", http.StatusBadGateway)
		return
	}
	head := r.Method == http.MethodHead
	resp, err := s.transport.RoundTrip(s.outgoing(r, upstream))
	if err != nil {
		// No answer from the origin layer (it may close on purpose so
		// that the edge serves a stale copy): no answer from here either.
		panic(http.ErrAbortHandler)
	}
	defer resp.Body.Close()
	log := s.cfg.Log.With("site", r.Header.Get("X-Edgeweir-Site"))
	encoded, ok := candidate(resp)
	if !ok {
		s.pass(w, resp, nil, head, false)
		return
	}
	// The document's length, or the most it may have, comes out of the
	// buffer budget while it is held.
	reserve := int64(MaxInput + 1)
	if !encoded && resp.ContentLength >= 0 {
		reserve = resp.ContentLength
	}
	if encoded {
		// The encoded bytes are kept too, to pass them on unconverted.
		reserve *= 2
	}
	wait, cancel := context.WithTimeout(r.Context(), slotWait)
	buffered := s.buffers.acquire(wait, reserve)
	cancel()
	if !buffered {
		log.Info("HTML kept for now: no buffer room")
		s.pass(w, resp, nil, head, true)
		return
	}
	release := sync.OnceFunc(func() { s.buffers.release(reserve) })
	defer release()
	raw, doc, err := s.read(resp, encoded)
	switch {
	case errors.Is(err, errSlowOriginal):
		release()
		log.Info("HTML kept for now: origin too slow")
		s.pass(w, resp, raw, head, true)
		return
	case errors.Is(err, errTooLarge), errors.Is(err, errDecode):
		log.Debug("HTML kept", "reason", err.Error())
		s.pass(w, resp, raw, head, false)
		return
	case err != nil:
		panic(http.ErrAbortHandler)
	}
	estimate := Estimate(int64(len(doc)))
	if estimate > s.cfg.Memory {
		log.Debug("HTML kept", "reason", "over the memory limit", "in", len(doc))
		s.pass(w, resp, raw, head, false)
		return
	}
	wait, cancel = context.WithTimeout(r.Context(), slotWait)
	acquired := s.lim.acquire(wait, estimate)
	cancel()
	if !acquired {
		log.Info("HTML kept for now: no conversion slot")
		s.pass(w, resp, raw, head, true)
		return
	}
	md, err := s.run(r.Context(), log, pageURL(r), resp.Header.Get("Content-Type"), doc, estimate)
	s.lim.release(estimate)
	if err != nil {
		s.pass(w, resp, raw, head, false)
		return
	}
	h := w.Header()
	copyHeaders(h, resp.Header, dropOnConverted...)
	h.Set("Content-Type", "text/markdown; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(md)))
	h.Set(TokensHeader, strconv.Itoa(EstimateTokens(md)))
	if h.Get("Content-Signal") == "" {
		h.Set("Content-Signal", ContentSignal)
	}
	h.Set(ConvertedHeader, "1")
	w.WriteHeader(resp.StatusCode)
	if !head {
		_, _ = w.Write(md)
	}
}

// outgoing returns the request for the origin layer: a GET (HEAD too: the
// Markdown's headers depend on the whole document) of the same raw URI with
// the same headers, without X-Edgeweir-Markdown, conditions, ranges or
// Accept-Encoding (the origin sends identity, gzip is decoded when it does
// not).
func (s *Server) outgoing(r *http.Request, upstream string) *http.Request {
	out := r.Clone(r.Context())
	out.Method = http.MethodGet
	out.RequestURI = ""
	raw, query, _ := strings.Cut(r.RequestURI, "?")
	u := &url.URL{Scheme: "http", Host: upstream, RawQuery: query, ForceQuery: strings.Contains(r.RequestURI, "?") && query == ""}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		u.Opaque = raw
	} else {
		u.Path, u.RawPath = r.URL.Path, r.URL.RawPath
	}
	out.URL = u
	out.Host = r.Host
	out.Header.Del(Header)
	for _, name := range slices.Concat(hopHeaders, conditionalHeaders) {
		out.Header.Del(name)
	}
	// No User-Agent stays none (Go would add its own).
	if _, ok := out.Header["User-Agent"]; !ok {
		out.Header["User-Agent"] = []string{""}
	}
	return out
}

// candidate reports whether the origin layer's answer may be converted,
// and whether it is gzip-encoded: a 2xx with content (not 204, 205 or 206)
// of type text/html or application/xhtml+xml, identity or gzip, within
// MaxInput when its identity length is known.
func candidate(resp *http.Response) (encoded, ok bool) {
	switch {
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return false, false
	case resp.StatusCode == http.StatusNoContent, resp.StatusCode == http.StatusResetContent, resp.StatusCode == http.StatusPartialContent:
		return false, false
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || (media != "text/html" && media != "application/xhtml+xml") {
		return false, false
	}
	switch ce := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))); ce {
	case "", "identity":
	case "gzip", "x-gzip":
		encoded = true
	default:
		return false, false
	}
	if !encoded && resp.ContentLength > MaxInput {
		return false, false
	}
	return encoded, true
}

// errDecode is a gzip body that does not decode.
var errDecode = errors.New("gzip body does not decode")

// read reads the document within the conversion timeout: raw is what came
// from the origin layer (for passing it on), doc the HTML (raw itself unless
// gzip-encoded). On errors raw holds what was read.
func (s *Server) read(resp *http.Response, encoded bool) (raw, doc []byte, err error) {
	src := &deadlineReader{r: resp.Body, deadline: time.Now().Add(s.cfg.Timeout)}
	if !encoded {
		doc, err = readAllLimited(src, MaxInput)
		return doc, doc, err
	}
	var buf bytes.Buffer
	tee := io.TeeReader(io.LimitReader(src, MaxInput+1), &buf)
	zr, err := gzip.NewReader(tee)
	if err == nil {
		doc, err = readAllLimited(zr, MaxInput)
	}
	if err == nil {
		// The rest of the encoded stream (a trailer, a second member) is
		// part of the original too.
		if _, err = io.Copy(io.Discard, tee); err == nil && buf.Len() > MaxInput {
			err = errTooLarge
		}
	}
	switch {
	case err == nil, errors.Is(err, errSlowOriginal), errors.Is(err, errTooLarge):
	case src.err != nil && !errors.Is(src.err, io.EOF):
		// The origin layer's stream broke.
		err = src.err
	default:
		err = errDecode
	}
	return buf.Bytes(), doc, err
}

// pageURL returns the request's absolute URL (the edge's scheme from
// X-Forwarded-Proto, its Host and raw URI).
func pageURL(r *http.Request) string {
	scheme := "http"
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.RequestURI
}

// pass answers with the origin layer's response: head (already read) and
// the rest of the body. transient caps the cache time of HTML that waits
// for another try.
func (s *Server) pass(w http.ResponseWriter, resp *http.Response, read []byte, head, transient bool) {
	h := w.Header()
	copyHeaders(h, resp.Header)
	if transient {
		h.Set("X-Accel-Expires", transientTTLValue(resp.Header.Get("X-Accel-Expires")))
	}
	w.WriteHeader(resp.StatusCode)
	if head {
		return
	}
	if len(read) > 0 {
		if _, err := w.Write(read); err != nil {
			panic(http.ErrAbortHandler)
		}
	}
	if _, err := io.Copy(flushWriter{w}, resp.Body); err != nil {
		// A truncated answer must not look complete to the edge's cache.
		panic(http.ErrAbortHandler)
	}
}

// errSlowOriginal ends reading a document past its deadline.
var errSlowOriginal = errors.New("origin too slow")

// deadlineReader fails a read that starts after the deadline; a read that
// waits for data is bounded by the origin layer's own timeouts.
// It records the underlying reader's last error.
type deadlineReader struct {
	r        io.Reader
	deadline time.Time
	err      error
}

func (d *deadlineReader) Read(p []byte) (int, error) {
	if time.Now().After(d.deadline) {
		return 0, errSlowOriginal
	}
	n, err := d.r.Read(p)
	if err != nil {
		d.err = err
	}
	return n, err
}

// transientTTLValue caps an X-Accel-Expires value at TransientTTL seconds
// (0, not cached, stays 0).
func transientTTLValue(v string) string {
	if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= TransientTTL {
		return v
	}
	return strconv.Itoa(TransientTTL)
}

// run converts doc in a child process within the timeout; its output is
// bounded by four times the input plus 64 KiB (Markdown is shorter than
// its HTML; frontmatter and JSON-LD are copied from it).
func (s *Server) run(ctx context.Context, log *slog.Logger, page, contentType string, doc []byte, estimate int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	cmd := s.cfg.Command(ctx, childArgs(page, contentType, estimate, MaxInput))
	cmd.Stdin = bytes.NewReader(doc)
	stdout := &boundedBuffer{max: 4*int64(len(doc)) + 64<<10, over: cancel}
	stderr := &limitedBuffer{max: 2048}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = time.Second
	start := time.Now()
	err := cmd.Run()
	wall := time.Since(start)
	var cpu time.Duration
	if st := cmd.ProcessState; st != nil {
		cpu = st.UserTime() + st.SystemTime()
	}
	attrs := []any{"in", len(doc), "ms", wall.Milliseconds(), "cpu_ms", cpu.Milliseconds()}
	if err == nil && stdout.exceeded {
		err = errOutputBound
	}
	if err != nil {
		var exit *exec.ExitError
		switch {
		case stdout.exceeded:
			log.Warn("Markdown conversion failed", append(attrs, "err", errOutputBound.Error())...)
			return nil, errOutputBound
		case ctx.Err() != nil:
			log.Warn("Markdown conversion timed out", append(attrs, "timeout", s.cfg.Timeout.String())...)
		case errors.As(err, &exit) && exit.ExitCode() == exitUnsupported:
			log.Debug("HTML kept", append(attrs, "reason", strings.TrimSpace(stderr.String()))...)
		default:
			log.Warn("Markdown conversion failed", append(attrs, "err", err.Error(), "stderr", strings.TrimSpace(stderr.String()))...)
		}
		return nil, err
	}
	log.Info("Markdown converted", append(attrs, "out", len(stdout.Bytes()))...)
	return stdout.Bytes(), nil
}

var errOutputBound = errors.New("output over its bound")

// copyHeaders copies src to dst without hop-by-hop headers and except.
// An origin's own X-Edgeweir-Markdown-Converted never passes.
func copyHeaders(dst, src http.Header, except ...string) {
	skip := slices.Concat(hopHeaders, except, []string{ConvertedHeader})
	for name, values := range src {
		if !slices.ContainsFunc(skip, func(e string) bool { return strings.EqualFold(name, e) }) {
			dst[name] = append([]string(nil), values...)
		}
	}
}

// flushWriter flushes after every write so that passed-through bodies
// stream.
type flushWriter struct{ w http.ResponseWriter }

func (f flushWriter) Write(b []byte) (int, error) {
	n, err := f.w.Write(b)
	if err == nil {
		err = http.NewResponseController(f.w).Flush()
	}
	return n, err
}

// boundedBuffer keeps what is written up to max bytes; one more byte
// marks it exceeded and calls over (which kills the child).
type boundedBuffer struct {
	buf      bytes.Buffer
	max      int64
	exceeded bool
	over     func()
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.exceeded {
		return 0, errOutputBound
	}
	if int64(b.buf.Len()+len(p)) > b.max {
		b.exceeded = true
		b.over()
		return 0, errOutputBound
	}
	return b.buf.Write(p)
}

// Bytes returns what was kept.
func (b *boundedBuffer) Bytes() []byte { return b.buf.Bytes() }

// limitedBuffer keeps the first max bytes written to it and drops the
// rest.
type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.buf.Len(); room > 0 {
		b.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

// String returns what was kept.
func (b *limitedBuffer) String() string { return b.buf.String() }

// limiter admits conversions while fewer than workers run and their
// memory estimates fit.
type limiter struct {
	mu      sync.Mutex
	workers int
	memory  int64
	busy    int
	used    int64
	wake    chan struct{}
}

func newLimiter(workers int, memory int64) *limiter {
	return &limiter{workers: workers, memory: memory, wake: make(chan struct{})}
}

func (l *limiter) acquire(ctx context.Context, mem int64) bool {
	for {
		l.mu.Lock()
		if l.busy < l.workers && l.used+mem <= l.memory {
			l.busy++
			l.used += mem
			l.mu.Unlock()
			return true
		}
		wake := l.wake
		l.mu.Unlock()
		select {
		case <-wake:
		case <-ctx.Done():
			return false
		}
	}
}

func (l *limiter) release(mem int64) {
	l.mu.Lock()
	l.busy--
	l.used -= mem
	close(l.wake)
	l.wake = make(chan struct{})
	l.mu.Unlock()
}
