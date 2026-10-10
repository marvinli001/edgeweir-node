package imageconv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

// Defaults of the node's converter flags (ADR-0043).
const (
	DefaultMemory  int64 = 1 << 30
	DefaultTimeout       = 8 * time.Second
	// TransientTTL caps how long an original answered for want of a
	// conversion slot stays cached under the variant's key.
	TransientTTL = 60
	// slotWait is how long a conversion waits for a slot.
	slotWait = time.Second
)

// DefaultWorkers is min(4, max(1, CPUs / 2)).
func DefaultWorkers() int {
	return min(4, max(1, runtime.NumCPU()/2))
}

// Estimate returns the memory a conversion of pixels to format is
// assumed to need (measured peaks plus margin, ADR-0043).
func Estimate(format Format, pixels int64) int64 {
	if format == AVIF {
		return 160*pixels + 64<<20
	}
	return 48*pixels + 32<<20
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
	// with ChildCommand); tests run their own.
	Command func(ctx context.Context, args []string) *exec.Cmd
	Log     *slog.Logger
}

// Server is the image converter's HTTP handler.
type Server struct {
	cfg       Config
	transport *http.Transport
	lim       *limiter
}

// New returns a Server.
func New(cfg Config) *Server {
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	s := &Server{cfg: cfg, lim: newLimiter(cfg.Workers, cfg.Memory)}
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

// dropOnVariant are headers of the original that do not describe a
// variant.
var dropOnVariant = []string{"Content-Length", "Content-Type", "Etag", "Content-Md5", "Content-Digest", "Repr-Digest", "Digest"}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p, err := ParseHeader(r.Header.Get(Header))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if _, ok := s.cfg.Upstreams[p.Upstream]; !ok {
		http.Error(w, "unknown origin layer", http.StatusBadGateway)
		return
	}
	out, stripped := s.outgoing(r, p)
	resp, err := s.transport.RoundTrip(out)
	if err != nil {
		// No answer from the origin layer (it may close on purpose so
		// that the edge serves a stale copy): no answer from here either.
		panic(http.ErrAbortHandler)
	}
	defer resp.Body.Close()
	log := s.cfg.Log.With("site", r.Header.Get("X-Edgeweir-Site"), "format", string(p.Format))
	kind, ok := s.candidate(r, resp, p)
	if !ok {
		s.pass(w, resp, nil, p, stripped, false)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, p.MaxSize+1))
	if err != nil {
		panic(http.ErrAbortHandler)
	}
	if int64(len(body)) > p.MaxSize || int64(len(body)) < p.MinSize {
		s.pass(w, resp, body, p, stripped, false)
		return
	}
	info, err := Inspect(body, kind)
	if err != nil {
		log.Debug("image kept", "reason", err.Error())
		s.pass(w, resp, body, p, stripped, false)
		return
	}
	estimate := Estimate(p.Format, info.Pixels())
	if info.Pixels() > p.MaxPixels || estimate > s.cfg.Memory {
		log.Debug("image kept", "reason", "over the pixel or memory limit", "pixels", info.Pixels())
		s.pass(w, resp, body, p, stripped, false)
		return
	}
	wait, cancel := context.WithTimeout(r.Context(), slotWait)
	acquired := s.lim.acquire(wait, estimate)
	cancel()
	if !acquired {
		log.Info("image kept for now: no conversion slot")
		s.pass(w, resp, body, p, stripped, true)
		return
	}
	variant, err := s.run(r.Context(), log, kind, p, info, body, estimate)
	s.lim.release(estimate)
	if err != nil || len(variant) >= len(body) {
		if err == nil {
			log.Debug("image kept", "reason", "the variant is not smaller", "in", len(body), "out", len(variant))
		}
		s.pass(w, resp, body, p, stripped, false)
		return
	}
	h := w.Header()
	copyHeaders(h, resp.Header, dropOnVariant...)
	h.Set("Content-Type", p.Format.MediaType())
	h.Set("Content-Length", strconv.Itoa(len(variant)))
	if etag := variantETag(resp.Header.Get("Etag"), p.Format); etag != "" {
		h.Set("Etag", etag)
	}
	h.Set(SavedHeader, strconv.Itoa(len(body)-len(variant)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(variant)
	}
}

// outgoing returns the request for the origin layer: the same method, raw
// URI and headers, without X-Edgeweir-Image; If-None-Match loses the
// variant's suffix (revalidation of a cached variant), stripped reports
// whether it had one.
func (s *Server) outgoing(r *http.Request, p Params) (*http.Request, bool) {
	out := r.Clone(r.Context())
	out.RequestURI = ""
	raw, query, _ := strings.Cut(r.RequestURI, "?")
	u := &url.URL{Scheme: "http", Host: p.Upstream, RawQuery: query, ForceQuery: strings.Contains(r.RequestURI, "?") && query == ""}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		u.Opaque = raw
	} else {
		u.Path, u.RawPath = r.URL.Path, r.URL.RawPath
	}
	out.URL = u
	out.Host = r.Host
	out.Header.Del(Header)
	for _, name := range hopHeaders {
		out.Header.Del(name)
	}
	// No User-Agent stays none (Go would add its own).
	if _, ok := out.Header["User-Agent"]; !ok {
		out.Header["User-Agent"] = []string{""}
	}
	stripped := false
	if inm := out.Header.Get("If-None-Match"); inm != "" {
		var tags []string
		for _, tag := range strings.Split(inm, ",") {
			tag = strings.TrimSpace(tag)
			if original, ok := originalETag(tag, p.Format); ok {
				tag, stripped = original, true
			}
			tags = append(tags, tag)
		}
		out.Header.Set("If-None-Match", strings.Join(tags, ", "))
	}
	return out, stripped
}

// candidate reports whether the origin layer's answer may be converted and
// its source type: a 200 to a GET, not encoded, of a source type the site
// converts, within the size limits when its length is known.
func (s *Server) candidate(r *http.Request, resp *http.Response, p Params) (Kind, bool) {
	if r.Method != http.MethodGet || resp.StatusCode != http.StatusOK {
		return "", false
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return "", false
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return "", false
	}
	var kind Kind
	switch media {
	case "image/jpeg", "image/pjpeg":
		kind = JPEG
	case "image/png":
		kind = PNG
	default:
		return "", false
	}
	if !p.Accepts(kind) {
		return "", false
	}
	if n := resp.ContentLength; n >= 0 && (n < p.MinSize || n > p.MaxSize) {
		return "", false
	}
	return kind, true
}

// pass answers with the origin layer's response: head (already read) and
// the rest of the body. transient caps the cache time of an original that
// waits for another try. A 304 to a stripped revalidation gets the
// variant's ETag back.
func (s *Server) pass(w http.ResponseWriter, resp *http.Response, head []byte, p Params, stripped, transient bool) {
	h := w.Header()
	copyHeaders(h, resp.Header)
	if head != nil && resp.ContentLength < 0 {
		h.Del("Content-Length")
	}
	if resp.StatusCode == http.StatusNotModified && stripped {
		if etag := variantETag(resp.Header.Get("Etag"), p.Format); etag != "" {
			h.Set("Etag", etag)
		}
	}
	if transient {
		h.Set("X-Accel-Expires", transientTTLValue(resp.Header.Get("X-Accel-Expires")))
	}
	w.WriteHeader(resp.StatusCode)
	if len(head) > 0 {
		if _, err := w.Write(head); err != nil {
			panic(http.ErrAbortHandler)
		}
	}
	if _, err := io.Copy(flushWriter{w}, resp.Body); err != nil {
		// A truncated answer must not look complete to the edge's cache.
		panic(http.ErrAbortHandler)
	}
}

// transientTTLValue caps an X-Accel-Expires value at TransientTTL seconds
// (0, not cached, stays 0).
func transientTTLValue(v string) string {
	if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= TransientTTL {
		return v
	}
	return strconv.Itoa(TransientTTL)
}

// run converts body in a child process within the timeout.
func (s *Server) run(ctx context.Context, log *slog.Logger, kind Kind, p Params, info Info, body []byte, estimate int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	cmd := s.cfg.Command(ctx, childArgs(kind, p.Format, p.Quality, info, estimate, p.MaxSize))
	cmd.Stdin = bytes.NewReader(body)
	var stdout bytes.Buffer
	stderr := &limitedBuffer{max: 2048}
	cmd.Stdout, cmd.Stderr = &stdout, stderr
	cmd.WaitDelay = time.Second
	start := time.Now()
	err := cmd.Run()
	wall := time.Since(start)
	var cpu time.Duration
	if st := cmd.ProcessState; st != nil {
		cpu = st.UserTime() + st.SystemTime()
	}
	attrs := []any{"kind", string(kind), "in", len(body), "pixels", info.Pixels(), "ms", wall.Milliseconds(), "cpu_ms", cpu.Milliseconds()}
	if err != nil {
		var exit *exec.ExitError
		switch {
		case ctx.Err() != nil:
			log.Warn("image conversion timed out", append(attrs, "timeout", s.cfg.Timeout.String())...)
		case errors.As(err, &exit) && exit.ExitCode() == exitUnsupported:
			log.Debug("image kept", append(attrs, "reason", strings.TrimSpace(stderr.String()))...)
		default:
			log.Warn("image conversion failed", append(attrs, "err", err.Error(), "stderr", strings.TrimSpace(stderr.String()))...)
		}
		return nil, err
	}
	log.Info("image converted", append(attrs, "out", stdout.Len())...)
	return stdout.Bytes(), nil
}

// copyHeaders copies src to dst without hop-by-hop headers and except.
// The origin layer's own X-Edgeweir-Image-Saved never passes (an origin
// could set one).
func copyHeaders(dst, src http.Header, except ...string) {
	skip := slices.Concat(hopHeaders, except, []string{SavedHeader})
	for name, values := range src {
		if !slices.ContainsFunc(skip, func(e string) bool { return strings.EqualFold(name, e) }) {
			dst[name] = append([]string(nil), values...)
		}
	}
}

// variantETag returns the variant's entity tag for an original's: the
// opaque tag with "-<format>" appended (W/ kept); "" for none or a
// malformed tag.
func variantETag(etag string, f Format) string {
	weak := strings.HasPrefix(etag, "W/")
	tag := strings.TrimPrefix(etag, "W/")
	if len(tag) < 2 || tag[0] != '"' || tag[len(tag)-1] != '"' || strings.Contains(tag[1:len(tag)-1], `"`) {
		return ""
	}
	out := tag[:len(tag)-1] + "-" + string(f) + `"`
	if weak {
		out = "W/" + out
	}
	return out
}

// originalETag undoes variantETag for f.
func originalETag(etag string, f Format) (string, bool) {
	suffix := "-" + string(f) + `"`
	if !strings.HasSuffix(etag, suffix) || !strings.HasPrefix(strings.TrimPrefix(etag, "W/"), `"`) {
		return "", false
	}
	return strings.TrimSuffix(etag, suffix) + `"`, true
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

// limitedBuffer keeps the first max bytes written to it.
type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.max - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

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
