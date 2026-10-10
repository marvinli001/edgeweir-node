package imageconv

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain runs the child when the server tests start the test binary as
// edgeweir-node imgconv.
func TestMain(m *testing.M) {
	if os.Getenv("IMAGECONV_TEST_CHILD") == "1" {
		os.Exit(RunChild(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// childCommand runs the test binary as the child.
func childCommand(ctx context.Context, args []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = []string{"IMAGECONV_TEST_CHILD=1", "GOMAXPROCS=1"}
	return cmd
}

// shCommand runs a shell script as the child (reading stdin).
func shCommand(script string) func(context.Context, []string) *exec.Cmd {
	return func(ctx context.Context, _ []string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", script)
	}
}

// originLayer is a fake origin layer on a unix socket; handler answers and
// requests records what arrived.
type originLayer struct {
	sock     string
	mu       sync.Mutex
	requests []*http.Request
	rawLines []string
}

func newOriginLayer(t *testing.T, handler http.HandlerFunc) *originLayer {
	t.Helper()
	dir, err := os.MkdirTemp("", "ic")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	o := &originLayer{sock: filepath.Join(dir, "o.sock")}
	l, err := net.Listen("unix", o.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		o.requests = append(o.requests, r.Clone(context.Background()))
		o.rawLines = append(o.rawLines, r.Method+" "+r.RequestURI)
		o.mu.Unlock()
		handler(w, r)
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return o
}

func (o *originLayer) last() *http.Request {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.requests[len(o.requests)-1]
}

// converter starts a Server in front of origin (as edgeweir_origin_verify)
// and returns a function that sends a request through it.
func converter(t *testing.T, o *originLayer, cfg Config) (*Server, func(*http.Request) *http.Response) {
	t.Helper()
	cfg.Upstreams = map[string]string{"edgeweir_origin_verify": o.sock}
	if cfg.Workers == 0 {
		cfg.Workers = 2
	}
	if cfg.Memory == 0 {
		cfg.Memory = DefaultMemory
	}
	if cfg.Command == nil {
		cfg.Command = childCommand
	}
	s := New(cfg)
	dir, err := os.MkdirTemp("", "ic")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "i.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: s}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close(); s.Close() })
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
		DisableCompression: true, DisableKeepAlives: true,
	}}
	return s, func(r *http.Request) *http.Response {
		t.Helper()
		resp, err := client.Do(r)
		if err != nil {
			t.Fatalf("%s %s: %v", r.Method, r.URL, err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
}

const header = "webp;q=80;min=0;max=10485760;px=16000000;src=jpeg,png;up=edgeweir_origin_verify"

func variantRequest(t *testing.T, method, uri, value string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, "http://img.test"+uri, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set(Header, value)
	r.Header.Set("X-Edgeweir-Site", "site-1")
	// Like a client without one: the test client sends none either.
	r.Header["User-Agent"] = []string{""}
	return r
}

func body(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// serveImage answers like the origin layer with an image.
func serveImage(data []byte, contentType string, extra map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		for k, v := range extra {
			w.Header().Set(k, v)
		}
		w.Write(data)
	}
}

func TestServerConverts(t *testing.T) {
	jpg := encodeJPEG(t, testImage(160, 120, false))
	o := newOriginLayer(t, serveImage(jpg, "image/jpeg", map[string]string{
		"Etag": `"v1"`, "X-Accel-Expires": "3600", "Cache-Control": "public, max-age=60",
		"Last-Modified": "Mon, 05 Oct 2026 10:00:00 GMT", "Content-Md5": "x", "X-Edgeweir-Upstream": "10.0.0.1:80",
	}))
	// Real conversions; without the release build tags AVIF runs on wazero
	// (compiled on each start), slow under the race detector.
	_, do := converter(t, o, Config{Timeout: 2 * time.Minute})
	for _, format := range []Format{WebP, AVIF} {
		value := strings.Replace(header, "webp", string(format), 1)
		resp := do(variantRequest(t, "GET", "/a%2Fb/photo.jpg?w=1&x=%20", value))
		got := body(t, resp)
		h := resp.Header
		if resp.StatusCode != 200 || h.Get("Content-Type") != format.MediaType() || h.Get("Content-Length") != strconv.Itoa(len(got)) {
			t.Fatalf("%s: %d %v", format, resp.StatusCode, h)
		}
		if h.Get("Etag") != `"v1-`+string(format)+`"` || h.Get("X-Accel-Expires") != "3600" || h.Get("Cache-Control") != "public, max-age=60" ||
			h.Get("Last-Modified") == "" || h.Get("Content-Md5") != "" || h.Get("X-Edgeweir-Upstream") != "10.0.0.1:80" {
			t.Fatalf("%s headers: %v", format, h)
		}
		if saved, _ := strconv.Atoi(h.Get(SavedHeader)); saved != len(jpg)-len(got) || saved <= 0 {
			t.Fatalf("%s: saved %q, original %d, variant %d", format, h.Get(SavedHeader), len(jpg), len(got))
		}
		if format == WebP && string(got[8:12]) != "WEBP" || format == AVIF && string(got[4:12]) != "ftypavif" {
			t.Fatalf("%s: wrong body", format)
		}
	}
	// The request reached the origin layer as it came, without the
	// converter's header, a User-Agent or an Accept-Encoding of its own.
	r := o.last()
	if o.rawLines[0] != "GET /a%2Fb/photo.jpg?w=1&x=%20" || r.Host != "img.test" || r.Header.Get("X-Edgeweir-Site") != "site-1" {
		t.Fatalf("forwarded %q host %q %v", o.rawLines[0], r.Host, r.Header)
	}
	if _, ok := r.Header[Header]; ok {
		t.Fatal("X-Edgeweir-Image reached the origin layer")
	}
	if _, ok := r.Header["User-Agent"]; ok {
		t.Fatalf("a User-Agent was added: %q", r.Header.Get("User-Agent"))
	}
	if _, ok := r.Header["Accept-Encoding"]; ok {
		t.Fatal("an Accept-Encoding was added")
	}
}

func TestServerKeepsOriginals(t *testing.T) {
	jpg := encodeJPEG(t, testImage(160, 120, false))
	pngData := encodePNG(t, testImage(40, 30, true))
	html := []byte("<html>" + strings.Repeat("x", 5000) + "</html>")
	routes := map[string]http.HandlerFunc{
		"/page":    serveImage(html, "text/html", nil),
		"/missing": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", 404) },
		"/encoded": serveImage(jpg, "image/jpeg", map[string]string{"Content-Encoding": "gzip"}),
		"/png":     serveImage(pngData, "image/png", nil),
		"/big.jpg": serveImage(jpg, "image/jpeg", nil),
		"/p3.jpg":  serveImage(withSegment(jpg, 0xE2, iccSegments(iccProfile("RGB ", "Display P3", false), 1000)[0]), "image/jpeg", nil),
		"/forged":  serveImage(html, "text/html", map[string]string{SavedHeader: "999999"}),
		"/chunked": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/jpeg")
			w.(http.Flusher).Flush()
			w.Write(jpg)
		},
	}
	o := newOriginLayer(t, func(w http.ResponseWriter, r *http.Request) { routes[r.URL.Path](w, r) })
	_, do := converter(t, o, Config{})
	for _, c := range []struct {
		path, header string
		status       int
		want         []byte
	}{
		{"/page", header, 200, html},
		{"/missing", header, 404, nil},
		{"/encoded", header, 200, jpg},
		{"/png", strings.Replace(header, "src=jpeg,png", "src=jpeg", 1), 200, pngData},
		{"/big.jpg", strings.Replace(header, "max=10485760", "max=1000", 1), 200, jpg},
		{"/big.jpg", strings.Replace(header, "min=0", "min=1000000", 1), 200, jpg},
		{"/chunked", strings.Replace(header, "max=10485760", "max=1000", 1), 200, jpg},
		{"/big.jpg", strings.Replace(header, "px=16000000", "px=19199", 1), 200, jpg},
		{"/p3.jpg", header, 200, nil},
		{"/forged", header, 200, html},
	} {
		resp := do(variantRequest(t, "GET", c.path, c.header))
		got := body(t, resp)
		if resp.StatusCode != c.status || (c.want != nil && !bytes.Equal(got, c.want)) {
			t.Errorf("%s (%s): %d, %d bytes", c.path, c.header, resp.StatusCode, len(got))
		}
		if ct := resp.Header.Get("Content-Type"); strings.HasPrefix(ct, "image/webp") {
			t.Errorf("%s converted", c.path)
		}
		if resp.Header.Get(SavedHeader) != "" {
			t.Errorf("%s: %s %q", c.path, SavedHeader, resp.Header.Get(SavedHeader))
		}
	}
	// Over the node's memory: the estimate for 160 x 120 is above 1 KiB.
	o2 := newOriginLayer(t, serveImage(jpg, "image/jpeg", nil))
	_, do2 := converter(t, o2, Config{Memory: 1 << 10})
	if resp := do2(variantRequest(t, "GET", "/x.jpg", header)); resp.Header.Get("Content-Type") != "image/jpeg" || !bytes.Equal(body(t, resp), jpg) {
		t.Fatal("an image over the memory limit was converted")
	}
}

func TestServerFailuresKeepOriginals(t *testing.T) {
	jpg := encodeJPEG(t, testImage(160, 120, false))
	for name, c := range map[string]struct {
		cfg Config
		ttl string
	}{
		"child fails":         {Config{Command: shCommand("cat >/dev/null; exit 1")}, "120"},
		"variant not smaller": {Config{Command: shCommand("cat; cat /dev/zero | head -c 100")}, "120"},
		"timeout":             {Config{Command: shCommand("cat >/dev/null; sleep 5"), Timeout: 200 * time.Millisecond}, "120"},
	} {
		o := newOriginLayer(t, serveImage(jpg, "image/jpeg", map[string]string{"X-Accel-Expires": "120"}))
		_, do := converter(t, o, c.cfg)
		start := time.Now()
		resp := do(variantRequest(t, "GET", "/a.jpg", header))
		if got := body(t, resp); !bytes.Equal(got, jpg) || resp.Header.Get("Content-Type") != "image/jpeg" || resp.Header.Get("X-Accel-Expires") != c.ttl {
			t.Errorf("%s: %d bytes, %v", name, len(got), resp.Header)
		}
		if time.Since(start) > 3*time.Second {
			t.Errorf("%s took %v", name, time.Since(start))
		}
	}
}

func TestServerBusy(t *testing.T) {
	jpg := encodeJPEG(t, testImage(160, 120, false))
	for _, c := range []struct{ accel, want string }{{"3600", "60"}, {"30", "30"}, {"0", "0"}, {"", "60"}} {
		extra := map[string]string{}
		if c.accel != "" {
			extra["X-Accel-Expires"] = c.accel
		}
		o := newOriginLayer(t, serveImage(jpg, "image/jpeg", extra))
		s, do := converter(t, o, Config{Workers: 1})
		// The only slot is taken.
		if !s.lim.acquire(context.Background(), 1) {
			t.Fatal("acquire")
		}
		resp := do(variantRequest(t, "GET", "/a.jpg", header))
		s.lim.release(1)
		if got := body(t, resp); !bytes.Equal(got, jpg) || resp.Header.Get("X-Accel-Expires") != c.want {
			t.Errorf("busy with X-Accel-Expires %q: %q", c.accel, resp.Header.Get("X-Accel-Expires"))
		}
	}
}

func TestServerRevalidation(t *testing.T) {
	jpg := encodeJPEG(t, testImage(160, 120, false))
	o := newOriginLayer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Etag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(304)
			return
		}
		serveImage(jpg, "image/jpeg", nil)(w, r)
	})
	_, do := converter(t, o, Config{})
	r := variantRequest(t, "GET", "/a.jpg", header)
	r.Header.Set("If-None-Match", `"v1-webp"`)
	resp := do(r)
	if resp.StatusCode != 304 || resp.Header.Get("Etag") != `"v1-webp"` || o.last().Header.Get("If-None-Match") != `"v1"` {
		t.Fatalf("revalidation: %d %v, sent %q", resp.StatusCode, resp.Header, o.last().Header.Get("If-None-Match"))
	}
	// An original cached under the variant's key revalidates as it is.
	r = variantRequest(t, "GET", "/a.jpg", header)
	r.Header.Set("If-None-Match", `"v1"`)
	if resp := do(r); resp.StatusCode != 304 || resp.Header.Get("Etag") != `"v1"` {
		t.Fatalf("original revalidation: %d %v", resp.StatusCode, resp.Header)
	}
}

func TestServerAbortsWithTheOriginLayer(t *testing.T) {
	o := newOriginLayer(t, func(w http.ResponseWriter, r *http.Request) {
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	})
	_, _ = converter(t, o, Config{})
	s := New(Config{Upstreams: map[string]string{"edgeweir_origin_verify": o.sock}, Workers: 1, Memory: DefaultMemory, Command: childCommand})
	dir, _ := os.MkdirTemp("", "ic")
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "i.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: s, ErrorLog: nil}
	go srv.Serve(l)
	defer srv.Close()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /a.jpg HTTP/1.1\r\nHost: img.test\r\n%s: %s\r\n\r\n", Header, header)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if line, err := bufio.NewReader(conn).ReadString('\n'); err == nil {
		t.Fatalf("got an answer %q, want the connection closed", line)
	}
}

func TestServerRejects(t *testing.T) {
	o := newOriginLayer(t, serveImage([]byte("x"), "text/plain", nil))
	_, do := converter(t, o, Config{})
	for _, v := range []string{"", "webp;q=80", strings.Replace(header, "up=edgeweir_origin_verify", "up=elsewhere", 1)} {
		if resp := do(variantRequest(t, "GET", "/a", v)); resp.StatusCode != 502 {
			t.Errorf("%q: %d", v, resp.StatusCode)
		}
	}
	if len(o.requests) != 0 {
		t.Fatal("a rejected request reached the origin layer")
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter(2, 100)
	ctx := context.Background()
	if !l.acquire(ctx, 60) || !l.acquire(ctx, 40) {
		t.Fatal("within the limits")
	}
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if l.acquire(short, 1) {
		t.Fatal("over the workers")
	}
	l.release(40)
	short2, cancel2 := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel2()
	if l.acquire(short2, 41) {
		t.Fatal("over the memory")
	}
	done := make(chan bool)
	go func() { done <- l.acquire(ctx, 100) }()
	time.Sleep(20 * time.Millisecond)
	l.release(60)
	if !<-done {
		t.Fatal("a waiter gets the slot when it frees")
	}
}

func TestRunChild(t *testing.T) {
	jpg := encodeJPEG(t, testImage(32, 24, false))
	run := func(stdin []byte, args ...string) (int, []byte) {
		var out, errb bytes.Buffer
		code := RunChild(args, bytes.NewReader(stdin), &out, &errb)
		return code, out.Bytes()
	}
	ok := []string{"--kind", "jpeg", "--format", "webp", "--quality", "80", "--width", "32", "--height", "24", "--memory", "1000000000"}
	if code, out := run(jpg, ok...); code != exitOK || string(out[8:12]) != "WEBP" {
		t.Fatalf("convert: %d", code)
	}
	if code, _ := run([]byte("garbage"), ok...); code != exitUnsupported {
		t.Fatalf("garbage: %d", code)
	}
	if code, _ := run(jpg, append(ok, "--max-input", "10")...); code != exitUnsupported {
		t.Fatalf("over max-input: %d", code)
	}
	for _, bad := range [][]string{{"--kind", "gif"}, {"--quality", "0"}, {"--width", "0"}, {"--memory", "0"}, {"--nope"}} {
		args := append(append([]string{}, ok...), bad...)
		if code, _ := run(jpg, args...); code != exitUsage {
			t.Errorf("%v: %d", bad, code)
		}
	}
	if args := childArgs(PNG, AVIF, 50, Info{3, 4, 6}, 99, 100); strings.Join(args, " ") !=
		"imgconv --kind png --format avif --quality 50 --width 3 --height 4 --orientation 6 --memory 99 --max-input 100" {
		t.Fatalf("childArgs: %v", args)
	}
}
