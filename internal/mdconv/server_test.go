package mdconv

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
// edgeweir-node mdconv.
func TestMain(m *testing.M) {
	if os.Getenv("MDCONV_TEST_CHILD") == "1" {
		os.Exit(RunChild(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// childCommand runs the test binary as the child.
func childCommand(ctx context.Context, args []string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = []string{"MDCONV_TEST_CHILD=1", "GOMAXPROCS=1"}
	return cmd
}

// shCommand runs a shell script as the child (reading stdin).
func shCommand(script string) func(context.Context, []string) *exec.Cmd {
	return func(ctx context.Context, _ []string) *exec.Cmd {
		return exec.CommandContext(ctx, "/bin/sh", "-c", script)
	}
}

// originLayer is a fake origin layer on a unix socket.
type originLayer struct {
	sock     string
	mu       sync.Mutex
	requests []*http.Request
}

func newOriginLayer(t *testing.T, handler http.HandlerFunc) *originLayer {
	t.Helper()
	dir, err := os.MkdirTemp("", "md")
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

const page = `<html><head><meta name="description" content="A page"></head><body><nav>menu</nav><h1>Hello</h1><p>See <a href="/x">x</a>.</p></body></html>`

const pageMarkdown = "---\ndescription: A page\n---\n\n# Hello\n\nSee [x](https://site.test/x).\n"

func htmlHandler(extra func(http.Header)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Etag", `"abc"`)
		h.Set("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT")
		h.Set("Cache-Control", "public, max-age=60")
		h.Set("Set-Cookie", "a=b")
		h.Set("Strict-Transport-Security", "max-age=1")
		h.Set("Cache-Tag", "page")
		h.Set("Accept-Ranges", "bytes")
		if extra != nil {
			extra(h)
		}
		io.WriteString(w, page)
	}
}

func newServer(o *originLayer, cfg Config) *Server {
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
	return New(cfg)
}

func request(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = "site.test"
	r.Header.Set(Header, "up=edgeweir_origin_verify")
	r.Header.Set("Accept", "text/markdown, text/html;q=0.9")
	r.Header.Set("X-Forwarded-Proto", "https")
	return r
}

func TestServerConverts(t *testing.T) {
	o := newOriginLayer(t, htmlHandler(nil))
	s := newServer(o, Config{})
	r := request(http.MethodGet, "/docs/a?q=1")
	r.Header.Set("Range", "bytes=0-10")
	r.Header.Set("If-None-Match", `"abc"`)
	r.Header.Set("If-Modified-Since", "Wed, 21 Oct 2026 07:28:00 GMT")
	r.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	res := w.Result()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(body) != pageMarkdown {
		t.Fatalf("%d %q", res.StatusCode, body)
	}
	h := res.Header
	want := map[string]string{
		"Content-Type":              "text/markdown; charset=utf-8",
		"Content-Length":            strconv.Itoa(len(pageMarkdown)),
		TokensHeader:                strconv.Itoa(EstimateTokens([]byte(pageMarkdown))),
		"Content-Signal":            ContentSignal,
		ConvertedHeader:             "1",
		"Cache-Control":             "public, max-age=60",
		"Set-Cookie":                "a=b",
		"Strict-Transport-Security": "max-age=1",
		"Cache-Tag":                 "page",
		"Etag":                      "",
		"Last-Modified":             "",
		"Accept-Ranges":             "",
		// The edge adds Vary: Accept towards clients; a cached Vary would
		// split the variant by every agent's Accept.
		"Vary": "",
	}
	for name, v := range want {
		if got := h.Get(name); got != v {
			t.Errorf("%s = %q, want %q", name, got, v)
		}
	}
	in := o.last()
	if in.Method != http.MethodGet || in.RequestURI != "/docs/a?q=1" || in.Host != "site.test" {
		t.Errorf("origin layer got %s %s Host %s", in.Method, in.RequestURI, in.Host)
	}
	for _, name := range []string{Header, "Range", "If-None-Match", "If-Modified-Since", "Accept-Encoding"} {
		if v := in.Header.Get(name); v != "" {
			t.Errorf("origin layer got %s: %s", name, v)
		}
	}
	if in.Header.Get("Accept") != "text/markdown, text/html;q=0.9" {
		t.Errorf("Accept = %q", in.Header.Get("Accept"))
	}
}

func TestServerKeepsOriginContentSignal(t *testing.T) {
	o := newOriginLayer(t, htmlHandler(func(h http.Header) {
		h.Set("Content-Signal", "ai-train=no, search=yes")
		h.Set(ConvertedHeader, "spoofed")
	}))
	w := httptest.NewRecorder()
	newServer(o, Config{}).ServeHTTP(w, request(http.MethodGet, "/"))
	if got := w.Header().Get("Content-Signal"); got != "ai-train=no, search=yes" {
		t.Errorf("Content-Signal = %q", got)
	}
	if got := w.Header().Values(ConvertedHeader); len(got) != 1 || got[0] != "1" {
		t.Errorf("%s = %q", ConvertedHeader, got)
	}
}

func TestServerHead(t *testing.T) {
	o := newOriginLayer(t, htmlHandler(nil))
	w := httptest.NewRecorder()
	newServer(o, Config{}).ServeHTTP(w, request(http.MethodHead, "/"))
	if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Length") != strconv.Itoa(len(pageMarkdown)) {
		t.Errorf("%d %q %q", w.Code, w.Body, w.Header().Get("Content-Length"))
	}
	if o.last().Method != http.MethodGet {
		t.Errorf("origin layer got %s", o.last().Method)
	}
}

func gzipped(s string) []byte {
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	io.WriteString(zw, s)
	zw.Close()
	return b.Bytes()
}

func TestServerDecodesGzip(t *testing.T) {
	o := newOriginLayer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(gzipped(page))
	})
	w := httptest.NewRecorder()
	newServer(o, Config{}).ServeHTTP(w, request(http.MethodGet, "/"))
	if w.Body.String() != pageMarkdown || w.Header().Get("Content-Encoding") != "" {
		t.Errorf("%q %q", w.Body, w.Header().Get("Content-Encoding"))
	}
}

func TestServerPasses(t *testing.T) {
	big := "<p>" + strings.Repeat("a", MaxInput) + "</p>"
	for name, c := range map[string]struct {
		handler http.HandlerFunc
		cfg     Config
		body    string
	}{
		"not HTML": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"a":1}`)
		}, Config{}, `{"a":1}`},
		"origin Markdown": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/markdown")
			io.WriteString(w, "# Own")
		}, Config{}, "# Own"},
		"404": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(404)
			io.WriteString(w, page)
		}, Config{}, page},
		"206": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(206)
			io.WriteString(w, page)
		}, Config{}, page},
		"brotli": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Encoding", "br")
			io.WriteString(w, "binary")
		}, Config{}, "binary"},
		"over the limit, known length": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Length", strconv.Itoa(len(big)))
			io.WriteString(w, big)
		}, Config{}, big},
		"over the limit, chunked": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.(http.Flusher).Flush()
			io.WriteString(w, big)
		}, Config{}, big},
		"bad gzip": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Encoding", "gzip")
			io.WriteString(w, "not gzip at all")
		}, Config{}, "not gzip at all"},
		"empty document": {func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<div id="app"></div>`)
		}, Config{}, `<div id="app"></div>`},
		"child fails":    {htmlHandler(nil), Config{Command: shCommand("cat >/dev/null; exit 1")}, page},
		"child too slow": {htmlHandler(nil), Config{Command: shCommand("cat >/dev/null; sleep 5"), Timeout: 200 * time.Millisecond}, page},
		"output over the bound": {htmlHandler(nil),
			Config{Command: shCommand("cat >/dev/null; head -c 2000000 /dev/zero; exec sleep 5"), Timeout: time.Minute}, page},
		"over the memory budget": {htmlHandler(nil), Config{Memory: Estimate(int64(len(page))) - 1}, page},
	} {
		t.Run(name, func(t *testing.T) {
			o := newOriginLayer(t, c.handler)
			w := httptest.NewRecorder()
			newServer(o, c.cfg).ServeHTTP(w, request(http.MethodGet, "/"))
			if w.Body.String() != c.body {
				t.Errorf("body %q…", w.Body.String()[:min(w.Body.Len(), 60)])
			}
			if w.Header().Get(ConvertedHeader) != "" || w.Header().Get(TokensHeader) != "" {
				t.Errorf("marked converted")
			}
			if w.Header().Get("X-Accel-Expires") != "" {
				t.Errorf("X-Accel-Expires %q", w.Header().Get("X-Accel-Expires"))
			}
		})
	}
}

func TestServerBusy(t *testing.T) {
	o := newOriginLayer(t, htmlHandler(nil))
	s := newServer(o, Config{Workers: 1})
	if !s.lim.acquire(context.Background(), 1) {
		t.Fatal("no slot")
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, request(http.MethodGet, "/"))
	if w.Body.String() != page || w.Header().Get("X-Accel-Expires") != strconv.Itoa(TransientTTL) {
		t.Errorf("%q %q", w.Body, w.Header().Get("X-Accel-Expires"))
	}
}

func TestServerRejects(t *testing.T) {
	o := newOriginLayer(t, htmlHandler(nil))
	s := newServer(o, Config{})
	for _, v := range []string{"", "up=edgeweir_origin_other"} {
		r := request(http.MethodGet, "/")
		r.Header.Set(Header, v)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusBadGateway {
			t.Errorf("%q: %d", v, w.Code)
		}
	}
}

func TestServerAbortsWithTheOriginLayer(t *testing.T) {
	o := newOriginLayer(t, func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	})
	s := newServer(o, Config{})
	defer func() {
		if recover() != http.ErrAbortHandler {
			t.Error("no abort")
		}
	}()
	s.ServeHTTP(httptest.NewRecorder(), request(http.MethodGet, "/"))
}

func TestPageURL(t *testing.T) {
	r := request(http.MethodGet, "/a/b?c=d")
	if got := pageURL(r); got != "https://site.test/a/b?c=d" {
		t.Errorf("%q", got)
	}
	r.Header.Del("X-Forwarded-Proto")
	if got := pageURL(r); got != "http://site.test/a/b?c=d" {
		t.Errorf("%q", got)
	}
}
