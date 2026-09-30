package engine

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Configure arguments of the official openresty/openresty:1.31.1.1-bookworm
// image (no Brotli, Zstandard or ModSecurity).
const officialV = `nginx version: openresty/1.31.1.1
built by gcc 12.2.0 (Debian 12.2.0-14+deb12u1)
built with OpenSSL 3.5.6 7 Apr 2026 (running with OpenSSL 3.5.7 9 Jun 2026)
TLS SNI support enabled
configure arguments: --prefix=/usr/local/openresty/nginx --with-cc-opt='-O2 -DNGX_LUA_ABORT_AT_PANIC -I/usr/local/openresty/zlib/include' --add-module=../ngx_devel_kit-0.3.4 --add-module=../echo-nginx-module-0.64 --add-module=../ngx_lua-0.10.31rc5 --add-module=../ngx_stream_lua-0.0.19rc4 --with-pcre-jit --with-http_v3_module --with-compat --with-http_ssl_module
`

// edgeweir-openresty (packaging/openresty).
const edgeweirV = `nginx version: openresty/1.31.1.1
built by gcc 11.5.0 20240719 (Red Hat 11.5.0-11) (GCC)
built with OpenSSL 3.5.9 29 Sep 2026
TLS SNI support enabled
configure arguments: --prefix=/usr/lib/edgeweir-openresty/nginx --with-cc-opt='-O2 -DNGX_LUA_ABORT_AT_PANIC' --add-module=../ngx_devel_kit-0.3.4 --add-module=../ngx_lua-0.10.31rc5 --with-pcre-jit --with-compat --add-module=/build/src/ngx_brotli --add-module=/build/src/zstd-nginx-module-0.1.1
`

func TestParseModuleFeatures(t *testing.T) {
	cases := []struct {
		name, v string
		want    []string
	}{
		{"official image", officialV, nil},
		{"edgeweir-openresty", edgeweirV, []string{FeatureBrotli, FeatureZstd}},
		{"Brotli only, versioned and quoted", "configure arguments: --add-module='/src/ngx_brotli-1.0.0rc/' --with-compat\n", []string{FeatureBrotli}},
		{"dynamic modules are not in the binary", "configure arguments: --add-dynamic-module=/src/ngx_brotli --add-dynamic-module=/src/zstd-nginx-module\n", nil},
		{"module names elsewhere do not count", "nginx version: openresty/1.31.1.1 ngx_brotli zstd-nginx-module\nconfigure arguments: --with-cc-opt='-DNGX_BROTLI' --add-module=/src/not_ngx_brotli\n", nil},
		{"zstd only", "configure arguments: --add-module=../zstd-nginx-module\n", []string{FeatureZstd}},
		{"empty", "", nil},
	}
	for _, c := range cases {
		if got := ParseModuleFeatures(c.v); !slices.Equal(got, c.want) {
			t.Errorf("%s: ParseModuleFeatures = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestModuleFeaturesRunsNginxV(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "nginx")
	script := "#!/bin/sh\n[ \"$1\" = -V ] || exit 2\ncat >&2 <<'EOF'\n" + edgeweirV + "EOF\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := New(Config{Bin: bin}).ModuleFeatures(context.Background())
	if err != nil || !slices.Equal(got, []string{FeatureBrotli, FeatureZstd}) {
		t.Fatalf("ModuleFeatures = %v, %v", got, err)
	}
	if _, err := New(Config{Bin: filepath.Join(dir, "missing")}).ModuleFeatures(context.Background()); err == nil {
		t.Fatal("missing binary: no error")
	}
}

func TestDefaultModSecurityModule(t *testing.T) {
	root := t.TempDir()
	sbin := filepath.Join(root, "usr/lib/edgeweir-openresty/nginx/sbin")
	if err := os.MkdirAll(sbin, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(sbin, "nginx")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := DefaultModSecurityModule(bin); got != "" {
		t.Fatalf("no module installed: %q", got)
	}
	modules := filepath.Join(root, "usr/lib/edgeweir-openresty/modules")
	if err := os.MkdirAll(modules, 0o755); err != nil {
		t.Fatal(err)
	}
	module := filepath.Join(modules, ModSecurityModuleFile)
	if err := os.WriteFile(module, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "openresty")
	if err := os.Symlink(bin, link); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{bin, link} {
		got := DefaultModSecurityModule(b)
		if want, _ := filepath.EvalSymlinks(module); got != want {
			t.Errorf("DefaultModSecurityModule(%s) = %q, want %q", b, got, want)
		}
	}
}

func TestModSecurityDenialsAreSummarized(t *testing.T) {
	var out bytes.Buffer
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	l := &lineLogger{log: slog.New(slog.NewTextHandler(&out, nil)), now: func() time.Time { return now }}
	denied := `2026/10/01 00:00:00 [error] 7#7: *1 [client 192.0.2.1] ModSecurity: Access denied with code 403 (phase 2). [id "949110"], client: 192.0.2.1, server: _, request: "GET /?token=secret HTTP/1.1"` + "\n"
	for range 5 {
		_, _ = l.Write([]byte(denied))
	}
	_, _ = l.Write([]byte("2026/10/01 00:00:00 [error] 7#7: *2 connect() failed\n"))
	if strings.Contains(out.String(), "token=secret") {
		t.Fatalf("a denied request's line reached the log:\n%s", out.String())
	}
	if c := strings.Count(out.String(), "ModSecurity denied requests"); c != 1 || !strings.Contains(out.String(), "requests=1") {
		t.Fatalf("want one summary of the first denial:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "connect() failed") {
		t.Fatal("other errors must still be logged")
	}
	now = now.Add(time.Minute)
	_, _ = l.Write([]byte(denied))
	if !strings.Contains(out.String(), "requests=5") {
		t.Fatalf("want a summary of the next 5 denials a minute later:\n%s", out.String())
	}
	_, _ = l.Write([]byte(denied))
	l.flush()
	if !strings.Contains(out.String(), "requests=1 since") || strings.Count(out.String(), "ModSecurity denied requests") != 3 {
		t.Fatalf("flush must report what is left:\n%s", out.String())
	}
}
