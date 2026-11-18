package render

import (
	"strings"
	"testing"
)

func TestEarlyHintsProbe(t *testing.T) {
	conf, err := EarlyHintsProbe(params())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(conf), "assert(ffi.C.ngx_http_ffi_send_early_hints)") || strings.Contains(string(conf), "listen ") {
		t.Fatalf("invalid FFI probe: %s", conf)
	}
	p := params()
	p.Prefix = "/tmp/invalid prefix"
	if _, err := EarlyHintsProbe(p); err == nil {
		t.Fatal("unsafe prefix accepted")
	}
}
