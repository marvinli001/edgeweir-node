package render

import "fmt"

// EarlyHintsProbe resolves the private FFI symbol without opening a listener.
func EarlyHintsProbe(p Params) ([]byte, error) {
	p = p.WithDefaults()
	if !safePath.MatchString(p.Prefix) {
		return nil, fmt.Errorf("nginx prefix %q must be an absolute path without spaces or special characters", p.Prefix)
	}
	return []byte(fmt.Sprintf(`pid %s/logs/early-hints-probe.pid;
error_log stderr notice;
events { worker_connections 16; }
http {
    init_by_lua_block {
        local ffi = require("ffi")
        ffi.cdef[[int ngx_http_ffi_send_early_hints(void *r, void *links, size_t count);]]
        assert(ffi.C.ngx_http_ffi_send_early_hints)
    }
}
`, p.Prefix)), nil
}
