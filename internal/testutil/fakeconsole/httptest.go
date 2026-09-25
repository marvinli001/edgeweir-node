package fakeconsole

import (
	"net"
	"net/http/httptest"
	"testing"
)

// StartTLS serves the console on a local HTTPS test server (HTTP/2 enabled)
// with a certificate for 127.0.0.1, ::1, localhost and console.test. The
// server is closed when the test ends.
func (c *Console) StartTLS(tb testing.TB) *httptest.Server {
	tb.Helper()
	cfg, err := c.TLSConfig([]string{"localhost", "console.test"}, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback})
	if err != nil {
		tb.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(c.Handler())
	srv.TLS = cfg
	srv.EnableHTTP2 = true
	srv.StartTLS()
	tb.Cleanup(func() {
		c.Close()
		srv.CloseClientConnections()
		srv.Close()
	})
	return srv
}
