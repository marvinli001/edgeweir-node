package fakeconsole

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coder/websocket"
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

// StartWebSocketEntry serves a node channel WebSocket entry in front of srv
// (from StartTLS), like the console's on its web port: each WebSocket at
// /node-channel with the edgeweir-node-channel subprotocol is piped to a TCP
// connection to srv, so the node's TLS runs inside it. With secure the entry
// itself is served over TLS (wss://, with httptest's own certificate);
// otherwise over plain HTTP (ws://). The server is closed when the test ends.
func (c *Console) StartWebSocketEntry(tb testing.TB, srv *httptest.Server, secure bool) *httptest.Server {
	tb.Helper()
	target := srv.Listener.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/node-channel", func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"edgeweir-node-channel"}})
		if err != nil {
			return
		}
		if ws.Subprotocol() != "edgeweir-node-channel" {
			_ = ws.Close(websocket.StatusPolicyViolation, "subprotocol required")
			return
		}
		tcp, err := net.Dial("tcp", target)
		if err != nil {
			_ = ws.Close(websocket.StatusInternalError, "node channel unreachable")
			return
		}
		conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
		done := make(chan struct{}, 2)
		go func() { _, _ = io.Copy(tcp, conn); done <- struct{}{} }()
		go func() { _, _ = io.Copy(conn, tcp); done <- struct{}{} }()
		<-done
		_ = tcp.Close()
		_ = conn.Close()
	})
	entry := httptest.NewUnstartedServer(mux)
	if secure {
		entry.StartTLS()
	} else {
		entry.Start()
	}
	tb.Cleanup(func() {
		entry.CloseClientConnections()
		entry.Close()
	})
	return entry
}
