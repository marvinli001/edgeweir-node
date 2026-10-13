// Package controlplane builds Connect clients for the console's node
// channel (NodeService and ProbeService): CA-pinned clients for enrollment
// and an mTLS channel with hot-swappable credentials for everything else.
package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/coder/websocket"

	"github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1/nodev1connect"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/pki"
)

// MaxMessageBytes bounds a single response message (config snapshots).
const MaxMessageBytes = 128 << 20

// WebSocketPath is where a wss:// or ws:// server URL is served: the
// console's WebSocket entry on its web port.
const WebSocketPath = "/node-channel"

// WebSocketProtocol is the WebSocket subprotocol of that entry.
const WebSocketProtocol = "edgeweir-node-channel"

// webSocketDialTimeout bounds the WebSocket handshake and the node channel's
// TLS handshake inside it.
const webSocketDialTimeout = 20 * time.Second

// webSocketRoots verifies a wss:// URL's own certificate; nil: the system roots.
var webSocketRoots *x509.CertPool

// ParseServerURL validates the console node-channel base URL: https:// for
// the node channel port, wss:// (ws:// for a plain-HTTP console) for its
// WebSocket entry on the console's web port. Either way the channel's TLS is
// terminated by the console: through the entry it runs inside the WebSocket.
func ParseServerURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}
	switch u.Scheme {
	case "https", "wss", "ws":
	default:
		return nil, fmt.Errorf("invalid server URL %q: scheme must be https, wss or ws", raw)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("invalid server URL %q: missing host", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid server URL %q: must not contain credentials, query or fragment", raw)
	}
	if isWebSocket(u) && u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("invalid server URL %q: a wss:// or ws:// URL has no path (the entry is %s)", raw, WebSocketPath)
	}
	return u, nil
}

func isWebSocket(u *url.URL) bool { return u.Scheme == "wss" || u.Scheme == "ws" }

// baseURL is the URL Connect clients address: the server URL itself, or for
// the WebSocket entry https:// with its host (the calls run over the
// channel's TLS inside the WebSocket).
func baseURL(u *url.URL) string {
	if !isWebSocket(u) {
		return u.String()
	}
	return (&url.URL{Scheme: "https", Host: u.Host}).String()
}

// NewTransport returns the HTTP transport used for the node channel at u.
// HTTP/2 is negotiated via ALPN; pings detect dead connections under
// long-lived WatchConfig streams. For a wss:// or ws:// URL each connection
// is a WebSocket to the console's entry with cfg's TLS inside it.
func NewTransport(u *url.URL, cfg *tls.Config) *http.Transport {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:     cfg,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        4,
		HTTP2: &http.HTTP2Config{
			SendPingTimeout: 30 * time.Second,
			PingTimeout:     15 * time.Second,
		},
	}
	if isWebSocket(u) {
		// The WebSocket handshake goes through the environment's proxy; a
		// proxy here would make the transport do its own TLS instead.
		tr.Proxy = nil
		tr.DialTLSContext = webSocketDialer(u, cfg)
	}
	return tr
}

// webSocketDialer opens a WebSocket to the console's entry at u and runs the
// node channel's TLS (cfg: the pinned or mTLS configuration) inside it. A
// wss:// URL's own certificate is verified against the system roots.
func webSocketDialer(u *url.URL, cfg *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	endpoint := (&url.URL{Scheme: u.Scheme, Host: u.Host, Path: WebSocketPath}).String()
	handshake := &http.Client{Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: webSocketRoots},
		TLSHandshakeTimeout: 10 * time.Second,
	}}
	inner := cfg.Clone()
	inner.NextProtos = []string{"h2", "http/1.1"}
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, webSocketDialTimeout)
		defer cancel()
		ws, resp, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{
			HTTPClient:   handshake,
			Subprotocols: []string{WebSocketProtocol},
		})
		if err != nil {
			if resp != nil {
				// The server answered over HTTP, but not with the entry.
				return nil, &WebSocketRefusedError{Endpoint: endpoint, Status: resp.StatusCode, Err: err}
			}
			return nil, fmt.Errorf("node channel WebSocket %s: %w", endpoint, err)
		}
		if ws.Subprotocol() != WebSocketProtocol {
			_ = ws.CloseNow()
			return nil, &WebSocketRefusedError{Endpoint: endpoint, Err: errors.New("the server is not the console's node channel entry")}
		}
		// The connection outlives the dial: only Close ends it.
		conn := tls.Client(websocket.NetConn(context.Background(), ws, websocket.MessageBinary), inner)
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

// WebSocketRefusedError: the server at a wss:// or ws:// URL answered, but
// not as the console's node channel entry (e.g. 404 while the entry is
// closed, or another service).
type WebSocketRefusedError struct {
	Endpoint string
	// HTTP status of the answer; 0 when the handshake succeeded with another
	// subprotocol.
	Status int
	Err    error
}

func (e *WebSocketRefusedError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("node channel WebSocket %s: answered %d: %v", e.Endpoint, e.Status, e.Err)
	}
	return fmt.Sprintf("node channel WebSocket %s: %v", e.Endpoint, e.Err)
}

func (e *WebSocketRefusedError) Unwrap() error { return e.Err }

func clientOptions() []connect.ClientOption {
	return []connect.ClientOption{connect.WithReadMaxBytes(MaxMessageBytes)}
}

// NewPinnedClient returns a NodeService client for Enroll that trusts only
// the CA matching pin. close releases idle connections.
func NewPinnedClient(serverURL, serverName, pin string) (client nodev1connect.NodeServiceClient, closeFn func(), err error) {
	hc, base, closeFn, err := pinnedHTTPClient(serverURL, serverName, pin)
	if err != nil {
		return nil, nil, err
	}
	return nodev1connect.NewNodeServiceClient(hc, base, clientOptions()...), closeFn, nil
}

// NewPinnedProbeClient returns a ProbeService client for EnrollProbe that
// trusts only the CA matching pin. close releases idle connections.
func NewPinnedProbeClient(serverURL, serverName, pin string) (client nodev1connect.ProbeServiceClient, closeFn func(), err error) {
	hc, base, closeFn, err := pinnedHTTPClient(serverURL, serverName, pin)
	if err != nil {
		return nil, nil, err
	}
	return nodev1connect.NewProbeServiceClient(hc, base, clientOptions()...), closeFn, nil
}

func pinnedHTTPClient(serverURL, serverName, pin string) (*http.Client, string, func(), error) {
	u, err := ParseServerURL(serverURL)
	if err != nil {
		return nil, "", nil, err
	}
	if serverName == "" {
		serverName = u.Hostname()
	}
	tr := NewTransport(u, pki.PinnedTLSConfig(pin, serverName))
	return &http.Client{Transport: tr}, baseURL(u), tr.CloseIdleConnections, nil
}

// Channel is the authenticated (mTLS) node channel. Credentials can be
// reloaded after certificate renewal without restarting the agent, and the
// console address changed (Use, Reload).
type Channel struct {
	store identity.Store

	mu        sync.RWMutex
	id        *identity.Loaded
	cert      *tls.Certificate
	addr      Address
	fallback  bool
	transport *http.Transport
	client    nodev1connect.NodeServiceClient
	probe     nodev1connect.ProbeServiceClient
	changed   chan struct{}
}

// NewChannel loads the identity from store and builds the mTLS client.
func NewChannel(store identity.Store) (*Channel, error) {
	c := &Channel{store: store, changed: make(chan struct{})}
	if err := c.Reload(); err != nil {
		return nil, err
	}
	return c, nil
}

// Reload re-reads the identity from disk and replaces the transport, so
// that new connections present the current certificate and go to the
// identity's console address (leaving the fallback Use switched to).
// Streams opened on the old transport keep running until they end;
// watchers should restart when Changed fires.
func (c *Channel) Reload() error {
	id, err := c.store.Load()
	if err != nil {
		return err
	}
	return c.install(id, CurrentAddress(id.Identity), false)
}

// Use connects to addr (the identity's fallback address) with the loaded
// credentials until the next Reload, without changing the identity file.
func (c *Channel) Use(addr Address) error {
	return c.install(c.Identity(), addr, true)
}

// InUse returns the address new connections go to, and whether it is the
// fallback Use switched to.
func (c *Channel) InUse() (Address, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.addr, c.fallback
}

func (c *Channel) install(id *identity.Loaded, addr Address, fallback bool) error {
	u, err := ParseServerURL(addr.URL)
	if err != nil {
		return err
	}
	if id.CAPool == nil {
		// Never fall back to the system roots.
		return errors.New("no pinned CA loaded")
	}
	cert := id.TLS
	tr := NewTransport(u, pki.MTLSConfig(id.CAPool, nameOf(addr, u), c.currentCert))
	hc := &http.Client{Transport: tr}
	client := nodev1connect.NewNodeServiceClient(hc, baseURL(u), clientOptions()...)
	probe := nodev1connect.NewProbeServiceClient(hc, baseURL(u), clientOptions()...)

	c.mu.Lock()
	old := c.transport
	c.id, c.cert, c.addr, c.fallback, c.transport, c.client, c.probe = id, &cert, addr, fallback, tr, client, probe
	oldChanged := c.changed
	c.changed = make(chan struct{})
	c.mu.Unlock()

	close(oldChanged)
	if old != nil {
		old.CloseIdleConnections()
	}
	return nil
}

// nameOf is the server name verified at addr: its own, or the URL's host.
func nameOf(addr Address, u *url.URL) string {
	if addr.ServerName != "" {
		return addr.ServerName
	}
	return u.Hostname()
}

func (c *Channel) currentCert() *tls.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cert
}

// Client returns the current NodeService client.
func (c *Channel) Client() nodev1connect.NodeServiceClient {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.client
}

// ProbeClient returns the current ProbeService client (same connection and
// certificate as Client).
func (c *Channel) ProbeClient() nodev1connect.ProbeServiceClient {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.probe
}

// Identity returns the currently loaded identity.
func (c *Channel) Identity() *identity.Loaded {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.id
}

// Changed returns a channel that is closed on the next Reload.
func (c *Channel) Changed() <-chan struct{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.changed
}

// Close releases idle connections.
func (c *Channel) Close() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
}

// IsAuthError reports whether err means the console rejected the node's
// credentials (deleted node, revoked or expired certificate, used token).
func IsAuthError(err error) bool {
	var ce *connect.Error
	if !errors.As(err, &ce) {
		return false
	}
	return ce.Code() == connect.CodeUnauthenticated || ce.Code() == connect.CodePermissionDenied
}
