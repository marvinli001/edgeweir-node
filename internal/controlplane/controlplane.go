// Package controlplane builds Connect clients for the console's node
// channel (NodeService): a CA-pinned client for enrollment and an mTLS
// channel with hot-swappable credentials for everything else.
package controlplane

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"connectrpc.com/connect"

	"github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1/nodev1connect"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/pki"
)

// MaxMessageBytes bounds a single response message (config snapshots).
const MaxMessageBytes = 128 << 20

// ParseServerURL validates the console node-channel base URL. Only https
// is accepted: the channel always uses TLS terminated by the console.
func ParseServerURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("invalid server URL %q: scheme must be https", raw)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("invalid server URL %q: missing host", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid server URL %q: must not contain credentials, query or fragment", raw)
	}
	return u, nil
}

// NewTransport returns the HTTP transport used for the node channel. HTTP/2
// is negotiated via ALPN; pings detect dead connections under long-lived
// WatchConfig streams.
func NewTransport(cfg *tls.Config) *http.Transport {
	return &http.Transport{
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
}

func clientOptions() []connect.ClientOption {
	return []connect.ClientOption{connect.WithReadMaxBytes(MaxMessageBytes)}
}

// NewPinnedClient returns a NodeService client for Enroll that trusts only
// the CA matching pin. close releases idle connections.
func NewPinnedClient(serverURL, serverName, pin string) (client nodev1connect.NodeServiceClient, closeFn func(), err error) {
	u, err := ParseServerURL(serverURL)
	if err != nil {
		return nil, nil, err
	}
	if serverName == "" {
		serverName = u.Hostname()
	}
	tr := NewTransport(pki.PinnedTLSConfig(pin, serverName))
	hc := &http.Client{Transport: tr}
	return nodev1connect.NewNodeServiceClient(hc, u.String(), clientOptions()...), tr.CloseIdleConnections, nil
}

// Channel is the authenticated (mTLS) node channel. Credentials can be
// reloaded after certificate renewal without restarting the agent.
type Channel struct {
	store identity.Store

	mu        sync.RWMutex
	id        *identity.Loaded
	cert      *tls.Certificate
	transport *http.Transport
	client    nodev1connect.NodeServiceClient
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
// that new connections present the current certificate. Streams opened on
// the old transport keep running until they end; watchers should restart
// when Changed fires.
func (c *Channel) Reload() error {
	id, err := c.store.Load()
	if err != nil {
		return err
	}
	u, err := ParseServerURL(id.ServerURL)
	if err != nil {
		return err
	}
	serverName := id.ServerName
	if serverName == "" {
		serverName = u.Hostname()
	}
	cert := id.TLS
	tr := NewTransport(pki.MTLSConfig(id.CAPool, serverName, c.currentCert))
	client := nodev1connect.NewNodeServiceClient(&http.Client{Transport: tr}, u.String(), clientOptions()...)

	c.mu.Lock()
	old := c.transport
	c.id, c.cert, c.transport, c.client = id, &cert, tr, client
	oldChanged := c.changed
	c.changed = make(chan struct{})
	c.mu.Unlock()

	close(oldChanged)
	if old != nil {
		old.CloseIdleConnections()
	}
	return nil
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
