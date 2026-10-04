package controlplane

import "crypto/x509"

// SetWebSocketRoots makes the WebSocket handshake of wss:// URLs trust roots
// (a test server's certificate) instead of the system roots, until the
// returned function restores them.
func SetWebSocketRoots(roots *x509.CertPool) (restore func()) {
	previous := webSocketRoots
	webSocketRoots = roots
	return func() { webSocketRoots = previous }
}
