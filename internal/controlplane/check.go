package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	"connectrpc.com/connect"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1/nodev1connect"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/pki"
)

// FollowFeature is the capability of following the console's node channel
// address (ChannelStatus, CheckChannel, `set-server`).
const FollowFeature = "channel-follow-v1"

// Codes of a failed check (ChannelStatus.error_code).
const (
	CheckUnreachable      = "unreachable"
	CheckWebSocketRefused = "websocket_refused"
	CheckTLSUntrusted     = "tls_untrusted"
	CheckRejected         = "rejected"
	CheckWrongIdentity    = "wrong_identity"
	CheckInvalidAddress   = "invalid_address"
)

// CheckError is a failed check with its code.
type CheckError struct {
	Code string
	Err  error
}

func (e *CheckError) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *CheckError) Unwrap() error { return e.Err }

// CheckCode returns the code of a failed check (CheckUnreachable for an
// error that does not tell more).
func CheckCode(err error) string {
	var ce *CheckError
	if errors.As(err, &ce) {
		return ce.Code
	}
	var ws *WebSocketRefusedError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verify *tls.CertificateVerificationError
	switch {
	case errors.As(err, &ws):
		return CheckWebSocketRefused
	case errors.As(err, &verify), errors.As(err, &unknown), errors.As(err, &hostname), errors.As(err, &invalid):
		return CheckTLSUntrusted
	}
	switch connect.CodeOf(err) {
	case connect.CodeUnauthenticated, connect.CodePermissionDenied:
		return CheckRejected
	}
	return CheckUnreachable
}

// CheckResult is the console's answer at the checked address.
type CheckResult struct {
	// The address the console gives out; empty when it did not say (a
	// console without CheckChannel).
	Advertised Address
	// The console answered, but has no CheckChannel: an RPC without side
	// effects stood in for it.
	Legacy bool
	// How far the node's clock is ahead of the console's (negative:
	// behind), from a second CheckChannel on the open connection
	// (CheckWithClock): the console's time against the middle of its round
	// trip (RTT). Unset for a console that does not tell its time.
	ClockOffset time.Duration
	ClockRTT    time.Duration
	ClockKnown  bool
}

// Check makes one authenticated call at addr with id's credentials: the
// connection trusts only the CA pinned at enrollment and presents the
// client certificate cert returns; the console must answer for id's node
// (CheckChannel) or probe (CheckProbeChannel). A console without these
// RPCs is checked with GetCertificates (no ids) or GetProbeTargets. Errors
// are CheckErrors.
func Check(ctx context.Context, id *identity.Loaded, cert func() *tls.Certificate, addr Address) (CheckResult, error) {
	return check(ctx, id, cert, addr, false)
}

// CheckWithClock is Check for a node that also measures its clock against
// the console's with a second call (CheckResult.ClockOffset).
func CheckWithClock(ctx context.Context, id *identity.Loaded, cert func() *tls.Certificate, addr Address) (CheckResult, error) {
	return check(ctx, id, cert, addr, true)
}

func check(ctx context.Context, id *identity.Loaded, cert func() *tls.Certificate, addr Address, clock bool) (CheckResult, error) {
	fail := func(code string, err error) (CheckResult, error) {
		return CheckResult{}, &CheckError{Code: code, Err: err}
	}
	u, err := ParseServerURL(addr.URL)
	if err != nil {
		return fail(CheckInvalidAddress, err)
	}
	if id == nil || id.CAPool == nil {
		// Never fall back to the system roots.
		return fail(CheckTLSUntrusted, errors.New("no pinned CA loaded"))
	}
	tr := NewTransport(u, pki.MTLSConfig(id.CAPool, nameOf(addr, u), cert))
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr}
	if id.ProbeID != "" {
		return checkProbe(ctx, nodev1connect.NewProbeServiceClient(hc, baseURL(u), clientOptions()...), id.ProbeID)
	}
	return checkNode(ctx, nodev1connect.NewNodeServiceClient(hc, baseURL(u), clientOptions()...), id.NodeID, clock)
}

func checkNode(ctx context.Context, client nodev1connect.NodeServiceClient, nodeID string, clock bool) (CheckResult, error) {
	resp, err := client.CheckChannel(ctx, connect.NewRequest(&nodev1.CheckChannelRequest{}))
	if connect.CodeOf(err) == connect.CodeUnimplemented {
		// The TLS handshake proved the console's CA; this proves the node
		// is accepted (disabled nodes too).
		_, err = client.GetCertificates(ctx, connect.NewRequest(&nodev1.GetCertificatesRequest{}))
		if err == nil || connect.CodeOf(err) == connect.CodePermissionDenied {
			return CheckResult{Legacy: true}, nil
		}
	}
	if err != nil {
		return CheckResult{}, &CheckError{Code: CheckCode(err), Err: err}
	}
	if got := resp.Msg.GetNodeId(); got != nodeID {
		return CheckResult{}, &CheckError{Code: CheckWrongIdentity, Err: fmt.Errorf("the console answered for node %q, not %q", got, nodeID)}
	}
	res := CheckResult{Advertised: advertised(resp.Msg.GetChannel())}
	if clock && resp.Msg.GetConsoleTime() != nil {
		// The first call included the connection setup.
		sent := time.Now()
		again, err := client.CheckChannel(ctx, connect.NewRequest(&nodev1.CheckChannelRequest{}))
		received := time.Now()
		if t := again.Msg.GetConsoleTime(); err == nil && t.IsValid() {
			res.ClockRTT = received.Sub(sent)
			res.ClockOffset = sent.Round(0).Add(res.ClockRTT / 2).Sub(t.AsTime())
			res.ClockKnown = true
		}
	}
	return res, nil
}

func checkProbe(ctx context.Context, client nodev1connect.ProbeServiceClient, probeID string) (CheckResult, error) {
	resp, err := client.CheckProbeChannel(ctx, connect.NewRequest(&nodev1.CheckProbeChannelRequest{}))
	if connect.CodeOf(err) == connect.CodeUnimplemented {
		if _, err = client.GetProbeTargets(ctx, connect.NewRequest(&nodev1.GetProbeTargetsRequest{})); err == nil {
			return CheckResult{Legacy: true}, nil
		}
	}
	if err != nil {
		return CheckResult{}, &CheckError{Code: CheckCode(err), Err: err}
	}
	if got := resp.Msg.GetProbeId(); got != probeID {
		return CheckResult{}, &CheckError{Code: CheckWrongIdentity, Err: fmt.Errorf("the console answered for probe %q, not %q", got, probeID)}
	}
	return CheckResult{Advertised: advertised(resp.Msg.GetChannel())}, nil
}

// advertised is the console's address when it parses (empty otherwise).
func advertised(a *nodev1.ChannelAddress) Address {
	if a.GetUrl() == "" {
		return Address{}
	}
	addr, err := ParseAddress(a.GetUrl(), a.GetServerName())
	if err != nil {
		return Address{}
	}
	return addr
}
