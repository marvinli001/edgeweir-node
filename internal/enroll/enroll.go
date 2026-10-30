// Package enroll implements `edgeweir-node enroll`: it exchanges a
// single-use token and a locally generated CSR for a node certificate
// issued by the console's internal CA. `edgeweir-node probe` enrolls a
// probe the same way (Probe).
//
// Trust bootstrap follows kubeadm's discovery model: the install command
// carries the SHA-256 of the internal CA certificate, the TLS handshake is
// verified against that pin before the token is sent, and the CA returned
// in the response must hash to the same pin.
package enroll

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"connectrpc.com/connect"

	"github.com/marvinli001/edgeweir-node/internal/controlplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/hostinfo"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/pki"
)

// ErrAlreadyEnrolled is returned when an identity exists and Force is off.
var ErrAlreadyEnrolled = errors.New("node is already enrolled (use --force to replace the identity)")

// ErrAgentRunning is returned by a forced enrollment while an agent runs
// with the state directory: the agent keeps the identity it loaded, and a
// certificate renewal could write the old node's certificate next to the
// new key.
var ErrAgentRunning = errors.New("edgeweir-node run is using this state directory; stop it first " +
	"(e.g. systemctl stop edgeweir-node), enroll --force, then start it again")

// ErrProbeAlreadyEnrolled is returned when a probe identity exists.
var ErrProbeAlreadyEnrolled = errors.New("probe is already enrolled")

// ErrEnrolledElsewhere is returned by Existing when the identity pins
// another console CA than the one asked for.
var ErrEnrolledElsewhere = errors.New("node is enrolled with another console (its identity pins another CA)")

// ErrBusy is returned while another enrollment runs with the state
// directory.
var ErrBusy = errors.New("another enrollment is running with this state directory; " +
	"wait for it, then run this command again")

// ErrInvalidOptions marks an invalid server URL, CA pin or missing token.
var ErrInvalidOptions = errors.New("invalid enrollment options")

// ErrStateDir marks a state directory that cannot hold the identity.
var ErrStateDir = errors.New("state directory unusable")

// ErrBadResponse marks an answer of the console that the node cannot use
// (missing fields, a certificate that does not fit the key).
var ErrBadResponse = errors.New("invalid enroll response")

// responseError is an error about the console's answer (ErrBadResponse);
// its message stays the wrapped one.
type responseError struct{ error }

func (e responseError) Unwrap() error        { return e.error }
func (e responseError) Is(target error) bool { return target == ErrBadResponse }

// ErrTokenRejected marks a token the console refused (unknown, expired
// or used).
var ErrTokenRejected = errors.New("console rejected the enrollment token (expired or already used)")

// Options configures an enrollment.
type Options struct {
	// ServerURL is the console node-channel base URL, e.g. https://console:8443.
	ServerURL string
	// Token is the single-use enrollment token.
	Token string
	// CASHA256 is the pinned internal CA fingerprint (hex SHA-256 of DER).
	CASHA256 string
	// ServerName overrides the TLS server name (defaults to the URL host).
	ServerName string
	// StateDir is where the identity is written.
	StateDir string
	// Force replaces an existing identity.
	Force bool
	// Info describes this node; collected automatically when nil.
	Info *nodev1.NodeInfo
	// Timeout bounds the Enroll RPC (default 30s).
	Timeout time.Duration
	Logger  *slog.Logger
}

// Run performs the enrollment and persists the identity.
func Run(ctx context.Context, opts Options) (*identity.Identity, error) {
	info := opts.Info
	if info == nil {
		info = hostinfo.Collect("")
	}
	return run(ctx, common{
		serverURL: opts.ServerURL, token: opts.Token, caSHA256: opts.CASHA256, serverName: opts.ServerName,
		force: opts.Force, timeout: opts.Timeout, log: opts.Logger, kind: "node",
	}, identity.Store{Dir: opts.StateDir}, info.GetHostname(), func(ctx context.Context, u, serverName, pin string, csrPEM []byte) (*issued, error) {
		client, closeIdle, err := controlplane.NewPinnedClient(u, serverName, pin)
		if err != nil {
			return nil, err
		}
		defer closeIdle()
		resp, err := client.Enroll(ctx, connect.NewRequest(&nodev1.EnrollRequest{
			Token:  opts.Token,
			CsrPem: string(csrPEM),
			Info:   info,
		}))
		if err != nil {
			return nil, err
		}
		msg := resp.Msg
		if msg.GetNodeId() == "" {
			return nil, responseError{errors.New("enroll response: empty node_id")}
		}
		return &issued{
			id:      identity.Identity{NodeID: msg.GetNodeId(), ClusterID: msg.GetClusterId(), NodeName: msg.GetNodeName()},
			subject: msg.GetNodeId(),
			certPEM: msg.GetCertificatePem(),
			caPEM:   msg.GetCaCertificatePem(),
		}, nil
	})
}

// ProbeOptions configures the enrollment of a probe (`edgeweir-node probe`).
type ProbeOptions struct {
	ServerURL  string
	Token      string
	CASHA256   string
	ServerName string
	// StateDir receives the probe layout of the identity (probe.key,
	// probe.crt, ca.crt, probe.json).
	StateDir string
	Info     *nodev1.ProbeInfo
	Timeout  time.Duration
	Logger   *slog.Logger
}

// Probe enrolls a probe with ProbeService.EnrollProbe: the same trust
// bootstrap as a node (CA pin checked before the token is sent, the key
// never leaves this host) and the probe layout of the identity store.
func Probe(ctx context.Context, opts ProbeOptions) (*identity.Identity, error) {
	info := opts.Info
	if info == nil {
		info = &nodev1.ProbeInfo{Hostname: hostinfo.Hostname()}
	}
	return run(ctx, common{
		serverURL: opts.ServerURL, token: opts.Token, caSHA256: opts.CASHA256, serverName: opts.ServerName,
		timeout: opts.Timeout, log: opts.Logger, kind: "probe",
	}, identity.Store{Dir: opts.StateDir, Probe: true}, info.GetHostname(), func(ctx context.Context, u, serverName, pin string, csrPEM []byte) (*issued, error) {
		client, closeIdle, err := controlplane.NewPinnedProbeClient(u, serverName, pin)
		if err != nil {
			return nil, err
		}
		defer closeIdle()
		resp, err := client.EnrollProbe(ctx, connect.NewRequest(&nodev1.EnrollProbeRequest{
			Token:  opts.Token,
			CsrPem: string(csrPEM),
			Info:   info,
		}))
		if err != nil {
			return nil, err
		}
		msg := resp.Msg
		if msg.GetProbeId() == "" {
			return nil, responseError{errors.New("enroll response: empty probe_id")}
		}
		return &issued{
			id:      identity.Identity{ProbeID: msg.GetProbeId(), ProbeName: msg.GetProbeName(), RegionID: msg.GetRegionId()},
			subject: msg.GetProbeId(),
			certPEM: msg.GetCertificatePem(),
			caPEM:   msg.GetCaCertificatePem(),
		}, nil
	})
}

// common are the settings shared by node and probe enrollments.
type common struct {
	serverURL, token, caSHA256, serverName string
	force                                  bool
	timeout                                time.Duration
	log                                    *slog.Logger
	kind                                   string // "node" or "probe", for messages
}

// issued is the console's answer: the identity metadata, the expected
// certificate CN and the PEM certificate and CA.
type issued struct {
	id             identity.Identity
	subject        string
	certPEM, caPEM string
}

// exchange sends the token and CSR over a client pinned to pin.
type exchange func(ctx context.Context, serverURL, serverName, pin string, csrPEM []byte) (*issued, error)

func run(ctx context.Context, c common, store identity.Store, hostname string, send exchange) (*identity.Identity, error) {
	log := c.log
	if log == nil {
		log = slog.Default()
	}
	if c.token == "" {
		return nil, fmt.Errorf("%w: enrollment token is required", ErrInvalidOptions)
	}
	pin, err := pki.NormalizePin(c.caSHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOptions, err)
	}
	u, err := controlplane.ParseServerURL(c.serverURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOptions, err)
	}
	serverName := c.serverName
	if serverName == "" {
		serverName = u.Hostname()
	}

	if err := alreadyEnrolled(store, c.force); err != nil {
		return nil, err
	}
	// Fail before burning the single-use token if the state directory is
	// not writable.
	if err := checkWritable(store); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateDir, err)
	}
	// One enrollment at a time: a second one (a retry while the first
	// still runs) would use another token for the same host.
	releaseEnroll, err := store.LockEnroll()
	if errors.Is(err, identity.ErrEnrolling) {
		return nil, ErrBusy
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateDir, err)
	}
	defer releaseEnroll()
	// The enrollment that held the lock may just have finished.
	if err := alreadyEnrolled(store, c.force); err != nil {
		return nil, err
	}
	// A first enrollment is what a waiting agent expects; replacing the
	// identity of a running one is not. The lock is held until the new
	// identity is saved: an agent that starts meanwhile waits for it.
	if c.force && store.Enrolled() && !store.Probe {
		release, err := store.LockRun()
		if errors.Is(err, identity.ErrRunning) {
			return nil, ErrAgentRunning
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrStateDir, err)
		}
		defer release()
	}

	// The key of an earlier attempt that did not complete is used again
	// (identity.PendingKeyFile).
	key, reused, err := store.PendingKey()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStateDir, err)
	}
	if reused {
		log.Info("using the key of an earlier enrollment attempt that did not complete", "state_dir", store.Dir)
	}
	csrPEM, err := pki.CreateCSR(key, hostname)
	if err != nil {
		return nil, err
	}

	timeout := c.timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	log.Info("enrolling "+c.kind, "server", u.String(), "server_name", serverName, "ca_sha256", pin)
	got, err := send(rctx, u.String(), serverName, pin, csrPEM)
	if err != nil {
		if controlplane.IsAuthError(err) {
			return nil, fmt.Errorf("%w: %w", ErrTokenRejected, err)
		}
		return nil, fmt.Errorf("enroll: %w", err)
	}

	ca, err := pki.ParseCertificatePEM([]byte(got.caPEM))
	if err != nil {
		return nil, responseError{fmt.Errorf("enroll response: CA certificate: %w", err)}
	}
	if fp := pki.Fingerprint(ca); fp != pin {
		return nil, fmt.Errorf("enroll response: %w: CA certificate sha256 %s does not match the pin %s", pki.ErrPinMismatch, fp, pin)
	}
	cert, err := pki.ParseCertificatePEM([]byte(got.certPEM))
	if err != nil {
		return nil, responseError{fmt.Errorf("enroll response: %s certificate: %w", c.kind, err)}
	}
	if err := pki.VerifyNodeCertificate(cert, ca, key, time.Now()); err != nil {
		return nil, responseError{fmt.Errorf("enroll response: %w", err)}
	}
	if cert.Subject.CommonName != got.subject {
		log.Warn(c.kind+" certificate CN differs from the "+c.kind+" id", "cn", cert.Subject.CommonName, "id", got.subject)
	}

	keyPEM, err := pki.MarshalPrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	if c.force {
		if err := store.Remove(); err != nil {
			return nil, fmt.Errorf("%w: remove previous identity: %w", ErrStateDir, err)
		}
	}
	id := got.id
	id.ServerURL, id.ServerName, id.CASHA256 = u.String(), serverName, pin
	id.EnrolledAt = time.Now().UTC().Truncate(time.Second)
	if err := store.Save(id, keyPEM, []byte(got.certPEM), []byte(got.caPEM)); err != nil {
		return nil, fmt.Errorf("%w: persist identity: %w", ErrStateDir, err)
	}
	if store.Probe {
		log.Info("probe enrolled", "probe_id", id.ProbeID, "probe_name", id.ProbeName, "region_id", id.RegionID,
			"certificate_not_after", cert.NotAfter.UTC().Format(time.RFC3339), "state_dir", store.Dir)
	} else {
		log.Info("node enrolled",
			"node_id", id.NodeID, "cluster_id", id.ClusterID, "node_name", id.NodeName,
			"certificate_not_after", cert.NotAfter.UTC().Format(time.RFC3339), "state_dir", store.Dir)
	}
	return &id, nil
}

// alreadyEnrolled refuses an enrolled state directory unless force.
func alreadyEnrolled(store identity.Store, force bool) error {
	if !store.Enrolled() || force {
		return nil
	}
	if store.Probe {
		return ErrProbeAlreadyEnrolled
	}
	return ErrAlreadyEnrolled
}

// Existing returns the identity of an enrolled node in stateDir when it
// pins the CA caSHA256 (the same console), with ErrEnrolledElsewhere when
// it pins another one, and identity.ErrNotEnrolled when there is none.
// Nothing is sent and no token is needed (`enroll --if-not-enrolled`).
func Existing(stateDir, caSHA256 string) (*identity.Identity, error) {
	pin, err := pki.NormalizePin(caSHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidOptions, err)
	}
	id, err := identity.Store{Dir: stateDir}.ReadIdentity()
	if err != nil {
		return nil, err
	}
	if id.CASHA256 != pin {
		return id, ErrEnrolledElsewhere
	}
	return id, nil
}

func checkWritable(store identity.Store) error {
	if err := store.EnsureDir(); err != nil {
		return err
	}
	f, err := os.CreateTemp(store.Dir, ".write-test-*")
	if err != nil {
		return fmt.Errorf("state dir %s is not writable: %w", store.Dir, err)
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}
