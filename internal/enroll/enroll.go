// Package enroll implements `edgeweir-node enroll`: it exchanges a
// single-use token and a locally generated CSR for a node certificate
// issued by the console's internal CA.
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

	"github.com/edgeweir/edgeweir-node/internal/controlplane"
	nodev1 "github.com/edgeweir/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/edgeweir/edgeweir-node/internal/hostinfo"
	"github.com/edgeweir/edgeweir-node/internal/identity"
	"github.com/edgeweir/edgeweir-node/internal/pki"
)

// ErrAlreadyEnrolled is returned when an identity exists and Force is off.
var ErrAlreadyEnrolled = errors.New("node is already enrolled (use --force to replace the identity)")

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
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	if opts.Token == "" {
		return nil, errors.New("enrollment token is required")
	}
	pin, err := pki.NormalizePin(opts.CASHA256)
	if err != nil {
		return nil, err
	}
	u, err := controlplane.ParseServerURL(opts.ServerURL)
	if err != nil {
		return nil, err
	}
	serverName := opts.ServerName
	if serverName == "" {
		serverName = u.Hostname()
	}

	store := identity.Store{Dir: opts.StateDir}
	if store.Enrolled() && !opts.Force {
		return nil, ErrAlreadyEnrolled
	}
	// Fail before burning the single-use token if the state directory is
	// not writable.
	if err := checkWritable(store); err != nil {
		return nil, err
	}

	key, err := pki.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	info := opts.Info
	if info == nil {
		info = hostinfo.Collect("")
	}
	csrPEM, err := pki.CreateCSR(key, info.GetHostname())
	if err != nil {
		return nil, err
	}

	client, closeIdle, err := controlplane.NewPinnedClient(u.String(), serverName, pin)
	if err != nil {
		return nil, err
	}
	defer closeIdle()

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	log.Info("enrolling node", "server", u.String(), "server_name", serverName, "ca_sha256", pin)
	resp, err := client.Enroll(rctx, connect.NewRequest(&nodev1.EnrollRequest{
		Token:  opts.Token,
		CsrPem: string(csrPEM),
		Info:   info,
	}))
	if err != nil {
		if controlplane.IsAuthError(err) {
			return nil, fmt.Errorf("console rejected the enrollment token (expired or already used): %w", err)
		}
		return nil, fmt.Errorf("enroll: %w", err)
	}
	msg := resp.Msg

	ca, err := pki.ParseCertificatePEM([]byte(msg.GetCaCertificatePem()))
	if err != nil {
		return nil, fmt.Errorf("enroll response: CA certificate: %w", err)
	}
	if got := pki.Fingerprint(ca); got != pin {
		return nil, fmt.Errorf("enroll response: CA certificate sha256 %s does not match the pin %s", got, pin)
	}
	cert, err := pki.ParseCertificatePEM([]byte(msg.GetCertificatePem()))
	if err != nil {
		return nil, fmt.Errorf("enroll response: node certificate: %w", err)
	}
	if err := pki.VerifyNodeCertificate(cert, ca, key, time.Now()); err != nil {
		return nil, fmt.Errorf("enroll response: %w", err)
	}
	if msg.GetNodeId() == "" {
		return nil, errors.New("enroll response: empty node_id")
	}
	if cert.Subject.CommonName != msg.GetNodeId() {
		log.Warn("node certificate CN differs from node_id", "cn", cert.Subject.CommonName, "node_id", msg.GetNodeId())
	}

	keyPEM, err := pki.MarshalPrivateKeyPEM(key)
	if err != nil {
		return nil, err
	}
	if opts.Force {
		if err := store.Remove(); err != nil {
			return nil, fmt.Errorf("remove previous identity: %w", err)
		}
	}
	id := identity.Identity{
		NodeID:     msg.GetNodeId(),
		ClusterID:  msg.GetClusterId(),
		NodeName:   msg.GetNodeName(),
		ServerURL:  u.String(),
		ServerName: serverName,
		CASHA256:   pin,
		EnrolledAt: time.Now().UTC().Truncate(time.Second),
	}
	if err := store.Save(id, keyPEM, []byte(msg.GetCertificatePem()), []byte(msg.GetCaCertificatePem())); err != nil {
		return nil, fmt.Errorf("persist identity: %w", err)
	}
	log.Info("node enrolled",
		"node_id", id.NodeID, "cluster_id", id.ClusterID, "node_name", id.NodeName,
		"certificate_not_after", cert.NotAfter.UTC().Format(time.RFC3339), "state_dir", store.Dir)
	return &id, nil
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
