package probe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"runtime"
	"time"

	"connectrpc.com/connect"

	"github.com/marvinli001/edgeweir-node/internal/controlplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/hostinfo"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/pki"
	"github.com/marvinli001/edgeweir-node/internal/version"
)

// ErrNotEnrolled is returned by Main when the state directory holds no
// probe identity and the enrollment settings are incomplete.
var ErrNotEnrolled = errors.New("probe is not enrolled: the first run needs --server, --ca-sha256 and a probe token " +
	"(EDGEWEIR_TOKEN, --token-file or --token)")

// Options configure a standalone probe (`edgeweir-node probe`).
type Options struct {
	// Enrollment (first run only): console node-channel URL, one-time
	// probe token, CA pin and an optional TLS server name.
	ServerURL  string
	Token      string
	CASHA256   string
	ServerName string
	// StateDir holds the probe identity (probe.key 0600, probe.crt, ca.crt,
	// probe.json).
	StateDir string
	// Timeout bounds every RPC, the enrollment included (default 30s).
	Timeout time.Duration
	Log     *slog.Logger

	// Tests: the prober and the backoff bounds of enrollment retries and
	// failed rounds (defaults 1s and 30s / 60s).
	Prober     *Prober
	BackoffMin time.Duration
	BackoffMax time.Duration
}

// Info describes this process in GetProbeTargets and EnrollProbe.
func Info() *nodev1.ProbeInfo {
	return &nodev1.ProbeInfo{Hostname: hostinfo.Hostname(), AgentVersion: version.Version, Os: runtime.GOOS, Arch: runtime.GOARCH}
}

// Main enrolls the probe on its first start and then runs rounds until ctx
// is done. A token given once the probe is enrolled is ignored. It never
// starts OpenResty.
func Main(ctx context.Context, o Options) error {
	log := o.Log
	if log == nil {
		log = slog.Default()
	}
	store := identity.Store{Dir: o.StateDir, Probe: true}
	info := Info()
	if !store.Enrolled() {
		if o.Token == "" || o.ServerURL == "" || o.CASHA256 == "" {
			return ErrNotEnrolled
		}
		if err := enrollWithRetry(ctx, o, info, log); err != nil {
			return err
		}
	} else if o.Token != "" {
		log.Info("probe already enrolled; ignoring the enrollment token", "state_dir", store.Dir)
	}
	ch, err := controlplane.NewChannel(store)
	if err != nil {
		return fmt.Errorf("load the probe identity from %s: %w", store.Dir, err)
	}
	defer ch.Close()
	id := ch.Identity()
	if o.ServerURL != "" && o.ServerURL != id.ServerURL {
		log.Warn("--server differs from the console this probe enrolled with; using the enrolled one", "server", id.ServerURL)
	}
	log.Info("starting edgeweir-node probe", "version", version.Version, "probe_id", id.ProbeID, "probe_name", id.ProbeName,
		"region_id", id.RegionID, "server", id.ServerURL, "state_dir", store.Dir,
		"certificate_not_after", id.Certificate.NotAfter.UTC().Format(time.RFC3339))
	rn := &renewer{ch: ch, store: store, log: log, timeout: o.Timeout}
	r := &Runner{
		Client:       ch.ProbeClient,
		Info:         info,
		Renew:        rn.renew,
		NeedsRenewal: func() bool { return pki.NeedsRenewal(ch.Identity().Certificate, time.Now()) },
		Prober:       o.Prober,
		Log:          log,
		RPCTimeout:   o.Timeout,
		BackoffMin:   o.BackoffMin,
		BackoffMax:   o.BackoffMax,
	}
	r.Run(ctx)
	log.Info("probe stopped")
	return nil
}

// enrollWithRetry enrolls, retrying while the console is unreachable or
// busy; a rejected token, a CA pin mismatch or any other answer ends it.
func enrollWithRetry(ctx context.Context, o Options, info *nodev1.ProbeInfo, log *slog.Logger) error {
	minWait, maxWait := o.BackoffMin, o.BackoffMax
	if minWait <= 0 {
		minWait = time.Second
	}
	if maxWait < minWait {
		maxWait = max(30*time.Second, minWait)
	}
	backoff := minWait
	for {
		_, err := enroll.Probe(ctx, enroll.ProbeOptions{
			ServerURL: o.ServerURL, Token: o.Token, CASHA256: o.CASHA256, ServerName: o.ServerName,
			StateDir: o.StateDir, Info: info, Timeout: o.Timeout, Logger: log,
		})
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !transient(err) {
			return fmt.Errorf("probe enrollment failed: %w", err)
		}
		wait := backoff/2 + rand.N(backoff/2+1)
		log.Warn("probe enrollment failed; retrying in "+wait.Round(time.Millisecond).String(), "err", err)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
		backoff = min(backoff*2, maxWait)
	}
}

// transient reports whether an enrollment failure is worth retrying with
// the same token: the console was unreachable or busy.
func transient(err error) bool {
	if errors.Is(err, pki.ErrPinMismatch) {
		return false
	}
	switch connect.CodeOf(err) {
	case connect.CodeUnavailable, connect.CodeDeadlineExceeded, connect.CodeResourceExhausted, connect.CodeAborted:
		return true
	}
	return false
}

// renewer renews the probe certificate with a fresh key (at most once a
// minute) and reloads the channel.
type renewer struct {
	ch      *controlplane.Channel
	store   identity.Store
	log     *slog.Logger
	timeout time.Duration
	last    time.Time
}

func (r *renewer) renew(ctx context.Context, reason string) {
	if time.Since(r.last) < time.Minute {
		return
	}
	r.last = time.Now()
	if err := r.do(ctx); err != nil {
		r.log.Warn("probe certificate renewal failed", "reason", reason, "err", err)
		return
	}
	r.log.Info("probe certificate renewed", "reason", reason,
		"not_after", r.ch.Identity().Certificate.NotAfter.UTC().Format(time.RFC3339))
}

func (r *renewer) do(ctx context.Context) error {
	id := r.ch.Identity()
	key, err := pki.GenerateKey()
	if err != nil {
		return err
	}
	csr, err := pki.CreateCSR(key, id.ProbeID)
	if err != nil {
		return err
	}
	timeout := r.timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := r.ch.ProbeClient().RenewProbeCertificate(cctx, connect.NewRequest(&nodev1.RenewProbeCertificateRequest{CsrPem: string(csr)}))
	if err != nil {
		return err
	}
	cert, err := pki.ParseCertificatePEM([]byte(resp.Msg.GetCertificatePem()))
	if err != nil {
		return err
	}
	// The pinned CA stays authoritative.
	if err := pki.VerifyNodeCertificate(cert, id.CA, key, time.Now()); err != nil {
		return err
	}
	if caPEM := resp.Msg.GetCaCertificatePem(); caPEM != "" {
		if ca, err := pki.ParseCertificatePEM([]byte(caPEM)); err != nil || !ca.Equal(id.CA) {
			r.log.Warn("console returned a different CA certificate; keeping the pinned CA")
		}
	}
	keyPEM, err := pki.MarshalPrivateKeyPEM(key)
	if err != nil {
		return err
	}
	if err := r.store.SwapCertificate(keyPEM, []byte(resp.Msg.GetCertificatePem())); err != nil {
		return err
	}
	return r.ch.Reload()
}
