// Package agent is the edgeweir-node runtime (`edgeweir-node run`).
//
// Lifecycle:
//
//	start ─► serve LKG (or the bootstrap config) ─► wait for enrollment
//	      ─► mTLS channel ─► watch + poll ─► fetch (snapshot | diff)
//	      ─► verify hash ─► validate ─► render/test/reload (structural only)
//	      ─► push site table to Lua ─► persist LKG ─► ReportStatus
//
// Dynamic bans travel outside revisions (bans.go): GetBans ─► bans.json
// ─► Lua (delta or full set) and nftables for platform bans.
//
// The data plane keeps serving the last-known-good configuration whenever
// the console is unreachable or a new configuration is rejected.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/bans"
	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/configstore"
	"github.com/marvinli001/edgeweir-node/internal/controlplane"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/geoip"
	"github.com/marvinli001/edgeweir-node/internal/healthcheck"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/metrics"
	"github.com/marvinli001/edgeweir-node/internal/nft"
	"github.com/marvinli001/edgeweir-node/internal/probe"
	"github.com/marvinli001/edgeweir-node/internal/render"
)

// Engine is the data plane process controller (see package engine).
type Engine interface {
	// Run supervises the engine until ctx is done (no-op when unmanaged).
	Run(ctx context.Context) error
	Version(ctx context.Context) (string, error)
	// Test validates a configuration file without applying it.
	Test(ctx context.Context, conf string) error
	// Reload applies the installed configuration file (starting the
	// engine if it is managed and not running).
	Reload(ctx context.Context) error
	Running() bool
	// Started fires whenever a managed engine (re)starts.
	Started() <-chan struct{}
	// ModuleFeatures returns the features of the optional static modules
	// compiled into the engine (brotli-v1, zstd-v1).
	ModuleFeatures(ctx context.Context) ([]string, error)
}

// DataPlane is the Lua control API (see package dataplane).
type DataPlane interface {
	Status(ctx context.Context) (*dataplane.Status, error)
	PutSites(ctx context.Context, t *dataplane.SiteTable) (*dataplane.Status, error)
	DrainStats(ctx context.Context) ([]dataplane.MinuteStats, error)
	PutPurge(ctx context.Context, t *dataplane.PurgeTable) (*dataplane.PurgeStatus, error)
	AddPurge(ctx context.Context, t *dataplane.PurgeTable) (*dataplane.PurgeStatus, error)
	OriginHealth(ctx context.Context) ([]dataplane.OriginHealth, error)
	BanStatus(ctx context.Context) (*dataplane.BanStatus, error)
	PutBans(ctx context.Context, t *dataplane.BanTable) (*dataplane.BanStatus, error)
	AddBans(ctx context.Context, d *dataplane.BanDelta) (*dataplane.BanStatus, error)
	DrainAutoBans(ctx context.Context) ([]dataplane.AutoBan, error)
	ReleaseOwnBans(ctx context.Context, list []dataplane.OwnBanRelease) (int, error)
	ChallengeStatus(ctx context.Context) (*dataplane.ChallengeStatus, error)
	PutChallengeKeys(ctx context.Context, k *dataplane.ChallengeKeys) (*dataplane.ChallengeStatus, error)
	PutCaptchas(ctx context.Context, p *dataplane.CaptchaPool) (*dataplane.ChallengeStatus, error)
	SecurityStatus(ctx context.Context) (*dataplane.SecurityStatus, error)
	DrainSecurity(ctx context.Context) ([]dataplane.SecurityEvent, error)
	PutActiveHealth(ctx context.Context, doc *dataplane.ActiveHealth) (*dataplane.ActiveHealthStatus, error)
	// Layer-4 applications (the stream subsystem, through the control API).
	L4Status(ctx context.Context) (*dataplane.L4Status, error)
	PutL4(ctx context.Context, t *dataplane.L4Table) (*dataplane.L4Status, error)
	DrainL4Stats(ctx context.Context) ([]dataplane.L4MinuteStats, error)
}

// Config configures the agent.
type Config struct {
	// StateDir holds the identity and the LKG configuration.
	StateDir         string
	SupervisorSocket string
	// ConfPath is where nginx.conf is written (inside the nginx prefix).
	ConfPath string
	// Render holds the node-local nginx.conf settings.
	Render render.Params
	// DefaultPort is served before any configuration exists.
	DefaultPort uint32
	// GeoIP selects the local MMDBs; an empty path disables that source.
	GeoIP geoip.Paths

	EnrollPollInterval time.Duration // default 2s
	PollInterval       time.Duration // GetConfig fallback poll, default 30s
	ReportInterval     time.Duration // heartbeat until the console says otherwise, default 15s
	StatsInterval      time.Duration // default 60s
	DataPlaneInterval  time.Duration // data plane health/resync check, default 5s
	WatchIdleTimeout   time.Duration // no message (incl. keepalive) for this long = dead stream, default 45s
	WatchBackoffMin    time.Duration // default 1s
	WatchBackoffMax    time.Duration // default 30s
	PushTimeout        time.Duration // retry budget for pushing a site table, default 15s
	ReloadTimeout      time.Duration // wait for workers running a new nginx.conf, default 15s
	RPCTimeout         time.Duration // unary RPC timeout, default 30s
	TaskPollInterval   time.Duration // PullTasks fallback poll, default 30s

	// PurgeMarkersPerSite bounds a site's URL and prefix purge markers,
	// PurgeTagsPerSite its tag markers; beyond either the site's markers
	// collapse into one site-level marker (defaults 1000 and 5000).
	PurgeMarkersPerSite int
	PurgeTagsPerSite    int

	// Prefetch tasks request URLs from the node's own edge listener.
	PrefetchHost        string        // default 127.0.0.1
	PrefetchConcurrency int           // default 4
	PrefetchTimeout     time.Duration // per URL, default 60s
	// PrefetchBudget bounds the prefetches of one pulled batch, counted
	// from the pull (default 4m: the console hands a task out again after
	// 5 minutes without a result).
	PrefetchBudget time.Duration

	// BanCapacity is the number of bans the data plane holds (default
	// render.DefaultBanCapacity; the same value goes into nginx.conf).
	BanCapacity int
	// Kernel runs nft scripts for kernel bans; nil disables them.
	Kernel nft.Executor
	// AutoBanInterval: the node's own bans are drained and reported this
	// often (default 5s).
	AutoBanInterval time.Duration
	// BanRetryInterval: manual bans that did not fit are retried this often
	// (default 1m).
	BanRetryInterval time.Duration
	// CaptchaInterval: a new captcha pool of CaptchaPoolSize images is
	// generated this often while the configuration uses challenges
	// (default 10m, 256 images).
	CaptchaInterval time.Duration
	CaptchaPoolSize int
	// SecurityInterval: CC events are drained and reported this often
	// (default 5s).
	SecurityInterval time.Duration
	// ChallengeKeyRetry: challenge keys the configuration names but the
	// console did not hand out are asked for again this often (default 30s).
	ChallengeKeyRetry time.Duration

	// ActiveHealth configures the active health checker; the agent sets
	// the trust store (unless RootCAs is set), IPv6 and OnChange. Tests
	// replace the resolver, dialer and clock.
	ActiveHealth healthcheck.Options
	// ActiveHealthRefresh: the active health marks are pushed again this
	// often (default 30s).
	ActiveHealthRefresh time.Duration

	// Prober probes the other nodes while the console lets this node probe
	// (nil: the defaults; tests replace the dialer).
	Prober *probe.Prober
	// Metrics measures the host metrics of the heartbeats (nil: /proc on
	// Linux, none elsewhere).
	Metrics *metrics.Collector
}

func (c *Config) setDefaults() {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&c.EnrollPollInterval, 2*time.Second)
	def(&c.PollInterval, 30*time.Second)
	def(&c.ReportInterval, 15*time.Second)
	def(&c.StatsInterval, time.Minute)
	def(&c.DataPlaneInterval, 5*time.Second)
	def(&c.WatchIdleTimeout, 45*time.Second)
	def(&c.WatchBackoffMin, time.Second)
	def(&c.WatchBackoffMax, 30*time.Second)
	def(&c.PushTimeout, 15*time.Second)
	def(&c.ReloadTimeout, 15*time.Second)
	def(&c.RPCTimeout, 30*time.Second)
	def(&c.TaskPollInterval, 30*time.Second)
	def(&c.PrefetchTimeout, time.Minute)
	def(&c.PrefetchBudget, 4*time.Minute)
	def(&c.AutoBanInterval, 5*time.Second)
	def(&c.BanRetryInterval, time.Minute)
	def(&c.CaptchaInterval, 10*time.Minute)
	def(&c.SecurityInterval, 5*time.Second)
	def(&c.ChallengeKeyRetry, 30*time.Second)
	def(&c.ActiveHealthRefresh, 30*time.Second)
	if c.CaptchaPoolSize <= 0 {
		c.CaptchaPoolSize = 256
	}
	if c.BanCapacity <= 0 {
		c.BanCapacity = render.DefaultBanCapacity
	}
	if c.PrefetchHost == "" {
		c.PrefetchHost = "127.0.0.1"
	}
	if c.PrefetchConcurrency <= 0 {
		c.PrefetchConcurrency = 4
	}
	if c.PurgeMarkersPerSite <= 0 {
		c.PurgeMarkersPerSite = DefaultPurgeMarkersPerSite
	}
	if c.PurgeTagsPerSite <= 0 {
		c.PurgeTagsPerSite = DefaultPurgeTagsPerSite
	}
	if c.DefaultPort == 0 {
		c.DefaultPort = 80
	}
	if c.Metrics == nil {
		c.Metrics = metrics.New()
	}
}

// Agent is the node runtime.
type Agent struct {
	cfg    Config
	log    *slog.Logger
	engine Engine
	dp     DataPlane
	ids    identity.Store
	lkg    configstore.Store

	geoFeatures []string
	// moduleFeatures are the optional OpenResty modules this node can use
	// (brotli-v1, zstd-v1, modsecurity-v1), detected at startup.
	moduleFeatures []string
	engineVersion  string
	channel        *controlplane.Channel
	// connectedCh is channel for loops that start before enrollment.
	connectedCh   atomic.Pointer[controlplane.Channel]
	nodeID        string // guarded by mu; empty until the identity is known
	connectedOnce sync.Once

	mu        sync.Mutex
	applied   *nodev1.NodeConfig // LKG in effect; nil while on the bootstrap config
	appliedAt time.Time
	plan      *configir.Plan       // plan in effect (listeners and zones for tasks)
	desired   *dataplane.SiteTable // table the data plane must serve
	// desiredL4 is the layer-4 table the stream subsystem must serve (nil:
	// the plan has no layer-4 applications, nginx.conf no stream block).
	desiredL4    *dataplane.L4Table
	creds        map[string]configir.Credential
	certificates map[string]configir.Certificate
	purge        *purgeState
	lastPrune    time.Time
	// purgeRetryAt: after installing the site-level fallback of the marker
	// set, the full set is tried again from then on.
	purgeRetryAt time.Time
	unreported   []*nodev1.ReportTaskResultRequest
	conf         []byte // nginx.conf currently installed
	state        nodev1.ApplyState
	message      string
	dpHealthy    bool
	rejectedKey  string
	rejectedAt   time.Time
	lastRenew    time.Time

	banStatus *dataplane.BanStatus // last ban status of the data plane (mu)

	pushMu       sync.Mutex
	activationMu sync.Mutex // structural reload and table activation/compensation
	purgeMu      sync.Mutex // serializes purge writes to the data plane
	syncCh       chan struct{}
	reportCh     chan struct{}
	taskCh       chan struct{}

	// Dynamic bans (bans.go). banMu serializes changes of the applied
	// state and writes of bans to the data plane.
	banMu          sync.Mutex
	bans           *bans.State
	banForcePut    bool                       // the next write replaces the whole set
	banSent        map[bans.SlotKey]bans.Slot // what the data plane was given (nil: unknown)
	banSentSeq     uint64                     // ... under this sequence
	banRetryAt     time.Time                  // next retry of unfit manual bans
	banDropped     uint64                     // automatic bans left out for capacity
	banDroppedSeen map[string]time.Time       // ... counted once each
	banCh          chan struct{}
	banReleases    []dataplane.OwnBanRelease // own bans the console lifted, not deleted yet (bansLoop only)
	banUnsupported sync.Once                 // logs an older console once
	nft            *nft.Manager              // nil without kernel bans
	kernelCh       chan struct{}

	addrMu            sync.Mutex
	consoleAddrsCache []netip.Prefix
	consoleAddrsAt    time.Time

	// Challenges (challenge.go): keys by id (challengeMu), the captcha
	// pool pushed last (challengePushMu, which also serializes pushes).
	challengeMu         sync.Mutex
	challengeKeys       map[string][]byte
	challengePushMu     sync.Mutex
	captchaID           string
	captchaCh           chan struct{}
	keysFetchedAt       time.Time // data plane loop only
	securityUnsupported sync.Once

	// Active health checks (activehealth.go). activeMu serializes the
	// pushes; activeMarks: the data plane may hold marks (unknown at
	// startup); activeDown: the origins of the last push.
	health      *healthcheck.Checker
	activeCh    chan struct{}
	activeMu    sync.Mutex
	activeMarks bool
	activeDown  map[healthcheck.Key]bool

	// healthCert is the self-signed certificate of SNI
	// health.edgeweir.invalid (healthcert.go), loaded at startup.
	healthCert *configir.Certificate

	// Probing the other nodes (probe.go) while the console asks for it.
	probeMu     sync.Mutex
	probeCancel context.CancelFunc
	probeDone   chan struct{}
}

// New creates an agent.
func New(cfg Config, eng Engine, dp DataPlane, log *slog.Logger) *Agent {
	cfg.setDefaults()
	if log == nil {
		log = slog.Default()
	}
	a := &Agent{
		cfg:          cfg,
		log:          log,
		engine:       eng,
		dp:           dp,
		ids:          identity.Store{Dir: cfg.StateDir},
		lkg:          configstore.Store{Dir: filepath.Join(cfg.StateDir, identity.ConfigDir)},
		message:      "waiting for the first configuration",
		creds:        map[string]configir.Credential{},
		certificates: map[string]configir.Certificate{},
		purge:        newPurgeState(),
		syncCh:       make(chan struct{}, 1),
		reportCh:     make(chan struct{}, 1),
		taskCh:       make(chan struct{}, 1),

		bans:           bans.New(),
		banDroppedSeen: map[string]time.Time{},
		banCh:          make(chan struct{}, 1),
		kernelCh:       make(chan struct{}, 1),
		nft:            kernelManager(cfg.Kernel, log),

		challengeKeys: map[string][]byte{},
		captchaCh:     make(chan struct{}, 1),

		activeCh:    make(chan struct{}, 1),
		activeMarks: true,
	}
	a.health = a.newHealthChecker()
	return a
}

func kernelManager(exec nft.Executor, log *slog.Logger) *nft.Manager {
	if exec == nil {
		return nil
	}
	return nft.NewManager(exec, log)
}

// Run runs the agent until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.prepareDirs(); err != nil {
		return err
	}
	if err := a.loadHealthCertificate(); err != nil {
		return err
	}
	databases, err := geoip.Open(a.cfg.GeoIP)
	if err != nil {
		return fmt.Errorf("load GeoIP: %w", err)
	}
	defer databases.Close()
	if databases.IPinfoErr != nil {
		a.log.Error("bundled IPinfo Lite database rejected; continuing without it", "err", databases.IPinfoErr)
	}
	a.geoFeatures = databases.Features()
	if len(a.geoFeatures) > 0 {
		attrs := []any{"features", a.geoFeatures}
		if built := databases.IPinfoBuilt(); !built.IsZero() {
			attrs = append(attrs, "ipinfo", a.cfg.GeoIP.IPinfo, "ipinfo_built", built.Format(time.DateOnly))
		}
		a.log.Info("GeoIP databases loaded", attrs...)
		l, err := databases.Serve(ctx, a.cfg.Render.WithDefaults().GeoIPSocket)
		if err != nil {
			return err
		}
		defer l.Close()
		if err := chownToUser(a.cfg.Render.User, a.cfg.Render.WithDefaults().GeoIPSocket); err != nil {
			return err
		}
	}
	if v, err := a.engine.Version(ctx); err != nil {
		a.log.Warn("cannot determine engine version", "err", err)
	} else {
		a.engineVersion = v
	}
	a.detectModules(ctx)

	var wg sync.WaitGroup
	spawn := func(name string, f func(context.Context)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f(ctx)
			a.log.Debug("loop stopped", "loop", name)
		}()
	}
	defer wg.Wait()

	spawn("engine", func(ctx context.Context) {
		if err := a.engine.Run(ctx); err != nil {
			a.log.Error("engine supervisor stopped", "err", err)
		}
	})
	a.loadCredentials()
	a.loadCertificates()
	a.loadPurge()
	a.loadChallengeKeys()
	defer a.health.Close()
	a.serveInitialConfig(ctx)
	a.startBans(ctx)
	// Runs before the loops finish (defers are last in, first out); a sync
	// after it finds the manager inactive.
	defer a.stopKernel()
	spawn("dataplane", a.dataPlaneLoop)
	spawn("activehealth", a.activeHealthLoop)
	spawn("ocsp", a.ocspLoop)
	spawn("kernel", a.kernelLoop)
	spawn("captchas", a.captchaLoop)

	if err := a.ids.WaitForEnrollment(ctx, a.cfg.EnrollPollInterval, a.log); err != nil {
		return nil // shutting down
	}
	ch, err := a.openChannel(ctx)
	if err != nil {
		return nil // shutting down
	}
	a.channel = ch
	a.connectedCh.Store(ch)
	defer ch.Close()
	id := ch.Identity()
	a.mu.Lock()
	a.nodeID = id.NodeID
	a.mu.Unlock()
	a.log.Info("node identity loaded", "node_id", id.NodeID, "cluster_id", id.ClusterID,
		"node_name", id.NodeName, "server", id.ServerURL,
		"certificate_not_after", id.Certificate.NotAfter.UTC().Format(time.RFC3339))
	// The console's addresses join the nftables allow list before the
	// first RPC.
	a.syncKernel(ctx)

	spawn("sync", a.syncLoop)
	spawn("watch", a.watchLoop)
	spawn("poll", a.pollLoop)
	spawn("report", a.reportLoop)
	spawn("stats", a.statsLoop)
	spawn("logs", a.logsLoop)
	spawn("tasks", a.taskLoop)
	spawn("bans", a.bansLoop)
	spawn("autobans", a.autoBansLoop)
	spawn("security", a.securityLoop)
	// Runs before the loops are waited for: the probe loop is not one of
	// them (it follows the heartbeat answers).
	defer a.stopProbing()
	a.triggerSync()
	a.triggerBans()

	<-ctx.Done()
	a.log.Info("shutting down")
	return nil
}

// openChannel loads the identity, retrying while it is unreadable (e.g.
// an enrollment is being written or files were damaged).
func (a *Agent) openChannel(ctx context.Context) (*controlplane.Channel, error) {
	for {
		ch, err := controlplane.NewChannel(a.ids)
		if err == nil {
			return ch, nil
		}
		a.log.Error("cannot load node identity; retrying (re-enroll with `edgeweir-node enroll --force` if this persists)", "err", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
}

func (a *Agent) prepareDirs() error {
	prefix := a.cfg.Render.Prefix
	dirs := []struct {
		path string
		mode os.FileMode
	}{
		{a.cfg.StateDir, 0o700},
		{filepath.Join(prefix, "conf"), 0o750},
		{filepath.Join(prefix, "logs"), 0o750},
		{filepath.Join(prefix, "tmp"), 0o750},
		{a.cfg.Render.CacheDir, 0o750},
		{filepath.Dir(a.cfg.Render.ControlSocket), 0o750},
		{filepath.Dir(a.cfg.Render.WithDefaults().EdgeSocket), 0o750},
		{filepath.Dir(a.cfg.Render.WithDefaults().L4Socket), 0o750},
		{filepath.Dir(a.cfg.Render.OriginSocket), 0o750},
		{filepath.Dir(a.cfg.ConfPath), 0o750},
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return fmt.Errorf("create %s: %w", d.path, err)
		}
	}
	if err := chownToUser(a.cfg.Render.User, filepath.Join(prefix, "tmp"), a.cfg.Render.CacheDir); err != nil {
		return err
	}
	return nil
}

func (a *Agent) buildOptions() configir.Options {
	opts := configir.Options{DefaultPort: a.cfg.DefaultPort, ExtraFeatures: a.extraFeatures()}
	if a.channel != nil {
		opts.ClusterID = a.channel.Identity().ClusterID
	}
	return opts
}

// serveInitialConfig brings the data plane up before the console is
// reachable: with the LKG configuration if one is stored and still valid,
// otherwise with the bootstrap configuration (404 for every host).
func (a *Agent) serveInitialConfig(ctx context.Context) {
	cfg, file, err := a.lkg.Load()
	switch {
	case err == nil:
		plan, perr := configir.Build(cfg, a.buildOptions())
		if perr == nil {
			// No console yet: S3 origins use the stored credentials.
			a.attachCredentials(plan)
			perr = a.attachCertificates(plan)
			if perr == nil {
				perr = a.applyPlan(ctx, plan)
			}
		}
		if perr == nil {
			a.mu.Lock()
			a.applied, a.appliedAt = cfg, time.Now()
			a.state = nodev1.ApplyState_APPLY_STATE_APPLIED
			a.message = fmt.Sprintf("restored last-known-good revision %d", cfg.GetRevision())
			a.mu.Unlock()
			a.log.Info("serving last-known-good configuration", "revision", cfg.GetRevision(),
				"content_hash", cfg.GetContentHash(), "file", file, "sites", len(plan.Sites))
			return
		}
		a.log.Error("cannot serve last-known-good configuration; falling back to bootstrap", "revision", cfg.GetRevision(), "err", perr)
	case !errors.Is(err, configstore.ErrNoConfig):
		a.log.Warn("cannot load last-known-good configuration", "err", err)
	default:
		a.log.Info("no configuration yet; serving bootstrap configuration (404 unknown-host)", "port", a.cfg.DefaultPort)
	}
	if err := a.applyPlan(ctx, configir.Bootstrap(a.cfg.DefaultPort)); err != nil {
		a.log.Error("cannot start data plane with the bootstrap configuration", "err", err)
		a.mu.Lock()
		a.state = nodev1.ApplyState_APPLY_STATE_FAILED
		a.message = truncate("bootstrap configuration failed: " + err.Error())
		a.mu.Unlock()
	}
}

// cdnID returns this node's CDN-Loop identifier, reading identity.json
// while the mTLS channel is not open yet (last-known-good at startup).
func (a *Agent) cdnID() string {
	a.mu.Lock()
	id := a.nodeID
	a.mu.Unlock()
	if id == "" {
		if ident, err := a.ids.ReadIdentity(); err == nil {
			id = ident.NodeID
		}
	}
	return dataplane.CDNID(id)
}

func (a *Agent) appliedConfig() *nodev1.NodeConfig {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.applied
}

func (a *Agent) appliedRevision() uint64 { return a.appliedConfig().GetRevision() }

// baseRevision is the revision to request diffs against. A configuration
// from another cluster (node re-enrolled elsewhere) is never used as base.
func (a *Agent) baseRevision() uint64 {
	applied := a.appliedConfig()
	if applied == nil {
		return 0
	}
	if a.channel != nil {
		if c := a.channel.Identity().ClusterID; c != "" && applied.GetClusterId() != "" && c != applied.GetClusterId() {
			return 0
		}
	}
	return applied.GetRevision()
}

func (a *Agent) triggerSync() {
	select {
	case a.syncCh <- struct{}{}:
	default:
	}
}

func (a *Agent) triggerReport() {
	select {
	case a.reportCh <- struct{}{}:
	default:
	}
}

// markConnected logs once that the mTLS channel works.
func (a *Agent) markConnected() {
	a.connectedOnce.Do(func() {
		id := a.channel.Identity()
		// The node id is part of the message so the line is easy to grep
		// for (the console's e2e test waits for it).
		a.log.Info("switched to mTLS channel node_id="+id.NodeID, "node_id", id.NodeID, "cluster_id", id.ClusterID, "server", id.ServerURL)
	})
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

const maxMessage = 4000

func truncate(s string) string {
	if len(s) <= maxMessage {
		return s
	}
	return s[:maxMessage] + "…"
}

func summarizeWarnings(ws []string) string {
	if len(ws) == 0 {
		return ""
	}
	return truncate(fmt.Sprintf("applied with %d warning(s): %s", len(ws), strings.Join(ws, "; ")))
}
