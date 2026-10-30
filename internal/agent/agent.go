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
	"github.com/marvinli001/edgeweir-node/internal/challengeverify"
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
	"github.com/marvinli001/edgeweir-node/internal/nodelog"
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
	DrainStats(ctx context.Context, all bool) ([]dataplane.MinuteStats, error)
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
	DrainL4Stats(ctx context.Context, all bool) ([]dataplane.L4MinuteStats, error)
}

// Config configures the agent.
type Config struct {
	// StateDir holds the identity and the LKG configuration.
	StateDir         string
	SupervisorSocket string
	// DiagSocket is the unix socket of the diagnostics (internal/diag:
	// status and pprof, 0600); empty: none.
	DiagSocket string
	// NodeLogs holds the process's warnings, errors and events (its
	// logger's nodelog.Handler and the engine's LogSink); the agent
	// uploads them (feature node-logs-v1). nil: no node logs.
	NodeLogs *nodelog.Collector
	// DebugLogs is the process's debug log ring (its logger's
	// nodelog.Handler and the engine's DebugSink); the agent uploads it
	// for a DebugLogsTask (feature debug-logs-v1). nil: none.
	DebugLogs *nodelog.Ring
	// NodeLogsUnsupportedRetry: a console without ReportNodeLogs is asked
	// again this often (default 10m).
	NodeLogsUnsupportedRetry time.Duration
	// NodeLogsSealAfter: entries wait at most this long before they are
	// sealed into a batch (default 5s).
	NodeLogsSealAfter time.Duration
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
	TestTimeout        time.Duration // `nginx -t` of a new nginx.conf, default 60s
	RPCTimeout         time.Duration // unary RPC timeout, default 30s
	// CacheUsageInterval is how often the cache zones' disk usage is
	// measured (ReportStatus.cache_usage), default 10m; the first
	// measurement runs after at most a minute.
	CacheUsageInterval time.Duration
	TaskPollInterval   time.Duration // PullTasks fallback poll, default 30s
	// SupervisorHealthInterval: the supervisor hears how the node is this
	// often (default 5s; see supervisorHealthLoop).
	SupervisorHealthInterval time.Duration
	// IdentityInterval: identity.json is compared with the identity in use
	// this often; a new one (re-enrolled) stops the agent so that it starts
	// again with it (default 10s).
	IdentityInterval time.Duration
	// Following the console's node channel address (controlplane.Follower;
	// zero values take its defaults): how long the address in use may fail
	// before the fallback is tried, how often the persisted address is
	// tried again from the fallback, and the waits between checks of an
	// address that failed one. Tests shorten them.
	ChannelFailoverAfter time.Duration
	ChannelRetryPrimary  time.Duration
	ChannelBackoff       []time.Duration

	// PurgeMarkersPerSite bounds a site's URL and prefix purge markers,
	// PurgeTagsPerSite its tag markers; beyond either the site's markers
	// collapse into one site-level marker (defaults 1000 and 5000).
	PurgeMarkersPerSite int
	PurgeTagsPerSite    int

	// Prefetch tasks request URLs through the node's local edge listeners
	// (Render.EdgeSocket, Render.EdgeTLSSocket).
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
	// Image configures the WebP / AVIF converter (ADR-0043); Workers 0
	// turns it off (the node does not announce image-convert-v1).
	Image ImageOptions
	// Markdown configures the Markdown converter (Markdown for Agents);
	// Workers 0 turns it off (the node does not announce markdown-v1).
	Markdown MarkdownOptions
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
	// ChallengeVerify checks the answers of interactive challenge providers
	// (agent socket POST /v1/challenge/verify, feature challenge-v3); nil
	// uses the providers' own endpoints.
	ChallengeVerify *challengeverify.Verifier

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
	def(&c.TestTimeout, time.Minute)
	def(&c.RPCTimeout, 30*time.Second)
	def(&c.CacheUsageInterval, 10*time.Minute)
	def(&c.TaskPollInterval, 30*time.Second)
	def(&c.IdentityInterval, 10*time.Second)
	def(&c.SupervisorHealthInterval, 5*time.Second)
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
	cfg Config
	log *slog.Logger

	// purgeLimit limits the accepted PURGE requests of each site.
	purgeLimit purgeLimiter
	engine     Engine
	dp         DataPlane
	ids        identity.Store
	// tierLatency holds the round trip times to the tiered cache's latency
	// targets (tierLatencyLoop).
	tierLatency tierLatencies
	lkg        configstore.Store
	// stopRun stops Run with a cause (set while Run runs).
	stopRun context.CancelCauseFunc

	geoFeatures []string
	// geo is set while the agent runs with GeoIP databases; locateAddress is
	// the address the console asks it to place itself by and located the
	// lookup of it (all guarded by mu).
	geo           *geoip.Databases
	locateAddress string
	located       *nodev1.NodeLocation
	// moduleFeatures are the optional OpenResty modules this node can use
	// (brotli-v1, zstd-v1, modsecurity-v1), detected at startup.
	moduleFeatures []string
	engineVersion  string
	channel        *controlplane.Channel
	// connectedCh is channel for loops that start before enrollment.
	connectedCh atomic.Pointer[controlplane.Channel]
	// follow moves the channel to the console's address (set with channel).
	follow atomic.Pointer[controlplane.Follower]
	nodeID string // guarded by mu; empty until the identity is known
	// cacheUsage is the last measurement of the cache zones (mu).
	cacheUsage    []*nodev1.CacheZoneUsage
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
	// originClientCerts is the origin client certificates' material by
	// "<id>/<fingerprint>" (origin-client-certificates.json).
	originClientCerts map[string]configir.Certificate
	// certUse: the applied plan's certificates that did not load and the
	// material it serves (certificate-isolation-v1).
	certUse   certificateUse
	purge     *purgeState
	lastPrune time.Time
	// purgeRetryAt: after installing the site-level fallback of the marker
	// set, the full set is tried again from then on.
	purgeRetryAt time.Time
	unreported   []*nodev1.ReportTaskResultRequest
	conf         []byte // nginx.conf currently installed
	state        nodev1.ApplyState
	message      string
	dpHealthy    bool
	lastBeat     heartbeat // for the supervisor (upgrades.go)
	rejectedKey  string
	rejectedAt   time.Time
	lastRenew    time.Time
	// Diagnostics (diag.go): heartbeats and the clock measured with them.
	startedAt      time.Time
	reportOK       time.Time
	reportErr      string
	reportErrAt    time.Time
	reportInterval time.Duration
	latestRevision uint64
	clock          *clockSample

	banStatus *dataplane.BanStatus // last ban status of the data plane (mu)

	pushMu       sync.Mutex
	activationMu sync.Mutex // structural reload and table activation/compensation
	purgeMu      sync.Mutex // serializes purge writes to the data plane
	syncCh       chan struct{}
	reportCh     chan struct{}
	taskCh       chan struct{}
	purgeCh      chan struct{} // wakes purgeLoop

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
	consoleHostsKey   string
	consoleHostAddrs  map[string][]netip.Prefix

	// Challenges (challenge.go): keys by id (challengeMu), the captcha
	// pool pushed last (challengePushMu, which also serializes pushes).
	challengeMu         sync.Mutex
	challengeKeys       map[string][]byte
	challengePushMu     sync.Mutex
	captchaID           string
	captchaCh           chan struct{}
	ocspCh              chan struct{}
	keysFetchedAt       time.Time // data plane loop only
	securityUnsupported sync.Once

	// TLS session ticket keys by id (tickets.go).
	ticketMu   sync.Mutex
	ticketKeys map[string][]byte

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
		cfg:               cfg,
		log:               log,
		engine:            eng,
		dp:                dp,
		ids:               identity.Store{Dir: cfg.StateDir},
		lkg:               configstore.Store{Dir: filepath.Join(cfg.StateDir, identity.ConfigDir)},
		message:           "waiting for the first configuration",
		startedAt:         time.Now(),
		creds:             map[string]configir.Credential{},
		certificates:      map[string]configir.Certificate{},
		originClientCerts: map[string]configir.Certificate{},
		purge:             newPurgeState(),
		syncCh:            make(chan struct{}, 1),
		reportCh:          make(chan struct{}, 1),
		taskCh:            make(chan struct{}, 1),
		purgeCh:           make(chan struct{}, 1),

		bans:           bans.New(),
		banDroppedSeen: map[string]time.Time{},
		banCh:          make(chan struct{}, 1),
		kernelCh:       make(chan struct{}, 1),
		nft:            kernelManager(cfg.Kernel, log),

		challengeKeys: map[string][]byte{},
		ticketKeys:    map[string][]byte{},
		captchaCh:     make(chan struct{}, 1),
		ocspCh:        make(chan struct{}, 1),

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

// errIdentityChanged stops the agent when identity.json no longer names the
// identity it uses (re-enrolled): the supervisor or systemd starts it again
// with the new one.
var errIdentityChanged = errors.New("the node identity changed (re-enrolled); restarting with the new identity")

// Run runs the agent until ctx is cancelled, until the node identity
// changes on disk (errIdentityChanged), or until the console decommissions
// the node (ErrDecommissioned, also at once when it was decommissioned
// before).
func (a *Agent) Run(parent context.Context) error {
	if a.decommissioned() {
		a.log.Error("not starting", "err", ErrDecommissioned, "marker", a.decommissionedMarker())
		return ErrDecommissioned
	}
	err := a.run(parent)
	if errors.Is(err, ErrDecommissioned) {
		// OpenResty and every loop have stopped.
		if werr := a.wipe(); werr != nil {
			a.log.Error("decommissioned, but not everything could be deleted", "err", werr)
		} else {
			a.log.Info("decommissioned: identity, configuration and cache deleted", "state_dir", a.cfg.StateDir)
		}
	}
	return err
}

func (a *Agent) run(parent context.Context) error {
	ctx, stop := context.WithCancelCause(parent)
	defer stop(nil)
	a.stopRun = stop
	if err := a.prepareDirs(); err != nil {
		return err
	}
	unlock, err := a.lockRun(ctx)
	if err != nil {
		return err
	}
	defer unlock()
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
		a.mu.Lock()
		a.geo = databases
		a.mu.Unlock()
		defer func() {
			a.mu.Lock()
			a.geo = nil
			a.mu.Unlock()
		}()
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

	// nginx outlives the other loops: its statistics counters are saved to
	// disk (statsLoop) before it stops. Deferred after wg.Wait, so this
	// runs first.
	engineCtx, stopEngine := context.WithCancel(context.WithoutCancel(ctx))
	defer stopEngine()
	spawn("engine", func(context.Context) {
		if err := a.engine.Run(engineCtx); err != nil {
			a.log.Error("engine supervisor stopped", "err", err)
		}
	})
	a.loadCredentials()
	a.loadCertificates()
	a.loadOriginClientCertificates()
	a.loadPurge()
	a.loadChallengeKeys()
	a.loadSessionTicketKeys()
	defer a.health.Close()
	a.serveInitialConfig(ctx)
	a.startBans(ctx)
	// Runs before the loops finish (defers are last in, first out); a sync
	// after it finds the manager inactive.
	defer a.stopKernel()
	spawn("dataplane", a.dataPlaneLoop)
	spawn("cacheusage", a.cacheUsageLoop)
	if err := a.serveAgentSocket(ctx, spawn); err != nil {
		return err
	}
	if err := a.serveImageSocket(ctx, spawn); err != nil {
		return err
	}
	if err := a.serveMarkdownSocket(ctx, spawn); err != nil {
		return err
	}
	if err := a.serveDiagSocket(ctx); err != nil {
		return err
	}
	spawn("activehealth", a.activeHealthLoop)
	spawn("ocsp", a.ocspLoop)
	spawn("kernel", a.kernelLoop)
	spawn("captchas", a.captchaLoop)
	spawn("tierlatency", a.tierLatencyLoop)

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
		"node_name", id.NodeName, "server", id.ServerURL, "fallback_server", id.FallbackServerURL,
		"certificate_not_after", id.Certificate.NotAfter.UTC().Format(time.RFC3339))
	a.follow.Store(&controlplane.Follower{
		Channel: ch,
		Store:   a.ids,
		Log:     a.log.With("component", "channel"),
		// The host joins the nftables allow list before the check connects.
		BeforeCheck: func(ctx context.Context) {
			a.addrMu.Lock()
			a.consoleAddrsAt = time.Time{}
			a.addrMu.Unlock()
			a.syncKernel(ctx)
		},
		Switched:      a.triggerReport,
		FailoverAfter: a.cfg.ChannelFailoverAfter,
		RetryPrimary:  a.cfg.ChannelRetryPrimary,
		Backoff:       a.cfg.ChannelBackoff,
	})
	// The console's addresses join the nftables allow list before the
	// first RPC.
	a.syncKernel(ctx)

	spawn("identity", func(ctx context.Context) { a.identityLoop(ctx, stop) })
	spawn("channel", a.follow.Load().Run)
	spawn("sync", a.syncLoop)
	spawn("watch", a.watchLoop)
	spawn("poll", a.pollLoop)
	spawn("report", a.reportLoop)
	statsStopped := make(chan struct{})
	spawn("stats", func(ctx context.Context) {
		defer close(statsStopped)
		a.statsLoop(ctx)
	})
	spawn("logs", a.logsLoop)
	spawn("nodelogs", a.nodeLogsLoop)
	spawn("tasks", a.taskLoop)
	spawn("purges", a.purgeLoop)
	spawn("supervisor", a.supervisorHealthLoop)
	spawn("bans", a.bansLoop)
	spawn("autobans", a.autoBansLoop)
	spawn("security", a.securityLoop)
	// Runs before the loops are waited for: the probe loop is not one of
	// them (it follows the heartbeat answers).
	defer a.stopProbing()
	a.triggerSync()
	a.triggerBans()

	<-ctx.Done()
	cause := context.Cause(ctx)
	if errors.Is(cause, errIdentityChanged) || errors.Is(cause, ErrDecommissioned) {
		a.log.Error("stopping", "err", cause)
	} else {
		a.log.Info("shutting down")
		cause = nil
	}
	select {
	case <-statsStopped:
	case <-time.After(15 * time.Second):
		a.log.Warn("statistics were not saved in time; stopping nginx anyway")
	}
	return cause
}

// lockRun takes the state directory's run lock (identity.Store.LockRun),
// waiting up to 30 seconds for a forced enrollment or an agent that is
// stopping.
func (a *Agent) lockRun(ctx context.Context) (func(), error) {
	deadline := time.Now().Add(30 * time.Second)
	for logged := false; ; logged = true {
		unlock, err := a.ids.LockRun()
		if !errors.Is(err, identity.ErrRunning) || time.Now().After(deadline) {
			return unlock, err
		}
		if !logged {
			a.log.Warn("the state directory is in use (another agent, or an enrollment); waiting", "state_dir", a.cfg.StateDir)
		}
		if !sleepCtx(ctx, time.Second) {
			return nil, ctx.Err()
		}
	}
}

// identityLoop stops the agent (stop with errIdentityChanged) once
// identity.json names another identity than the one in use.
func (a *Agent) identityLoop(ctx context.Context, stop context.CancelCauseFunc) {
	t := time.NewTicker(a.cfg.IdentityInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if a.identityChanged() {
			stop(errIdentityChanged)
			return
		}
	}
}

// identityChanged reports whether identity.json is readable and names
// another identity than the channel's (an unreadable one is being written,
// or damaged: the channel reports that on its own). A changed console
// address is the follower's business (controlplane.Follower).
func (a *Agent) identityChanged() bool {
	cur, err := a.ids.ReadIdentity()
	if err != nil {
		return false
	}
	return !identity.SameIdentity(*cur, a.channel.Identity().Identity)
}

// openChannel loads the identity, retrying while it is unreadable (e.g.
// an enrollment is being written or files were damaged).
func (a *Agent) openChannel(ctx context.Context) (*controlplane.Channel, error) {
	for {
		ch, err := controlplane.NewChannel(a.ids)
		if err == nil {
			return ch, nil
		}
		a.log.Error("cannot load node identity; retrying (if this persists, stop the agent and re-enroll with `edgeweir-node enroll --force`)", "err", err)
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
		{filepath.Dir(a.cfg.Render.WithDefaults().EdgeTLSSocket), 0o750},
		{filepath.Dir(a.cfg.Render.WithDefaults().L4Socket), 0o750},
		{filepath.Dir(a.cfg.Render.OriginSocket), 0o750},
		{filepath.Dir(a.cfg.ConfPath), 0o750},
	}
	if a.cfg.DiagSocket != "" {
		dirs = append(dirs, struct {
			path string
			mode os.FileMode
		}{filepath.Dir(a.cfg.DiagSocket), 0o750})
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return fmt.Errorf("create %s: %w", d.path, err)
		}
	}
	if err := chownToUser(a.cfg.Render.User, filepath.Join(prefix, "tmp"), a.cfg.Render.CacheDir); err != nil {
		return err
	}
	// Workers connect to the GeoIP, origin-layer and layer-4 relay sockets
	// and write temp files under the prefix (inside the 0700 state
	// directory by default).
	p := a.cfg.Render.WithDefaults()
	paths := []string{filepath.Join(prefix, "tmp"), a.cfg.Render.CacheDir, filepath.Dir(p.GeoIPSocket), filepath.Dir(p.L4Socket)}
	for _, socket := range p.OriginLayerSockets() {
		paths = append(paths, filepath.Dir(socket))
	}
	return letWorkersIn(a.cfg.Render.User, paths...)
}

func (a *Agent) buildOptions() configir.Options {
	opts := configir.Options{DefaultPort: a.cfg.DefaultPort, ExtraFeatures: a.extraFeatures(), NodeID: a.selfID()}
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
		var certs certificateUse
		if perr == nil {
			// No console yet: S3 origins use the stored credentials.
			a.attachCredentials(plan)
			a.attachSessionTicketKeys(plan)
			certs, perr = a.attachCertificates(plan, a.loadCertificateFailures(cfg))
			a.attachOriginClientCertificates(plan)
			if perr == nil {
				perr = a.applyPlan(ctx, plan)
			}
		}
		if perr == nil {
			a.mu.Lock()
			a.applied, a.appliedAt = cfg, time.Now()
			a.state = nodev1.ApplyState_APPLY_STATE_APPLIED
			a.message = fmt.Sprintf("restored last-known-good revision %d", cfg.GetRevision())
			if w := certs.warnings(); len(w) > 0 {
				a.message = truncate(a.message + "; " + strings.Join(w, "; "))
			}
			a.certUse = certs
			a.mu.Unlock()
			a.log.Info("serving last-known-good configuration", "revision", cfg.GetRevision(),
				"content_hash", cfg.GetContentHash(), "file", file, "sites", len(plan.Sites),
				nodelog.EventKey, nodelog.EventLastKnownGood)
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
	return dataplane.CDNID(a.selfID())
}

// selfID returns this node's id ("" before enrollment), reading
// identity.json while the mTLS channel is not open yet.
func (a *Agent) selfID() string {
	a.mu.Lock()
	id := a.nodeID
	a.mu.Unlock()
	if id == "" {
		if ident, err := a.ids.ReadIdentity(); err == nil {
			id = ident.NodeID
		}
	}
	return id
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
