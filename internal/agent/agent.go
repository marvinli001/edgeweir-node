// Package agent is the edgeweir-node runtime (`edgeweir-node run`).
//
// Lifecycle:
//
//	start ─► serve LKG (or the bootstrap config) ─► wait for enrollment
//	      ─► mTLS channel ─► watch + poll ─► fetch (snapshot | diff)
//	      ─► verify hash ─► validate ─► render/test/reload (structural only)
//	      ─► push site table to Lua ─► persist LKG ─► ReportStatus
//
// The data plane keeps serving the last-known-good configuration whenever
// the console is unreachable or a new configuration is rejected.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/configstore"
	"github.com/marvinli001/edgeweir-node/internal/controlplane"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/geoip"
	"github.com/marvinli001/edgeweir-node/internal/identity"
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
}

// DataPlane is the Lua control API (see package dataplane).
type DataPlane interface {
	Status(ctx context.Context) (*dataplane.Status, error)
	PutSites(ctx context.Context, t *dataplane.SiteTable) (*dataplane.Status, error)
	DrainStats(ctx context.Context) ([]dataplane.MinuteStats, error)
	PutPurge(ctx context.Context, t *dataplane.PurgeTable) (*dataplane.PurgeStatus, error)
	AddPurge(ctx context.Context, t *dataplane.PurgeTable) (*dataplane.PurgeStatus, error)
	OriginHealth(ctx context.Context) ([]dataplane.OriginHealth, error)
}

// Config configures the agent.
type Config struct {
	// StateDir holds the identity and the LKG configuration.
	StateDir string
	// ConfPath is where nginx.conf is written (inside the nginx prefix).
	ConfPath string
	// Render holds the node-local nginx.conf settings.
	Render render.Params
	// DefaultPort is served before any configuration exists.
	DefaultPort   uint32
	GeoIPCityPath string
	GeoIPASNPath  string

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

	// PurgeMarkersPerSite bounds a site's URL and prefix purge markers;
	// beyond it they collapse into one site-level marker (default 1000).
	PurgeMarkersPerSite int

	// Prefetch tasks request URLs from the node's own edge listener.
	PrefetchHost        string        // default 127.0.0.1
	PrefetchConcurrency int           // default 4
	PrefetchTimeout     time.Duration // per URL, default 60s
	// PrefetchBudget bounds the prefetches of one pulled batch, counted
	// from the pull (default 4m: the console hands a task out again after
	// 5 minutes without a result).
	PrefetchBudget time.Duration
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
	if c.PrefetchHost == "" {
		c.PrefetchHost = "127.0.0.1"
	}
	if c.PrefetchConcurrency <= 0 {
		c.PrefetchConcurrency = 4
	}
	if c.PurgeMarkersPerSite <= 0 {
		c.PurgeMarkersPerSite = DefaultPurgeMarkersPerSite
	}
	if c.DefaultPort == 0 {
		c.DefaultPort = 80
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

	geoFeatures   []string
	engineVersion string
	channel       *controlplane.Channel
	nodeID        string // guarded by mu; empty until the identity is known
	connectedOnce sync.Once

	mu           sync.Mutex
	applied      *nodev1.NodeConfig // LKG in effect; nil while on the bootstrap config
	appliedAt    time.Time
	plan         *configir.Plan       // plan in effect (listeners and zones for tasks)
	desired      *dataplane.SiteTable // table the data plane must serve
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

	pushMu       sync.Mutex
	activationMu sync.Mutex // structural reload and table activation/compensation
	purgeMu      sync.Mutex // serializes purge writes to the data plane
	syncCh       chan struct{}
	reportCh     chan struct{}
	taskCh       chan struct{}
}

// New creates an agent.
func New(cfg Config, eng Engine, dp DataPlane, log *slog.Logger) *Agent {
	cfg.setDefaults()
	if log == nil {
		log = slog.Default()
	}
	return &Agent{
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
	}
}

// Run runs the agent until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.prepareDirs(); err != nil {
		return err
	}
	databases, err := geoip.Open(a.cfg.GeoIPCityPath, a.cfg.GeoIPASNPath)
	if err != nil {
		return fmt.Errorf("load GeoIP: %w", err)
	}
	defer databases.Close()
	a.geoFeatures = databases.Features()
	if len(a.geoFeatures) > 0 {
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
	a.serveInitialConfig(ctx)
	spawn("dataplane", a.dataPlaneLoop)
	spawn("ocsp", a.ocspLoop)

	if err := a.ids.WaitForEnrollment(ctx, a.cfg.EnrollPollInterval, a.log); err != nil {
		return nil // shutting down
	}
	ch, err := a.openChannel(ctx)
	if err != nil {
		return nil // shutting down
	}
	a.channel = ch
	defer ch.Close()
	id := ch.Identity()
	a.mu.Lock()
	a.nodeID = id.NodeID
	a.mu.Unlock()
	a.log.Info("node identity loaded", "node_id", id.NodeID, "cluster_id", id.ClusterID,
		"node_name", id.NodeName, "server", id.ServerURL,
		"certificate_not_after", id.Certificate.NotAfter.UTC().Format(time.RFC3339))

	spawn("sync", a.syncLoop)
	spawn("watch", a.watchLoop)
	spawn("poll", a.pollLoop)
	spawn("report", a.reportLoop)
	spawn("stats", a.statsLoop)
	spawn("logs", a.logsLoop)
	spawn("tasks", a.taskLoop)
	a.triggerSync()

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
	opts := configir.Options{DefaultPort: a.cfg.DefaultPort, ExtraFeatures: a.geoFeatures}
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
