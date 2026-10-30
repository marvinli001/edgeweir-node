package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"connectrpc.com/connect"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/sidecar"
)

// Extension version 1.1 (docs/reference/extensions.md in the console
// repository): the console's extension secrets, per-site data items and
// sidecars. extensionLoop keeps them in line with the applied plan; the
// data plane gets the secrets and the sidecars' readiness through
// PUT /v1/extensions/runtime.

// extRuntime is extensionLoop's state.
type extRuntime struct {
	mu       sync.Mutex
	secrets  map[string]*nodev1.ExtensionSecret
	sidecars map[string]*sidecarProc
	indexes  map[string]string // extension id -> digest of its last index.json
	pushed   string            // digest of the last runtime document
	pushedAt time.Time
}

// sidecarProc is one running (or restarting) sidecar.
type sidecarProc struct {
	id, sha string
	cancel  context.CancelFunc
	done    chan struct{}

	mu       sync.Mutex
	state    string // starting, running, unhealthy, crashed, stopped, unsupported
	restarts int
	lastExit string
	since    time.Time
	ready    bool
	status   json.RawMessage
	pid      int
}

func (p *sidecarProc) set(f func(p *sidecarProc)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f(p)
}

// wakeExtensions asks extensionLoop to run now.
func (a *Agent) wakeExtensions() {
	select {
	case a.extCh <- struct{}{}:
	default:
	}
}

// extensionLoop runs after every apply and every 5 seconds.
func (a *Agent) extensionLoop(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	defer a.stopSidecars()
	for {
		a.mu.Lock()
		plan := a.plan
		a.mu.Unlock()
		if plan != nil {
			a.syncExtensionRuntime(ctx, plan)
		}
		select {
		case <-ctx.Done():
			return
		case <-a.extCh:
		case <-tick.C:
		}
	}
}

// runnable reports whether an extension of plan runs now: loaded, enabled
// and the kill switch off.
func runnable(plan *configir.Plan, e configir.Extension) bool {
	return e.Dir != "" && e.State == "loaded" && e.Enabled && !plan.ExtensionsDisabled
}

func (a *Agent) syncExtensionRuntime(ctx context.Context, plan *configir.Plan) {
	if a.cfg.Extensions.Disabled {
		return
	}
	a.ext.mu.Lock()
	if a.ext.secrets == nil {
		a.ext.secrets = map[string]*nodev1.ExtensionSecret{}
		a.ext.sidecars = map[string]*sidecarProc{}
		a.ext.indexes = map[string]string{}
	}
	a.ext.mu.Unlock()
	a.syncSecrets(ctx, plan)
	for _, e := range plan.Extensions {
		if e.Sidecar == nil || !runnable(plan, e) {
			continue
		}
		if err := a.syncSidecarData(ctx, plan, e); err != nil {
			a.log.Warn("extension data not synced", "extension", e.ID, "err", err)
		}
	}
	a.reconcileSidecars(plan)
	a.pushExtensionRuntime(ctx)
}

// syncSecrets fetches the secrets whose version changed.
func (a *Agent) syncSecrets(ctx context.Context, plan *configir.Plan) {
	var want []string
	keep := map[string]bool{}
	a.ext.mu.Lock()
	for _, e := range plan.Extensions {
		if e.SecretVersion == 0 || e.Dir == "" {
			continue
		}
		keep[e.ID] = true
		if s := a.ext.secrets[e.ID]; s == nil || s.GetVersion() != e.SecretVersion {
			want = append(want, e.ID)
		}
	}
	for id := range a.ext.secrets {
		if !keep[id] {
			delete(a.ext.secrets, id)
		}
	}
	a.ext.mu.Unlock()
	if len(want) == 0 || a.channel == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	res, err := a.channel.Client().GetExtensionSecrets(cctx, connect.NewRequest(&nodev1.GetExtensionSecretsRequest{Ids: want}))
	cancel()
	if err != nil {
		a.log.Warn("cannot fetch extension secrets", "err", err)
		return
	}
	a.ext.mu.Lock()
	defer a.ext.mu.Unlock()
	for _, s := range res.Msg.GetSecrets() {
		if keep[s.GetId()] && len(s.GetCurrent()) == 32 {
			a.ext.secrets[s.GetId()] = s
		}
	}
}

// pushExtensionRuntime hands the secrets and the sidecars' readiness to
// the data plane when they changed, and every minute (nginx restarts lose
// shared memory).
func (a *Agent) pushExtensionRuntime(ctx context.Context) {
	type secret struct {
		Current  string `json:"current"`
		Previous string `json:"previous,omitempty"`
	}
	doc := struct {
		Secrets  map[string]secret `json:"secrets"`
		Sidecars map[string]bool   `json:"sidecars"`
	}{Secrets: map[string]secret{}, Sidecars: map[string]bool{}}
	a.ext.mu.Lock()
	for id, s := range a.ext.secrets {
		doc.Secrets[id] = secret{Current: base64.StdEncoding.EncodeToString(s.GetCurrent()), Previous: base64.StdEncoding.EncodeToString(s.GetPrevious())}
	}
	for id, p := range a.ext.sidecars {
		p.mu.Lock()
		doc.Sidecars[id] = p.ready
		p.mu.Unlock()
	}
	raw, _ := json.Marshal(doc)
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	due := digest != a.ext.pushed || time.Since(a.ext.pushedAt) > time.Minute
	a.ext.mu.Unlock()
	if !due {
		return
	}
	dp, ok := a.dp.(extensionRuntimeDataPlane)
	if !ok {
		return
	}
	if err := dp.PutExtensionRuntime(ctx, raw); err != nil {
		a.log.Debug("extension runtime not stored", "err", err)
		return
	}
	a.ext.mu.Lock()
	a.ext.pushed, a.ext.pushedAt = digest, time.Now()
	a.ext.mu.Unlock()
}

// extensionRuntimeDataPlane is PUT /v1/extensions/runtime.
type extensionRuntimeDataPlane interface {
	PutExtensionRuntime(ctx context.Context, doc json.RawMessage) error
}

// --- Sidecar directories -----------------------------------------------------

// sidecarDir holds each sidecar's package copy, state and data.
func (a *Agent) sidecarDir() string {
	if a.cfg.Extensions.SidecarDir != "" {
		return a.cfg.Extensions.SidecarDir
	}
	return strings.TrimRight(a.cfg.StateDir, "/") + "-sidecar"
}

// sidecarIDs returns the sidecar user's uid and gid, or why sidecars do
// not run on this node.
func (a *Agent) sidecarIDs() (uid, gid int, why string) {
	cfg := a.cfg.Extensions
	switch {
	case cfg.SidecarMode == "off":
		return 0, 0, "sidecars are turned off on this node (--sidecar-mode off)"
	case !sidecar.Supported():
		return 0, 0, "sidecars need Linux on amd64 or arm64"
	case cfg.SidecarMode == "systemd":
		return 0, 0, "--sidecar-mode systemd is not available in this build"
	case cfg.SidecarUser == "" || (os.Geteuid() != 0 && !hasSidecarCaps()):
		return 0, 0, "sidecars need --sidecar-user and an agent that may switch users (root, or CAP_SETUID, CAP_SETGID and CAP_KILL)"
	}
	uid, gid, err := lookupUser(cfg.SidecarUser)
	if err != nil {
		return 0, 0, err.Error()
	}
	if uid == 0 || gid == 0 || uid == os.Geteuid() {
		return 0, 0, "--sidecar-user must be an unprivileged user of its own"
	}
	return uid, gid, ""
}

// hasSidecarCaps reports whether the agent holds CAP_SETUID and CAP_SETGID
// (to start a sidecar as its user) and CAP_KILL (to signal and stop it): a
// container image built with them as file capabilities.
func hasSidecarCaps() bool {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			caps, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			const kill, setgid, setuid = 1 << 5, 1 << 6, 1 << 7
			return err == nil && caps&(kill|setgid|setuid) == kill|setgid|setuid
		}
	}
	return false
}

// nginxUID is the user of nginx's workers (they connect to the sidecar's
// socket and serve its origin socket).
func (a *Agent) nginxUID() int {
	if a.cfg.Render.User != "" && os.Geteuid() == 0 {
		if uid, _, err := lookupUser(a.cfg.Render.User); err == nil {
			return uid
		}
	}
	return os.Geteuid()
}

// prepareSidecarSockets creates an extension's socket directory before
// nginx.conf names its origin socket: owned by nginx's user, group of the
// sidecar user, setgid, so that only the two reach the sockets in it.
func (a *Agent) prepareSidecarSockets(id string) error {
	dir, _, _ := a.cfg.Render.ExtensionSidecarSockets(id)
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return err
	}
	gid := os.Getegid()
	if _, g, why := a.sidecarIDs(); why == "" {
		gid = g
	}
	if err := os.Chown(dir, a.nginxUID(), gid); err != nil && os.Geteuid() == 0 {
		return err
	}
	return os.Chmod(dir, 0o770|os.ModeSetgid)
}

// openOriginSocket lets the sidecar user (the directory's group) connect
// to the origin socket nginx created with its own umask.
func (a *Agent) openOriginSocket(id string) {
	_, _, origin := a.cfg.Render.ExtensionSidecarSockets(id)
	if st, err := os.Stat(origin); err == nil && st.Mode().Perm() != 0o770 {
		_ = os.Chmod(origin, 0o770)
	}
}

// --- Per-site data -------------------------------------------------------------

// sidecarIndex is $EDGEWEIR_EXT_DATA/index.json.
type sidecarIndex struct {
	Revision uint64                      `json:"revision"`
	Config   json.RawMessage             `json:"config"`
	Sites    map[string]sidecarIndexSite `json:"sites"`
}

type sidecarIndexSite struct {
	Name    string             `json:"name"`
	Domains []string           `json:"domains"`
	Config  json.RawMessage    `json:"config"`
	Data    []sidecarIndexItem `json:"data"`
}

type sidecarIndexItem struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Path   string `json:"path"`
}

// syncSidecarData fetches the extension's data items of the sites that
// turn it on (by digest), removes the others and writes index.json
// atomically once every item is there; a changed index reaches the
// sidecar as SIGHUP.
func (a *Agent) syncSidecarData(ctx context.Context, plan *configir.Plan, e configir.Extension) error {
	root := filepath.Join(a.sidecarDir(), e.ID)
	dataDir := filepath.Join(root, "data")
	_, gid, why := a.sidecarIDs()
	if why != "" {
		return nil
	}
	if err := mkdirOwned(dataDir, 0o750, gid); err != nil {
		return err
	}
	idx := sidecarIndex{Revision: plan.Revision, Config: e.Config, Sites: map[string]sidecarIndexSite{}}
	keep := map[string]bool{"index.json": true}
	for _, s := range plan.Sites {
		i := slices.IndexFunc(s.Extensions, func(x configir.SiteExtension) bool { return x.ID == e.ID })
		if i < 0 {
			continue
		}
		x := s.Extensions[i]
		site := sidecarIndexSite{Config: x.Config, Data: []sidecarIndexItem{}}
		for _, d := range s.Domains {
			site.Domains = append(site.Domains, d.Name)
		}
		if len(site.Domains) > 0 {
			site.Name = site.Domains[0]
		}
		keep[s.ID] = true
		siteDir := filepath.Join(dataDir, s.ID)
		if err := mkdirOwned(siteDir, 0o750, gid); err != nil {
			return err
		}
		names := map[string]bool{}
		for _, d := range x.Data {
			path := filepath.Join(siteDir, d.Name)
			if err := a.ensureDataItem(ctx, e.ID, s.ID, d, path, gid); err != nil {
				return fmt.Errorf("site %s, %s: %w", s.ID, d.Name, err)
			}
			names[d.Name] = true
			site.Data = append(site.Data, sidecarIndexItem{Name: d.Name, SHA256: d.SHA256, Size: d.Size, Path: path})
		}
		removeExcept(siteDir, names)
		idx.Sites[s.ID] = site
	}
	removeExcept(dataDir, keep)
	raw, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	a.ext.mu.Lock()
	same := a.ext.indexes[e.ID] == digest
	a.ext.mu.Unlock()
	if same {
		return nil
	}
	path := filepath.Join(dataDir, "index.json")
	if err := fsutil.WriteFileAtomic(path, raw, 0o640); err != nil {
		return err
	}
	if err := os.Chown(path, -1, gid); err != nil {
		return err
	}
	a.ext.mu.Lock()
	a.ext.indexes[e.ID] = digest
	p := a.ext.sidecars[e.ID]
	a.ext.mu.Unlock()
	if p != nil {
		p.mu.Lock()
		pid := p.pid
		p.mu.Unlock()
		if pid > 0 {
			_ = syscall.Kill(pid, syscall.SIGHUP)
		}
	}
	return nil
}

// ensureDataItem keeps path with the item's content (GetExtensionData).
func (a *Agent) ensureDataItem(ctx context.Context, extID, siteID string, d configir.ExtensionDataItem, path string, gid int) error {
	if f, err := os.Open(path); err == nil {
		h := sha256.New()
		_, err := io.Copy(h, f)
		f.Close()
		if err == nil && hex.EncodeToString(h.Sum(nil)) == d.SHA256 {
			return nil
		}
	}
	if a.channel == nil {
		return errors.New("console unavailable")
	}
	data, err := a.fetchChunked(ctx, int(d.Size), func(cctx context.Context, offset uint64) ([]byte, uint64, error) {
		res, err := a.channel.Client().GetExtensionData(cctx, connect.NewRequest(&nodev1.GetExtensionDataRequest{
			ExtensionId: extID, SiteId: siteID, Sha256: d.SHA256, Offset: offset,
		}))
		if err != nil {
			return nil, 0, err
		}
		return res.Msg.GetData(), res.Msg.GetTotal(), nil
	})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != d.SHA256 {
		return errors.New("digest mismatch")
	}
	if err := fsutil.WriteFileAtomic(path, data, 0o640); err != nil {
		return err
	}
	return os.Chown(path, -1, gid)
}

// mkdirOwned makes dir the agent's, in group gid, with mode (the agent
// needs root, CAP_CHOWN or membership in the group).
func mkdirOwned(dir string, mode os.FileMode, gid int) error {
	// Parents (the extension's directory) stay traversable for the sidecar.
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return err
	}
	if err := os.Chown(dir, -1, gid); err != nil {
		return err
	}
	return os.Chmod(dir, mode)
}

// removeExcept deletes the entries of dir not in keep.
func removeExcept(dir string, keep map[string]bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !keep[e.Name()] {
			_ = os.RemoveAll(filepath.Join(dir, e.Name()))
		}
	}
}

// --- Supervision ---------------------------------------------------------------

// reconcileSidecars starts the sidecars of runnable extensions, restarts
// those whose package changed and stops the rest.
func (a *Agent) reconcileSidecars(plan *configir.Plan) {
	want := map[string]configir.Extension{}
	for _, e := range plan.Extensions {
		if e.Sidecar != nil && runnable(plan, e) {
			want[e.ID] = e
		}
	}
	a.ext.mu.Lock()
	defer a.ext.mu.Unlock()
	for id, p := range a.ext.sidecars {
		if e, ok := want[id]; !ok || e.SHA256 != p.sha {
			p.cancel()
			<-p.done
			delete(a.ext.sidecars, id)
			removeAllQuiet(filepath.Join(a.sidecarDir(), id, "package"))
		}
	}
	for id, e := range want {
		a.openOriginSocket(id)
		if a.ext.sidecars[id] != nil {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		p := &sidecarProc{id: id, sha: e.SHA256, cancel: cancel, done: make(chan struct{}), state: "starting", since: time.Now()}
		a.ext.sidecars[id] = p
		go a.superviseSidecar(ctx, p, e)
	}
	// Sidecars of extensions no plan has any more leave their directory.
	entries, _ := os.ReadDir(a.sidecarDir())
	for _, d := range entries {
		if _, ok := want[d.Name()]; !ok && a.ext.sidecars[d.Name()] == nil {
			if !slices.ContainsFunc(plan.Extensions, func(x configir.Extension) bool { return x.ID == d.Name() }) {
				removeAllQuiet(filepath.Join(a.sidecarDir(), d.Name()))
			}
		}
	}
}

func removeAllQuiet(path string) { _ = os.RemoveAll(path) }

// stopSidecars stops every sidecar (the agent stops).
func (a *Agent) stopSidecars() {
	a.ext.mu.Lock()
	defer a.ext.mu.Unlock()
	for id, p := range a.ext.sidecars {
		p.cancel()
		<-p.done
		delete(a.ext.sidecars, id)
	}
}

// superviseSidecar runs the sidecar until ctx ends, restarting it after an
// exit (1 s doubling to 60 s; back to 1 s after a minute of running).
func (a *Agent) superviseSidecar(ctx context.Context, p *sidecarProc, e configir.Extension) {
	defer close(p.done)
	uid, gid, why := a.sidecarIDs()
	if why != "" {
		p.set(func(p *sidecarProc) { p.state, p.lastExit = "unsupported", why })
		<-ctx.Done()
		return
	}
	backoff := time.Second
	for {
		started := time.Now()
		err := a.runSidecar(ctx, p, e, uid, gid)
		if ctx.Err() != nil {
			p.set(func(p *sidecarProc) { p.state, p.ready, p.pid = "stopped", false, 0 })
			return
		}
		msg := "exited"
		if err != nil {
			msg = err.Error()
		}
		if len(msg) > 300 {
			msg = msg[:300]
		}
		p.set(func(p *sidecarProc) {
			p.state, p.ready, p.pid, p.lastExit, p.since = "crashed", false, 0, msg, time.Now()
			p.restarts++
		})
		a.wakeExtensions()
		a.log.Warn("extension sidecar exited", "extension", e.ID, "err", msg, "restart_in", backoff.String())
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			p.set(func(p *sidecarProc) { p.state = "stopped" })
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 60*time.Second)
	}
}

// runSidecar starts the sidecar through the sandbox helper and waits for
// it, checking its health meanwhile.
func (a *Agent) runSidecar(ctx context.Context, p *sidecarProc, e configir.Extension, uid, gid int) error {
	s := e.Sidecar
	root := filepath.Join(a.sidecarDir(), e.ID)
	pkgDir := filepath.Join(root, "package")
	stateDir := filepath.Join(root, "state")
	dataDir := filepath.Join(root, "data")
	_, sock, origin := a.cfg.Render.ExtensionSidecarSockets(e.ID)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(root, 0o755); err != nil {
		return err
	}
	// The sidecar writes its state through the group (setgid: its files
	// stay in the group).
	if err := mkdirOwned(stateDir, 0o770|os.ModeSetgid, gid); err != nil {
		return err
	}
	if err := mkdirOwned(dataDir, 0o750, gid); err != nil {
		return err
	}
	if err := a.prepareSidecarSockets(e.ID); err != nil {
		return err
	}
	if err := copyPackage(e.Dir, pkgDir); err != nil {
		return fmt.Errorf("copy package: %w", err)
	}
	binary := filepath.Join(pkgDir, "sidecar", "linux-"+runtime.GOARCH, s.Binary)
	if _, err := os.Stat(binary); err != nil {
		p.set(func(p *sidecarProc) {
			p.state, p.lastExit = "unsupported", "the package has no sidecar for linux-"+runtime.GOARCH
		})
		<-ctx.Done()
		return nil
	}
	_ = os.Remove(sock)
	replace := strings.NewReplacer("{socket}", sock, "{origin_socket}", origin, "{state}", stateDir, "{data}", dataDir)
	args := make([]string, len(s.Args))
	for i, x := range s.Args {
		args[i] = replace.Replace(x)
	}
	env := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + stateDir, "TMPDIR=" + stateDir,
		"EDGEWEIR_SIDECAR_SOCKET=" + sock, "EDGEWEIR_ORIGIN_SOCKET=" + origin,
		"EDGEWEIR_EXT_STATE=" + stateDir, "EDGEWEIR_EXT_DATA=" + dataDir,
		"EDGEWEIR_EXT_ID=" + e.ID, "EDGEWEIR_EXT_VERSION=" + e.Version,
	}
	keys := make([]string, 0, len(s.Env))
	for k := range s.Env {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		env = append(env, k+"="+s.Env[k])
	}
	spec := sidecar.Spec{
		Binary: binary, Args: args, Env: env, Dir: stateDir, UID: uid, GID: gid,
		Cgroup:      a.sidecarCgroup(e),
		MemoryBytes: uint64(s.MemoryMB) << 20, Tasks: uint64(s.TasksMax),
	}
	raw, _ := json.Marshal(spec)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, sidecar.ChildCommand)
	cmd.Env = []string{sidecar.SpecEnv + "=" + string(raw)}
	cmd.SysProcAttr = sidecarProcAttr()
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return err
	}
	pid := cmd.Process.Pid
	p.set(func(p *sidecarProc) { p.state, p.pid, p.since = "starting", pid, time.Now() })
	a.log.Info("extension sidecar started", "extension", e.ID, "pid", pid)
	limiter := newLineLimiter()
	var wg sync.WaitGroup
	for _, r := range []io.Reader{stdout, stderr} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sc := bufio.NewScanner(r)
			sc.Buffer(make([]byte, 64<<10), 64<<10)
			for sc.Scan() {
				line := sc.Text()
				if len(line) > 1024 {
					line = line[:1024]
				}
				if limiter.allow() {
					a.log.Info("extension sidecar", "source", "extension", "extension", e.ID, "line", line)
				}
			}
		}()
	}
	exited := make(chan error, 1)
	go func() {
		wg.Wait()
		exited <- cmd.Wait()
	}()
	health := time.NewTicker(5 * time.Second)
	defer health.Stop()
	statusAt := time.Time{}
	client := unixHTTPClient(sock, 3*time.Second)
	check := func() {
		ok := sidecarGet(ctx, client, s.HealthPath) != nil
		var status json.RawMessage
		if ok && time.Since(statusAt) > 30*time.Second {
			statusAt = time.Now()
			if body := sidecarGet(ctx, client, "/status"); len(body) <= 2048 && json.Valid(body) {
				status = body
			}
		}
		changed := false
		p.set(func(p *sidecarProc) {
			changed = p.ready != ok
			p.ready = ok
			if ok {
				if p.state != "running" {
					p.state, p.since = "running", time.Now()
				}
			} else if p.state == "running" {
				p.state, p.since = "unhealthy", time.Now()
			}
			if status != nil {
				p.status = status
			}
		})
		if changed {
			a.wakeExtensions()
		}
	}
	// The first check soon after the start.
	first := time.After(500 * time.Millisecond)
	for {
		select {
		case err := <-exited:
			return err
		case <-ctx.Done():
			if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil {
				a.log.Warn("extension sidecar not signalled", "extension", e.ID, "err", err)
			}
			select {
			case <-exited:
			case <-time.After(10 * time.Second):
				if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
					// Waiting would block the extension runtime for good.
					a.log.Error("extension sidecar could not be stopped", "extension", e.ID, "pid", pid, "err", err)
					return nil
				}
				<-exited
			}
			return nil
		case <-first:
			check()
		case <-health.C:
			check()
		}
	}
}

// sidecarGet answers the body of a 200 to GET path on the sidecar's
// socket, nil otherwise.
func sidecarGet(ctx context.Context, client *http.Client, path string) []byte {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://sidecar"+path, nil)
	if err != nil {
		return nil
	}
	res, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 4096))
	if err != nil || res.StatusCode != http.StatusOK {
		return nil
	}
	if body == nil {
		body = []byte{}
	}
	return body
}

func unixHTTPClient(sock string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
			DisableKeepAlives: true,
		},
	}
}

// lineLimiter lets at most 20 lines a second through.
type lineLimiter struct {
	mu     sync.Mutex
	second int64
	n      int
}

func newLineLimiter() *lineLimiter { return &lineLimiter{} }

func (l *lineLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now().Unix()
	if now != l.second {
		l.second, l.n = now, 0
	}
	l.n++
	return l.n <= 20
}

// copyPackage copies the unpacked package (root-owned, world-readable) to
// dst, where the sidecar user can read it; unchanged when .verified
// matches.
func copyPackage(src, dst string) error {
	want, err := os.ReadFile(filepath.Join(src, ".verified"))
	if err != nil {
		return err
	}
	if have, err := os.ReadFile(filepath.Join(dst, ".verified")); err == nil && bytes.Equal(have, want) {
		return nil
	}
	tmp := dst + ".tmp"
	_ = os.RemoveAll(tmp)
	err = filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, path)
		out := filepath.Join(tmp, rel)
		if d.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("not a regular file: %s", rel)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if info.Mode()&0o100 != 0 {
			mode = 0o755
		}
		return os.WriteFile(out, data, mode)
	})
	if err != nil {
		return err
	}
	_ = os.RemoveAll(dst)
	return os.Rename(tmp, dst)
}

// sidecarCgroup creates the sidecar's cgroup v2 with its limits when the
// agent's own cgroup allows it; "" otherwise (rlimits then).
func (a *Agent) sidecarCgroup(e configir.Extension) string {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	rel, ok := strings.CutPrefix(strings.TrimSpace(string(raw)), "0::")
	if !ok || strings.Contains(rel, "\n") {
		return ""
	}
	parent := filepath.Join("/sys/fs/cgroup", rel)
	if err := os.WriteFile(filepath.Join(parent, "cgroup.subtree_control"), []byte("+memory +pids +cpu"), 0); err != nil {
		return ""
	}
	dir := filepath.Join(parent, "ewx-"+e.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ""
	}
	s := e.Sidecar
	settings := map[string]string{
		"memory.max":      strconv.FormatInt(int64(s.MemoryMB)<<20, 10),
		"memory.swap.max": "0",
		"pids.max":        strconv.Itoa(s.TasksMax),
	}
	if s.CPUPercent > 0 {
		settings["cpu.max"] = strconv.Itoa(s.CPUPercent*1000) + " 100000"
	}
	for name, value := range settings {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0); err != nil && name != "memory.swap.max" {
			return ""
		}
	}
	return dir
}

// sidecarDetails is ExtensionStatus.details_json of an extension.
func (a *Agent) sidecarDetails(id string) string {
	a.ext.mu.Lock()
	p := a.ext.sidecars[id]
	a.ext.mu.Unlock()
	if p == nil {
		return ""
	}
	p.mu.Lock()
	d := map[string]any{"sidecar": map[string]any{
		"state": p.state, "pid": p.pid, "restarts": p.restarts, "last_exit": p.lastExit, "since": p.since.UTC().Format(time.RFC3339),
	}}
	if p.status != nil {
		d["sidecar"].(map[string]any)["status"] = p.status
	}
	p.mu.Unlock()
	raw, err := json.Marshal(d)
	if err != nil || len(raw) > 4096 {
		return ""
	}
	return string(raw)
}
