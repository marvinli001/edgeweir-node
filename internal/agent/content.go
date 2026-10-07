package agent

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// cacheUsageLoop measures the disk usage of the cache zones of the plan in
// effect every CacheUsageInterval (the first time after at most a minute)
// for the heartbeat (ReportStatus.cache_usage, feature cache-zone-v1).
func (a *Agent) cacheUsageLoop(ctx context.Context) {
	t := time.NewTimer(min(a.cfg.CacheUsageInterval, time.Minute))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		usage := a.measureCacheUsage(ctx)
		a.mu.Lock()
		a.cacheUsage = usage
		a.mu.Unlock()
		t.Reset(a.cfg.CacheUsageInterval)
	}
}

// measureCacheUsage walks the directory of every cache zone and adds up
// the space its files occupy (allocated blocks).
func (a *Agent) measureCacheUsage(ctx context.Context) []*nodev1.CacheZoneUsage {
	a.mu.Lock()
	plan := a.plan
	a.mu.Unlock()
	if plan == nil || a.cfg.Render.CacheDir == "" {
		return nil
	}
	var out []*nodev1.CacheZoneUsage
	for _, z := range plan.CacheZones {
		used, err := dirUsage(ctx, filepath.Join(a.cfg.Render.CacheDir, z.Name))
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			a.log.Warn("cannot measure cache zone", "zone", z.Name, "err", err)
			continue
		}
		out = append(out, &nodev1.CacheZoneUsage{
			Name: z.Name, UsedBytes: used, MaxBytes: z.MaxSizeMB << 20, MeasuredAt: timestamppb.Now(),
		})
	}
	return out
}

// dirUsage returns the bytes the regular files below dir occupy on disk
// (0 for a missing directory).
func dirUsage(ctx context.Context, dir string) (uint64, error) {
	var total uint64
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // a file the cache manager just removed
			}
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		total += allocatedBytes(info)
		return nil
	})
	return total, err
}

// cacheUsageReport is the last cache usage measurement.
func (a *Agent) cacheUsageReport() []*nodev1.CacheZoneUsage {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cacheUsage
}

// serveAgentSocket serves the data plane's requests to the agent on the
// agent socket (PURGE method). The socket belongs to nginx's user; only it
// and root can connect.
func (a *Agent) serveAgentSocket(ctx context.Context, spawn func(string, func(context.Context))) error {
	path := a.cfg.Render.WithDefaults().AgentSocket
	if path == "" {
		return nil
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("agent socket %s is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("agent socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return err
	}
	if err := chownToUser(a.cfg.Render.User, path); err != nil {
		l.Close()
		return err
	}
	server := &http.Server{Handler: a.agentHandler(), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: a.cfg.RPCTimeout + 5*time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
	spawn("agentsocket", func(ctx context.Context) {
		go func() { <-ctx.Done(); _ = server.Close() }()
		if err := server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log.Error("agent socket stopped", "err", err)
		}
	})
	return nil
}

// purgeRequest is what the data plane sends for a PURGE request.
type purgeRequest struct {
	SiteID string `json:"site_id"`
	URL    string `json:"url"`
	Key    string `json:"key"`
}

// purgeAnswer is the agent's answer; Error is the X-Edgeweir-Error code.
type purgeAnswer struct {
	TaskID     string `json:"task_id,omitempty"`
	Error      string `json:"error,omitempty"`
	RetryAfter int    `json:"retry_after,omitempty"`
}

// Errors of PURGE requests (X-Edgeweir-Error).
const (
	purgeKeyInvalid  = "purge-key-invalid"
	purgeDisabled    = "purge-disabled"
	purgeURLInvalid  = "purge-url-invalid"
	purgeRateLimited = "purge-rate-limited"
	purgeUnavailable = "purge-unavailable"
)

var retryAfterRE = regexp.MustCompile(`retry after (\d{1,5})`)

func (a *Agent) agentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/purge", func(w http.ResponseWriter, r *http.Request) {
		var req purgeRequest
		raw, err := io.ReadAll(io.LimitReader(r.Body, 8192))
		if err != nil || json.Unmarshal(raw, &req) != nil {
			writePurge(w, http.StatusBadRequest, purgeAnswer{Error: purgeURLInvalid})
			return
		}
		status, answer := a.purgeMethod(r.Context(), req)
		writePurge(w, status, answer)
	})
	return mux
}

func writePurge(w http.ResponseWriter, status int, answer purgeAnswer) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(answer)
}

// purgeMethod checks the key of a PURGE request against the site's and submits
// the URL purge to the console.
func (a *Agent) purgeMethod(ctx context.Context, req purgeRequest) (int, purgeAnswer) {
	a.mu.Lock()
	plan := a.plan
	var ref *configir.PurgeRef
	if plan != nil {
		for i := range plan.Sites {
			if plan.Sites[i].ID == req.SiteID {
				ref = plan.Sites[i].PurgeKey
				break
			}
		}
	}
	var stored configir.Credential
	var have bool
	if ref != nil {
		stored, have = a.creds[ref.CredentialID]
	}
	a.mu.Unlock()
	switch {
	case ref == nil:
		return http.StatusForbidden, purgeAnswer{Error: purgeDisabled}
	case !have || stored.Version < ref.CredentialVersion || stored.SecretKey == "":
		// The key of this version has not been fetched yet.
		return http.StatusServiceUnavailable, purgeAnswer{Error: purgeUnavailable}
	case !samePurgeKey(req.Key, stored.SecretKey):
		return http.StatusForbidden, purgeAnswer{Error: purgeKeyInvalid}
	case len(req.URL) == 0 || len(req.URL) > 2048:
		return http.StatusBadRequest, purgeAnswer{Error: purgeURLInvalid}
	case !a.purgeLimit.allow(req.SiteID):
		return http.StatusTooManyRequests, purgeAnswer{Error: purgeRateLimited, RetryAfter: 1}
	}
	ch := a.connectedCh.Load()
	if ch == nil {
		return http.StatusServiceUnavailable, purgeAnswer{Error: purgeUnavailable}
	}
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	defer cancel()
	resp, err := ch.Client().SubmitPurge(cctx, connect.NewRequest(&nodev1.SubmitPurgeRequest{SiteId: req.SiteID, Url: req.URL}))
	if err != nil {
		a.log.Warn("PURGE request not submitted", "site", req.SiteID, "err", err)
		switch connect.CodeOf(err) {
		case connect.CodePermissionDenied:
			return http.StatusForbidden, purgeAnswer{Error: purgeDisabled}
		case connect.CodeInvalidArgument:
			return http.StatusBadRequest, purgeAnswer{Error: purgeURLInvalid}
		case connect.CodeResourceExhausted:
			retry := 60
			if m := retryAfterRE.FindStringSubmatch(err.Error()); m != nil {
				retry, _ = strconv.Atoi(m[1])
			}
			return http.StatusTooManyRequests, purgeAnswer{Error: purgeRateLimited, RetryAfter: max(retry, 1)}
		}
		return http.StatusServiceUnavailable, purgeAnswer{Error: purgeUnavailable}
	}
	a.log.Info("PURGE request submitted", "site", req.SiteID, "task", resp.Msg.GetTaskId())
	return http.StatusAccepted, purgeAnswer{TaskID: resp.Msg.GetTaskId()}
}

// purgeRate is how many accepted PURGE requests (right key) a site takes
// per second on this node. The data plane limits every client address to
// as many requests first, so clients without the key cannot use up a
// site's budget.
const purgeRate = 20

// purgeLimiter counts the accepted PURGE requests of each site in fixed
// one-second windows.
type purgeLimiter struct {
	mu     sync.Mutex
	now    func() time.Time // nil: time.Now
	window int64
	counts map[string]int
}

// allow reports whether site may take one more accepted request in the
// current second, and counts it.
func (l *purgeLimiter) allow(site string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now
	if l.now != nil {
		now = l.now
	}
	if sec := now().Unix(); sec != l.window || l.counts == nil {
		l.window, l.counts = sec, map[string]int{}
	}
	if l.counts[site] >= purgeRate {
		return false
	}
	l.counts[site]++
	return true
}

// samePurgeKey compares a PURGE key in constant time (of the digests, so
// the time does not depend on the length either).
func samePurgeKey(given, stored string) bool {
	if given == "" {
		return false
	}
	g, s := sha256.Sum256([]byte(given)), sha256.Sum256([]byte(stored))
	return subtle.ConstantTimeCompare(g[:], s[:]) == 1
}
