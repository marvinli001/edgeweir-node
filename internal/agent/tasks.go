package agent

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/edgeweir/edgeweir-node/internal/dataplane"
	nodev1 "github.com/edgeweir/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/edgeweir/edgeweir-node/internal/version"
)

// Typed tasks (ADR-0014): the console can ask for purges and prefetches,
// nothing else. Tasks are idempotent; a task whose result does not reach
// the console is handed out again and simply runs again.
//
// Order and time (N-M7): the purges of a pulled batch run first (they are
// quick and must never wait behind a slow origin), then its prefetches,
// which share a time budget counted from the pull (PrefetchBudget, below
// the console's five minutes before it hands a task out again). URLs not
// done when the budget runs out are reported as failed.

const (
	maxTasksPerPull  = 10
	maxPullRounds    = 10
	maxUnreported    = 1000
	maxResultMessage = 1000
)

func (a *Agent) triggerTasks() {
	select {
	case a.taskCh <- struct{}{}:
	default:
	}
}

// taskLoop pulls tasks when the console announces them (watch event or
// heartbeat) and every TaskPollInterval as a fallback.
func (a *Agent) taskLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.TaskPollInterval)
	defer t.Stop()
	for {
		a.runTasks(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.taskCh:
		}
	}
}

func (a *Agent) runTasks(ctx context.Context) {
	a.flushResults(ctx)
	for range maxPullRounds {
		cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
		resp, err := a.channel.Client().PullTasks(cctx, connect.NewRequest(&nodev1.PullTasksRequest{MaxTasks: maxTasksPerPull}))
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				a.logRPCError("PullTasks failed", err)
			}
			return
		}
		a.markConnected()
		tasks := resp.Msg.GetTasks()
		if len(tasks) == 0 {
			return
		}
		deadline := time.Now().Add(a.cfg.PrefetchBudget)
		slices.SortStableFunc(tasks, func(x, y *nodev1.NodeTask) int { return cmp.Compare(taskRank(x), taskRank(y)) })
		for _, task := range tasks {
			result := a.executeTask(ctx, task, deadline)
			a.log.Info("task finished", "task_id", task.GetId(), "state", result.GetState().String(),
				"succeeded", result.GetSucceeded(), "failed", result.GetFailed(), "message", result.GetMessage())
			a.reportResult(ctx, result)
		}
	}
}

func (a *Agent) reportResult(ctx context.Context, r *nodev1.ReportTaskResultRequest) {
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	defer cancel()
	if _, err := a.channel.Client().ReportTaskResult(cctx, connect.NewRequest(r)); err != nil {
		if ctx.Err() == nil {
			a.logRPCError("ReportTaskResult failed; will retry", err)
		}
		a.mu.Lock()
		if len(a.unreported) < maxUnreported {
			a.unreported = append(a.unreported, r)
		}
		a.mu.Unlock()
	}
}

// flushResults retries results that could not be reported earlier.
func (a *Agent) flushResults(ctx context.Context) {
	a.mu.Lock()
	pending := a.unreported
	a.unreported = nil
	a.mu.Unlock()
	for _, r := range pending {
		a.reportResult(ctx, r)
	}
}

func result(task *nodev1.NodeTask, ok, failed uint32, state nodev1.TaskState, msg string) *nodev1.ReportTaskResultRequest {
	if len(msg) > maxResultMessage {
		msg = msg[:maxResultMessage] + "…"
	}
	return &nodev1.ReportTaskResultRequest{
		TaskId:     task.GetId(),
		State:      state,
		Message:    msg,
		Succeeded:  ok,
		Failed:     failed,
		FinishedAt: timestamppb.Now(),
	}
}

// taskRank orders a batch: purges, then anything else, then prefetches.
func taskRank(t *nodev1.NodeTask) int {
	switch t.GetKind().(type) {
	case *nodev1.NodeTask_Purge:
		return 0
	case *nodev1.NodeTask_Prefetch:
		return 2
	default:
		return 1
	}
}

// executeTask runs one task; prefetches stop at deadline.
func (a *Agent) executeTask(ctx context.Context, task *nodev1.NodeTask, deadline time.Time) *nodev1.ReportTaskResultRequest {
	switch kind := task.GetKind().(type) {
	case *nodev1.NodeTask_Purge:
		return a.executePurge(ctx, task, kind.Purge)
	case *nodev1.NodeTask_Prefetch:
		return a.executePrefetch(ctx, task, kind.Prefetch, deadline)
	default:
		return result(task, 0, 0, nodev1.TaskState_TASK_STATE_FAILED, "unsupported task type; upgrade edgeweir-node")
	}
}

var purgeTypes = map[nodev1.PurgeType]string{
	nodev1.PurgeType_PURGE_TYPE_URL:    "url",
	nodev1.PurgeType_PURGE_TYPE_PREFIX: "prefix",
	nodev1.PurgeType_PURGE_TYPE_SITE:   "site",
}

// purgeMarkers converts purge targets into markers with the given epoch.
func purgeMarkers(p *nodev1.PurgeTask, epoch int64) ([]dataplane.PurgeMarker, []string) {
	var markers []dataplane.PurgeMarker
	var invalid []string
	for _, t := range p.GetTargets() {
		typ, ok := purgeTypes[t.GetType()]
		host := strings.ToLower(t.GetHost())
		switch {
		case !ok || t.GetSiteId() == "":
			invalid = append(invalid, fmt.Sprintf("invalid target %v", t.GetType()))
			continue
		case typ != "site" && (host == "" || !strings.HasPrefix(t.GetPath(), "/")):
			invalid = append(invalid, fmt.Sprintf("invalid %s target %q%q", typ, host, t.GetPath()))
			continue
		}
		m := dataplane.PurgeMarker{SiteID: t.GetSiteId(), Type: typ, Epoch: epoch}
		if typ != "site" {
			m.Host, m.Path = host, t.GetPath()
		}
		if typ == "url" {
			m.Query = t.GetQuery()
		}
		markers = append(markers, m)
	}
	return markers, invalid
}

// executePurge applies a purge task. Its marker time is assigned by the
// node the first time it sees the task (see purgeState).
func (a *Agent) executePurge(ctx context.Context, task *nodev1.NodeTask, p *nodev1.PurgeTask) *nodev1.ReportTaskResultRequest {
	markers, invalid := purgeMarkers(p, 0)
	failed := uint32(len(invalid))
	if len(markers) == 0 {
		return result(task, 0, failed, nodev1.TaskState_TASK_STATE_FAILED, strings.Join(invalid, "; "))
	}
	epoch := a.taskEpoch(task.GetId())
	for i := range markers {
		markers[i].Epoch = epoch
	}
	delta, collapsed, id, err := a.addMarkers(markers)
	if err != nil {
		// Still in memory and pushed below; the next restart would lose it.
		a.log.Error("cannot persist purge markers", "err", err)
	}
	if len(collapsed) > 0 {
		a.log.Info("purge markers of sites over the per-site limit collapsed into site-level markers",
			"sites", collapsed, "limit", a.cfg.PurgeMarkersPerSite)
		cctx, cancel := context.WithTimeout(ctx, a.cfg.PushTimeout)
		err = a.syncPurge(cctx)
		cancel()
	} else {
		err = a.pushMarkers(ctx, &dataplane.PurgeTable{ID: id, Markers: delta})
	}
	if err != nil {
		return result(task, 0, uint32(len(markers))+failed, nodev1.TaskState_TASK_STATE_FAILED,
			"data plane unavailable, the purge applies when it recovers: "+err.Error())
	}
	state := nodev1.TaskState_TASK_STATE_SUCCEEDED
	if failed > 0 {
		state = nodev1.TaskState_TASK_STATE_FAILED
	}
	return result(task, uint32(len(markers)), failed, state, strings.Join(invalid, "; "))
}

// httpPort returns the first plain-HTTP listener of the serving plan.
func (a *Agent) httpPort() uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.plan != nil && len(a.plan.Listeners) > 0 {
		return a.plan.Listeners[0].Port
	}
	return a.cfg.DefaultPort
}

// prefetchOutcome is the result of one prefetch URL.
type prefetchOutcome struct {
	done   bool   // false: not attempted or cut off by the time budget
	err    string // empty on success
	reason string // status, connect_failed, timeout, https_unsupported, other
	status int    // HTTP status when reason is "status"
}

// executePrefetch requests every URL through the node's own edge listener
// (so the response lands in the cache exactly as for a client) with
// bounded concurrency until deadline. 2xx and 3xx count as success.
func (a *Agent) executePrefetch(ctx context.Context, task *nodev1.NodeTask, p *nodev1.PrefetchTask, deadline time.Time) *nodev1.ReportTaskResultRequest {
	addr := net.JoinHostPort(a.cfg.PrefetchHost, strconv.Itoa(int(a.httpPort())))
	client := &http.Client{
		Timeout: a.cfg.PrefetchTimeout,
		// Redirects are cached as they are, never followed.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
			DisableCompression:  true,
			MaxIdleConnsPerHost: a.cfg.PrefetchConcurrency,
		},
	}
	defer client.CloseIdleConnections()

	bctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	targets := p.GetTargets()
	outcomes := make([]prefetchOutcome, len(targets))
	sem := make(chan struct{}, a.cfg.PrefetchConcurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		select {
		case sem <- struct{}{}:
		case <-bctx.Done():
		}
		if bctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			outcomes[i] = prefetchOne(bctx, client, t.GetUrl())
		}()
	}
	wg.Wait()
	timedOut := ctx.Err() == nil && bctx.Err() != nil

	var ok, failed, done uint32
	var msgs []string
	for i, o := range outcomes {
		switch {
		case !o.done:
			failed++
		case o.err == "":
			ok++
			done++
		default:
			failed++
			done++
			if len(msgs) < 5 {
				msgs = append(msgs, targets[i].GetUrl()+": "+o.err)
			}
		}
	}
	if timedOut && done < uint32(len(targets)) {
		msgs = append([]string{fmt.Sprintf("prefetch time budget exhausted: %d of %d URLs done", done, len(targets))}, msgs...)
	}
	state := nodev1.TaskState_TASK_STATE_SUCCEEDED
	if failed > 0 {
		state = nodev1.TaskState_TASK_STATE_FAILED
	}
	return result(task, ok, failed, state, strings.Join(msgs, "; "))
}

func prefetchOne(ctx context.Context, client *http.Client, raw string) prefetchOutcome {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return prefetchOutcome{done: true, err: "invalid URL", reason: "other"}
	}
	if u.Scheme != "http" {
		return prefetchOutcome{done: true, err: "HTTPS prefetch needs an HTTPS listener on the node", reason: "https_unsupported"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+u.Host+u.RequestURI(), nil)
	if err != nil {
		return prefetchOutcome{done: true, err: err.Error(), reason: "other"}
	}
	req.Host = u.Hostname()
	req.Header.Set("User-Agent", "edgeweir-node-prefetch/"+version.Version)
	resp, err := client.Do(req)
	if err != nil {
		return failedOutcome(ctx, err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		o := failedOutcome(ctx, err)
		o.err = "read body: " + o.err
		return o
	}
	if resp.StatusCode >= 400 {
		return prefetchOutcome{done: true, err: "HTTP " + strconv.Itoa(resp.StatusCode), reason: "status", status: resp.StatusCode}
	}
	return prefetchOutcome{done: true}
}

// failedOutcome classifies a transport error; a request cut off by the
// task's time budget is not done.
func failedOutcome(ctx context.Context, err error) prefetchOutcome {
	if ctx.Err() != nil {
		return prefetchOutcome{err: err.Error()}
	}
	var netErr net.Error
	var opErr *net.OpError
	switch {
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return prefetchOutcome{done: true, err: err.Error(), reason: "connect_failed"}
	case errors.As(err, &netErr) && netErr.Timeout():
		return prefetchOutcome{done: true, err: err.Error(), reason: "timeout"}
	default:
		return prefetchOutcome{done: true, err: err.Error(), reason: "other"}
	}
}
