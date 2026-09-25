package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
		for _, task := range tasks {
			result := a.executeTask(ctx, task)
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

func (a *Agent) executeTask(ctx context.Context, task *nodev1.NodeTask) *nodev1.ReportTaskResultRequest {
	switch kind := task.GetKind().(type) {
	case *nodev1.NodeTask_Purge:
		return a.executePurge(ctx, task, kind.Purge)
	case *nodev1.NodeTask_Prefetch:
		return a.executePrefetch(ctx, task, kind.Prefetch)
	default:
		return result(task, 0, 0, nodev1.TaskState_TASK_STATE_FAILED, "unsupported task type; upgrade edgeweir-node")
	}
}

var purgeTypes = map[nodev1.PurgeType]string{
	nodev1.PurgeType_PURGE_TYPE_URL:    "url",
	nodev1.PurgeType_PURGE_TYPE_PREFIX: "prefix",
	nodev1.PurgeType_PURGE_TYPE_SITE:   "site",
}

// purgeMarkers converts purge targets into markers whose epoch is the
// task's creation time.
func purgeMarkers(task *nodev1.NodeTask, p *nodev1.PurgeTask) ([]dataplane.PurgeMarker, []string) {
	epoch := time.Now().UnixMilli()
	if task.GetCreatedAt() != nil {
		epoch = task.GetCreatedAt().AsTime().UnixMilli()
	}
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

func (a *Agent) executePurge(ctx context.Context, task *nodev1.NodeTask, p *nodev1.PurgeTask) *nodev1.ReportTaskResultRequest {
	markers, invalid := purgeMarkers(task, p)
	failed := uint32(len(invalid))
	if len(markers) == 0 {
		return result(task, 0, failed, nodev1.TaskState_TASK_STATE_FAILED, strings.Join(invalid, "; "))
	}
	id, err := a.addMarkers(markers)
	if err != nil {
		// Still in memory and pushed below; the next restart would lose it.
		a.log.Error("cannot persist purge markers", "err", err)
	}
	if err := a.pushMarkers(ctx, &dataplane.PurgeTable{ID: id, Markers: markers}); err != nil {
		return result(task, 0, uint32(len(markers))+failed, nodev1.TaskState_TASK_STATE_FAILED,
			"data plane unavailable, the purge applies when it recovers: "+err.Error())
	}
	state := nodev1.TaskState_TASK_STATE_SUCCEEDED
	if failed > 0 {
		state = nodev1.TaskState_TASK_STATE_FAILED
	}
	return result(task, uint32(len(markers)), failed, state, strings.Join(invalid, "; "))
}

// pushMarkers merges markers into the data plane, retrying transient
// failures within the push timeout.
func (a *Agent) pushMarkers(ctx context.Context, t *dataplane.PurgeTable) error {
	deadline := time.Now().Add(a.cfg.PushTimeout)
	delay := 100 * time.Millisecond
	for {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := a.dp.AddPurge(cctx, t)
		cancel()
		if err == nil {
			a.log.Info("purge markers added to data plane", "markers", len(t.Markers), "id", t.ID)
			return nil
		}
		var apiErr *dataplane.APIError
		if (errors.As(err, &apiErr) && apiErr.Status == 400) || time.Now().After(deadline) {
			return err
		}
		if !sleepCtx(ctx, delay) {
			return ctx.Err()
		}
		delay = min(delay*2, 2*time.Second)
	}
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

// executePrefetch requests every URL through the node's own edge listener
// (so the response lands in the cache exactly as for a client) with
// bounded concurrency. 2xx and 3xx count as success.
func (a *Agent) executePrefetch(ctx context.Context, task *nodev1.NodeTask, p *nodev1.PrefetchTask) *nodev1.ReportTaskResultRequest {
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

	targets := p.GetTargets()
	errs := make([]string, len(targets))
	sem := make(chan struct{}, a.cfg.PrefetchConcurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			errs[i] = prefetchOne(ctx, client, t.GetUrl())
		}()
	}
	wg.Wait()

	var ok, failed uint32
	var msgs []string
	for i, e := range errs {
		if e == "" {
			ok++
			continue
		}
		failed++
		if len(msgs) < 5 {
			msgs = append(msgs, targets[i].GetUrl()+": "+e)
		}
	}
	state := nodev1.TaskState_TASK_STATE_SUCCEEDED
	if failed > 0 {
		state = nodev1.TaskState_TASK_STATE_FAILED
	}
	return result(task, ok, failed, state, strings.Join(msgs, "; "))
}

func prefetchOne(ctx context.Context, client *http.Client, raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "invalid URL"
	}
	if u.Scheme != "http" {
		return "HTTPS prefetch needs an HTTPS listener on the node"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+u.Host+u.RequestURI(), nil)
	if err != nil {
		return err.Error()
	}
	req.Host = u.Hostname()
	req.Header.Set("User-Agent", "edgeweir-node-prefetch/"+version.Version)
	resp, err := client.Do(req)
	if err != nil {
		return err.Error()
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return "read body: " + err.Error()
	}
	if resp.StatusCode >= 400 {
		return "HTTP " + strconv.Itoa(resp.StatusCode)
	}
	return ""
}
