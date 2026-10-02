package agent

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// Typed tasks (ADR-0014): the console can ask for purges, prefetches (of
// URLs or of the URLs a sitemap lists) and upgrades, nothing else. Tasks
// are idempotent; a task whose result does not reach the console is handed
// out again and simply runs again.
//
// Order and time (N-M7): the purges of a pulled batch run first (they are
// quick and must never wait behind a slow origin), then its prefetches and
// sitemaps, which share a time budget counted from the pull
// (PrefetchBudget, below the console's five minutes before it hands a task
// out again). URLs not done when the budget runs out are reported as
// failed.

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
// heartbeat) and about every TaskPollInterval (jittered) as a fallback.
func (a *Agent) taskLoop(ctx context.Context) {
	for {
		a.runTasks(ctx)
		t := time.NewTimer(jittered(a.cfg.TaskPollInterval))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-a.taskCh:
			t.Stop()
		}
	}
}

func (a *Agent) runTasks(ctx context.Context) {
	a.flushResults(ctx)
	a.flushUpgradeResult(ctx)
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
			if result == nil {
				continue
			}
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

// Task error codes (ReportTaskResultRequest.error_code, proto v0.2.1); the
// console localizes them and falls back to the message.
const (
	codePrefetchFailed  = "prefetch_failed"  // failed, total, url, reason, status
	codePrefetchTimeout = "prefetch_timeout" // done, total
	codeTaskUnsupported = "task_unsupported" // type
	codePurgeFailed     = "purge_failed"
	codeSitemapFailed   = "sitemap_failed" // url, reason, status
	codeSitemapEmpty    = "sitemap_empty"  // url
)

// withCode sets the error code of a failed result.
func withCode(r *nodev1.ReportTaskResultRequest, code string, params map[string]string) *nodev1.ReportTaskResultRequest {
	r.ErrorCode, r.ErrorParams = code, params
	return r
}

// unknownKind names the task kind an older node does not know: the field
// number of the unknown oneof case ("field_<n>"), or "unknown".
func unknownKind(task *nodev1.NodeTask) string {
	b := task.ProtoReflect().GetUnknown()
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		if num > 2 { // 1 id, 2 created_at
			return "field_" + strconv.Itoa(int(num))
		}
		m := protowire.ConsumeFieldValue(num, typ, b[n:])
		if m < 0 {
			break
		}
		b = b[n+m:]
	}
	return "unknown"
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

// taskRank orders a batch: purges, then anything else, then prefetches
// and sitemaps.
func taskRank(t *nodev1.NodeTask) int {
	switch t.GetKind().(type) {
	case *nodev1.NodeTask_Purge:
		return 0
	case *nodev1.NodeTask_Prefetch, *nodev1.NodeTask_Sitemap:
		return 2
	default:
		return 1
	}
}

// executeTask runs one task; prefetches stop at deadline.
func (a *Agent) executeTask(ctx context.Context, task *nodev1.NodeTask, deadline time.Time) *nodev1.ReportTaskResultRequest {
	switch kind := task.GetKind().(type) {
	case *nodev1.NodeTask_Upgrade:
		return a.executeUpgrade(ctx, task, kind.Upgrade)
	case *nodev1.NodeTask_Purge:
		return a.executePurge(ctx, task, kind.Purge)
	case *nodev1.NodeTask_Prefetch:
		return a.executePrefetch(ctx, task, kind.Prefetch, deadline)
	case *nodev1.NodeTask_Sitemap:
		return a.executeSitemap(ctx, task, kind.Sitemap, deadline)
	default:
		name := unknownKind(task)
		return withCode(result(task, 0, 0, nodev1.TaskState_TASK_STATE_FAILED, "unsupported task type ("+name+"); upgrade edgeweir-node"),
			codeTaskUnsupported, map[string]string{"type": name})
	}
}

// maxCacheTag bounds a Cache-Tag value (PurgeTarget.tag; the data plane
// drops longer elements of Cache-Tag headers).
const maxCacheTag = 128

// cacheTag returns tag in lowercase if it is a valid PurgeTarget.tag: 1-128
// bytes of printable ASCII (0x20-0x7e) without commas and without leading
// or trailing spaces, as the console normalizes it. Tags compare in
// lowercase everywhere.
func cacheTag(tag string) (string, bool) {
	if tag == "" || len(tag) > maxCacheTag || tag[0] == ' ' || tag[len(tag)-1] == ' ' {
		return "", false
	}
	for i := 0; i < len(tag); i++ {
		if c := tag[i]; c < 0x20 || c > 0x7e || c == ',' {
			return "", false
		}
	}
	return strings.ToLower(tag), true // ASCII only: checked above
}

// purgeMarkers converts purge targets into markers with the given epoch. A
// HOST target is a prefix marker on "/" (every path of the host), a TAG
// target a tag marker. Invalid targets are described in the second result.
func purgeMarkers(p *nodev1.PurgeTask, epoch int64) ([]dataplane.PurgeMarker, []string) {
	var markers []dataplane.PurgeMarker
	var invalid []string
	for _, t := range p.GetTargets() {
		m, why := purgeMarker(t, epoch)
		if why != "" {
			invalid = append(invalid, why)
			continue
		}
		markers = append(markers, m)
	}
	return markers, invalid
}

// purgeMarker converts one purge target; the reason is empty when it is
// valid. Hosts must be host names: a pattern such as "*.example.com" would
// match no request, the purge would do nothing and report success.
func purgeMarker(t *nodev1.PurgeTarget, epoch int64) (dataplane.PurgeMarker, string) {
	m := dataplane.PurgeMarker{SiteID: t.GetSiteId(), Epoch: epoch}
	host := strings.ToLower(t.GetHost())
	if !configir.ValidID(m.SiteID) {
		return m, fmt.Sprintf("invalid %v target: site id %q", t.GetType(), m.SiteID)
	}
	switch t.GetType() {
	case nodev1.PurgeType_PURGE_TYPE_URL, nodev1.PurgeType_PURGE_TYPE_PREFIX:
		m.Type, m.Host, m.Path = "url", host, t.GetPath()
		if t.GetType() == nodev1.PurgeType_PURGE_TYPE_PREFIX {
			m.Type = "prefix"
		} else {
			m.Query = t.GetQuery()
		}
		if !configir.ValidHostname(host) || !strings.HasPrefix(m.Path, "/") {
			return m, fmt.Sprintf("invalid %s target %q%q", m.Type, host, m.Path)
		}
	case nodev1.PurgeType_PURGE_TYPE_HOST:
		m.Type, m.Host, m.Path = "prefix", host, "/"
		if host == "" {
			return m, "invalid host target: no host"
		}
		if !configir.ValidHostname(host) {
			return m, fmt.Sprintf("invalid host target %q", host)
		}
	case nodev1.PurgeType_PURGE_TYPE_SITE:
		m.Type = "site"
	case nodev1.PurgeType_PURGE_TYPE_TAG:
		tag, ok := cacheTag(t.GetTag())
		if !ok {
			return m, fmt.Sprintf("invalid tag target %q", t.GetTag())
		}
		m.Type, m.Tag = "tag", tag
	default:
		return m, fmt.Sprintf("invalid target %v", t.GetType())
	}
	return m, ""
}

// executePurge applies a purge task. Its marker time is assigned by the
// node the first time it sees the task (see purgeState).
func (a *Agent) executePurge(ctx context.Context, task *nodev1.NodeTask, p *nodev1.PurgeTask) *nodev1.ReportTaskResultRequest {
	markers, invalid := purgeMarkers(p, 0)
	failed := uint32(len(invalid))
	if len(markers) == 0 {
		return withCode(result(task, 0, failed, nodev1.TaskState_TASK_STATE_FAILED, strings.Join(invalid, "; ")), codePurgeFailed, nil)
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
		a.log.Info("purge markers of sites over a per-site limit collapsed into site-level markers",
			"sites", collapsed, "limit", a.cfg.PurgeMarkersPerSite, "tag_limit", a.cfg.PurgeTagsPerSite)
		cctx, cancel := context.WithTimeout(ctx, a.cfg.PushTimeout)
		err = a.syncPurge(cctx)
		cancel()
	} else {
		err = a.pushMarkers(ctx, &dataplane.PurgeTable{ID: id, Markers: delta})
	}
	if err != nil {
		return withCode(result(task, 0, uint32(len(markers))+failed, nodev1.TaskState_TASK_STATE_FAILED,
			"data plane unavailable, the purge applies when it recovers: "+err.Error()), codePurgeFailed, nil)
	}
	if failed > 0 {
		return withCode(result(task, uint32(len(markers)), failed, nodev1.TaskState_TASK_STATE_FAILED, strings.Join(invalid, "; ")),
			codePurgeFailed, nil)
	}
	return result(task, uint32(len(markers)), 0, nodev1.TaskState_TASK_STATE_SUCCEEDED, "")
}
