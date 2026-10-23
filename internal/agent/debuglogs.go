package agent

import (
	"context"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/nodelog"
	"github.com/marvinli001/edgeweir-node/internal/upgrade"
)

// Debug logs (feature debug-logs-v1): a DebugLogsTask uploads the entries
// of the agent's ring (Config.DebugLogs) and of the supervisor's that the
// task selects, newest within the upload limits, with UploadDebugLogs.
// The task's result follows; a failed upload is not retried (the operator
// asks again).

// codeDebugLogsFailed is the result code of a task that uploaded nothing:
// reason disabled (no ring) or upload_failed.
const codeDebugLogsFailed = "debug_logs_failed"

var debugSources = map[nodev1.NodeLogSource]nodelog.Source{
	nodev1.NodeLogSource_NODE_LOG_SOURCE_AGENT:      nodelog.SourceAgent,
	nodev1.NodeLogSource_NODE_LOG_SOURCE_SUPERVISOR: nodelog.SourceSupervisor,
	nodev1.NodeLogSource_NODE_LOG_SOURCE_NGINX:      nodelog.SourceNginx,
	nodev1.NodeLogSource_NODE_LOG_SOURCE_LUA:        nodelog.SourceLua,
}

// debugFilter is the task's selection. Unknown sources select nothing of
// their own.
func debugFilter(t *nodev1.DebugLogsTask) nodelog.DebugFilter {
	var f nodelog.DebugFilter
	if t.GetSince() != nil {
		f.Since = t.GetSince().AsTime()
	}
	if t.GetUntil() != nil {
		f.Until = t.GetUntil().AsTime()
	}
	f.Components = t.GetComponents()
	for _, s := range t.GetSources() {
		if src, ok := debugSources[s]; ok {
			f.Sources = append(f.Sources, src)
		} else {
			f.Sources = append(f.Sources, nodelog.Source("unknown"))
		}
	}
	return f
}

func (a *Agent) executeDebugLogs(ctx context.Context, task *nodev1.NodeTask, t *nodev1.DebugLogsTask) *nodev1.ReportTaskResultRequest {
	if a.cfg.DebugLogs == nil {
		return withCode(result(task, 0, 0, nodev1.TaskState_TASK_STATE_FAILED, "this node keeps no debug logs (--debug-log-buffer 0)"),
			codeDebugLogsFailed, map[string]string{"reason": "disabled"})
	}
	f := debugFilter(t)
	snap := a.cfg.DebugLogs.Snapshot(f)
	supervisorMissing := false
	if sock := a.cfg.SupervisorSocket; sock != "" {
		client := upgrade.NewClient(sock)
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		caps, err := client.Capabilities(cctx)
		var sup *nodelog.DebugSnapshot
		if err == nil && caps.DebugLogs {
			sup, err = client.ReadDebugLogs(cctx, f)
		}
		cancel()
		if sup != nil {
			snap = nodelog.MergeDebug(snap, *sup)
		} else {
			// An older supervisor keeps no ring, or it did not answer.
			supervisorMissing = true
			if err != nil {
				a.log.Debug("cannot read the supervisor's debug logs", "err", err)
			}
		}
	}
	req := &nodev1.UploadDebugLogsRequest{
		TaskId:            task.GetId(),
		Entries:           make([]*nodev1.NodeLogEntry, 0, len(snap.Entries)),
		Truncated:         snap.Truncated,
		Overwritten:       snap.Overwritten,
		SupervisorMissing: supervisorMissing,
	}
	if !snap.Oldest.IsZero() {
		req.BufferSince = timestamppb.New(snap.Oldest)
	}
	for _, e := range snap.Entries {
		req.Entries = append(req.Entries, e.Proto())
	}
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	_, err := a.channel.Client().UploadDebugLogs(cctx, connect.NewRequest(req))
	cancel()
	if err != nil {
		return withCode(result(task, 0, uint32(len(req.Entries)), nodev1.TaskState_TASK_STATE_FAILED, "debug log upload failed: "+err.Error()),
			codeDebugLogsFailed, map[string]string{"reason": "upload_failed"})
	}
	return result(task, uint32(len(req.Entries)), 0, nodev1.TaskState_TASK_STATE_SUCCEEDED, "")
}
