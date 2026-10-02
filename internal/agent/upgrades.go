package agent

import (
	"connectrpc.com/connect"
	"context"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/upgrade"
	"github.com/marvinli001/edgeweir-node/internal/version"
	"google.golang.org/protobuf/types/known/timestamppb"
	"time"
)

func (a *Agent) executeUpgrade(ctx context.Context, task *nodev1.NodeTask, t *nodev1.UpgradeTask) *nodev1.ReportTaskResultRequest {
	if a.cfg.SupervisorSocket == "" {
		return withCode(result(task, 0, 1, nodev1.TaskState_TASK_STATE_FAILED, "node supervisor is not enabled"), codeTaskUnsupported, map[string]string{"type": "upgrade"})
	}
	if task.CreatedAt == nil || time.Since(task.CreatedAt.AsTime()) > 30*time.Minute || time.Until(task.CreatedAt.AsTime()) > 5*time.Minute {
		return withCode(result(task, 0, 1, nodev1.TaskState_TASK_STATE_FAILED, "upgrade task has expired"), "upgrade_rejected", map[string]string{"version": t.GetVersion()})
	}
	cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	err := upgrade.NewClient(a.cfg.SupervisorSocket).Stage(cctx, upgrade.Task{ID: task.Id, Version: t.GetVersion(), ArchiveURL: t.GetArchiveUrl(), SHA256: t.GetSha256(), ChecksumsURL: t.GetChecksumsUrl(), SignatureURL: t.GetSignatureUrl()})
	if err != nil {
		a.log.Warn("upgrade staging was not acknowledged; waiting for durable result or task retry", "task_id", task.Id, "err", err)
	}
	// The stable parent reports the result after restart/rollback. No optimistic
	// success result is sent by the process about to be replaced.
	return nil
}
func (a *Agent) flushUpgradeResult(ctx context.Context) {
	if a.cfg.SupervisorSocket == "" {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	defer cancel()
	client := upgrade.NewClient(a.cfg.SupervisorSocket)
	r, err := client.Result(cctx)
	if err != nil || r == nil {
		return
	}
	state := nodev1.TaskState_TASK_STATE_FAILED
	code := "upgrade_rejected"
	ok, failed := uint32(0), uint32(1)
	if r.Success {
		state = nodev1.TaskState_TASK_STATE_SUCCEEDED
		code = ""
		ok = 1
		failed = 0
	} else if r.ErrorCode == "upgrade_interrupted" {
		code = r.ErrorCode
	} else if r.RolledBack {
		code = "upgrade_rolled_back"
	}
	_, err = a.channel.Client().ReportTaskResult(cctx, connect.NewRequest(&nodev1.ReportTaskResultRequest{TaskId: r.TaskID, State: state, Succeeded: ok, Failed: failed, Message: r.Message, ErrorCode: code, ErrorParams: map[string]string{"version": r.Version}, FinishedAt: timestamppb.New(r.FinishedAt)}))
	if err != nil {
		a.logRPCError("upgrade result not acknowledged", err)
		return
	}
	if err = client.Ack(cctx, r.TaskID); err != nil {
		a.log.Warn("cannot persist upgrade result acknowledgement", "err", err)
	}
}

// heartbeat is the outcome of the last accepted heartbeat, for the
// supervisor's health checks.
type heartbeat struct {
	at      time.Time
	healthy bool // applied, data plane healthy, up to date
	every   time.Duration
}

// noteHeartbeat records a heartbeat's outcome and tells the supervisor at
// once.
func (a *Agent) noteHeartbeat(ctx context.Context, healthy bool, every time.Duration) {
	if a.cfg.SupervisorSocket == "" {
		return
	}
	a.mu.Lock()
	a.lastBeat = heartbeat{at: time.Now(), healthy: healthy, every: every}
	a.mu.Unlock()
	a.supervisorHealthy(ctx, healthy)
}

// supervisorHealthLoop tells the supervisor every five seconds whether the
// node is healthy: the last heartbeat (no older than two report intervals)
// said so and the data plane still is. An upgrade trial needs healthy
// reports at least 10 s apart within 90 s, whatever the console's report
// interval (up to five minutes).
func (a *Agent) supervisorHealthLoop(ctx context.Context) {
	if a.cfg.SupervisorSocket == "" {
		return
	}
	t := time.NewTicker(a.cfg.SupervisorHealthInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.mu.Lock()
		beat, dp := a.lastBeat, a.dpHealthy
		a.mu.Unlock()
		if beat.at.IsZero() {
			continue
		}
		a.supervisorHealthy(ctx, beat.healthy && dp && time.Since(beat.at) <= 2*beat.every+30*time.Second)
	}
}

func (a *Agent) supervisorHealthy(ctx context.Context, healthy bool) {
	if a.cfg.SupervisorSocket == "" {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := upgrade.NewClient(a.cfg.SupervisorSocket).ReportHealth(cctx, version.Version, healthy); err != nil {
		a.log.Debug("supervisor health receipt failed", "err", err)
	}
}
