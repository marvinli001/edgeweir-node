package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"

	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/identity"
)

// Decommissioning (feature decommission-v1, proto v1.8.0): a
// DecommissionTask retires the node without SSH. The node reports the task
// first (afterwards it has no identity to report with), then stops: Run
// returns ErrDecommissioned once OpenResty and the loops stopped, the state
// directory (identity, last-known-good configuration, certificates, spools)
// and the cache are emptied, and the marker identity.DecommissionedFile
// keeps the node from serving again, also after a reboot, until the host
// is enrolled anew (`edgeweir-node enroll` removes the marker). The
// supervisor's upgrades/ stay: the agent version the host runs. Removing
// the packages needs root on the host.

// FeatureDecommission is announced while the agent can run decommission
// tasks.
const FeatureDecommission = "decommission-v1"

const codeDecommissionFailed = "decommission_failed" // reason

// ErrDecommissioned is returned by Run when the console decommissioned the
// node, now or before this start. The command exits with status 3
// (upgrade.ExitDecommissioned), which neither the supervisor nor systemd
// restarts; systemd counts it as a clean stop.
var ErrDecommissioned = errors.New("this node was decommissioned by the console: it serves nothing and has no identity; " +
	"enroll it again (edgeweir-node enroll) or remove the edgeweir-node package")

// decommissionMarker is the content of identity.DecommissionedFile.
type decommissionMarker struct {
	TaskID string    `json:"task_id"`
	NodeID string    `json:"node_id"`
	At     time.Time `json:"decommissioned_at"`
}

func (a *Agent) decommissionedMarker() string {
	return filepath.Join(a.cfg.StateDir, identity.DecommissionedFile)
}

// decommissioned reports whether the marker exists.
func (a *Agent) decommissioned() bool { return fsutil.Exists(a.decommissionedMarker()) }

// executeDecommission writes the marker, reports the task and stops the
// agent. A result that does not reach the console undoes the marker: the
// console hands the task out again.
func (a *Agent) executeDecommission(ctx context.Context, task *nodev1.NodeTask) *nodev1.ReportTaskResultRequest {
	a.mu.Lock()
	nodeID := a.nodeID
	a.mu.Unlock()
	raw, _ := json.Marshal(decommissionMarker{TaskID: task.GetId(), NodeID: nodeID, At: time.Now().UTC().Truncate(time.Second)})
	if err := fsutil.WriteFileAtomic(a.decommissionedMarker(), append(raw, '\n'), 0o600); err != nil {
		a.log.Error("decommission task failed", "task_id", task.GetId(), "err", err)
		return withCode(result(task, 0, 1, nodev1.TaskState_TASK_STATE_FAILED, "cannot write the decommission marker: "+err.Error()),
			codeDecommissionFailed, map[string]string{"reason": "state_dir"})
	}
	r := result(task, 1, 0, nodev1.TaskState_TASK_STATE_SUCCEEDED, "decommissioning: the node stops serving and deletes its identity, configuration and cache")
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	_, err := a.channel.Client().ReportTaskResult(cctx, connect.NewRequest(r))
	cancel()
	if err != nil {
		_ = os.Remove(a.decommissionedMarker())
		if ctx.Err() == nil {
			a.logRPCError("decommission task not reported; the console hands it out again", err)
		}
		return nil
	}
	a.log.Error("decommissioned by the console: stopping, deleting the identity, configuration and cache",
		"task_id", task.GetId(), "node_id", nodeID)
	if a.stopRun != nil {
		a.stopRun(ErrDecommissioned)
	}
	return nil
}

// wipe empties the state directory (but for the marker and the
// supervisor's upgrades) and the cache directory after a decommission.
func (a *Agent) wipe() error {
	var errs []error
	keep := map[string]bool{identity.DecommissionedFile: true, "upgrades": true}
	empty := func(dir string, keep map[string]bool) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
			return
		}
		for _, e := range entries {
			if keep[e.Name()] {
				continue
			}
			if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
				errs = append(errs, err)
			}
		}
	}
	// The identity marker first: an interrupted wipe never leaves a node
	// that looks enrolled.
	if err := a.ids.Remove(); err != nil {
		errs = append(errs, err)
	}
	empty(a.cfg.StateDir, keep)
	if prefix := a.cfg.Render.Prefix; prefix != "" && !within(prefix, a.cfg.StateDir) {
		empty(prefix, nil)
	}
	if cache := a.cfg.Render.CacheDir; cache != "" {
		empty(cache, nil)
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("decommission: %w", err)
	}
	return nil
}

// within reports whether path is dir or inside it.
func within(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !filepath.IsAbs(rel) && (rel == "." || len(rel) < 3 || rel[:3] != "../")
}
