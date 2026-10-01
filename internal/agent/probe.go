package agent

import (
	"context"

	"github.com/marvinli001/edgeweir-node/internal/probe"
)

// setProbing starts or stops probing the other nodes, as the console's
// heartbeat answer says (ReportStatusResponse.probe). The loop uses the
// node's own mTLS identity against ProbeService and never probes this
// node; the node certificate is renewed through NodeService as always.
func (a *Agent) setProbing(ctx context.Context, on bool) {
	a.probeMu.Lock()
	defer a.probeMu.Unlock()
	running := a.probeCancel != nil
	switch {
	case on && !running && ctx.Err() == nil:
		pctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		a.probeCancel, a.probeDone = cancel, done
		a.mu.Lock()
		nodeID := a.nodeID
		a.mu.Unlock()
		r := &probe.Runner{
			Client:     a.channel.ProbeClient,
			Info:       probe.Info(),
			SkipNodeID: nodeID,
			Prober:     a.cfg.Prober,
			Log:        a.log.With("loop", "probe"),
			RPCTimeout: a.cfg.RPCTimeout,
		}
		go func() {
			defer close(done)
			r.Run(pctx)
		}()
		a.log.Info("probing the other nodes for the console")
	case !on && running:
		a.probeCancel()
		<-a.probeDone
		a.probeCancel, a.probeDone = nil, nil
		a.log.Info("stopped probing the other nodes")
	}
}

// stopProbing ends the probe loop (agent shutdown).
func (a *Agent) stopProbing() { a.setProbing(context.Background(), false) }
