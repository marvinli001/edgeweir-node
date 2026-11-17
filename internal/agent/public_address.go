package agent

import (
	"context"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/hostinfo"
)

func (a *Agent) publicAddressLoop(ctx context.Context) {
	var expires time.Time
	for {
		address, err := hostinfo.AWSPublicIPv4(ctx)
		if ctx.Err() != nil {
			return
		}
		if err == nil || time.Now().After(expires) {
			a.mu.Lock()
			changed := a.publicIPv4 != address
			a.publicIPv4 = address
			a.mu.Unlock()
			if changed {
				a.log.Info("AWS public IPv4 changed", "address", address)
				a.triggerReport()
			}
		}
		if err == nil {
			expires = time.Now().Add(15 * time.Minute)
		}
		timer := time.NewTimer(5 * time.Minute)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
