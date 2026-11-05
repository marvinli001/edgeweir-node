package agent

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/extension"
)

// nginx -t does not bind TCP sockets. Probe new endpoints before replacing
// the live file; reload confirmation still catches a race after Close.
func preflightExtensionListeners(ctx context.Context, plan, previous *configir.Plan) error {
	owned := map[uint32]bool{}
	if previous != nil {
		for _, e := range previous.Extensions {
			if e.Scope == extension.ScopeNode && runnable(previous, e) {
				for _, listener := range e.Listeners {
					owned[listener.Port] = true
				}
			}
		}
	}
	for _, e := range plan.Extensions {
		if e.Scope != extension.ScopeNode || !runnable(plan, e) {
			continue
		}
		for _, listener := range e.Listeners {
			address := net.JoinHostPort(listener.Bind, strconv.Itoa(int(listener.Port)))
			// Address changes on an occupied, controlled port are checked by
			// nginx's reload and waitForConf, not mistaken for a foreign owner.
			if owned[listener.Port] {
				continue
			}
			network := "tcp4"
			if strings.Contains(listener.Bind, ":") {
				network = "tcp6"
			}
			var lc net.ListenConfig
			socket, err := lc.Listen(ctx, network, address)
			if err != nil {
				return fmt.Errorf("extension %q listener %q (%s): %w", e.ID, listener.Name, address, err)
			}
			if err := socket.Close(); err != nil {
				return fmt.Errorf("extension %q listener %q preflight: %w", e.ID, listener.Name, err)
			}
		}
	}
	return nil
}
