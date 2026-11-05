package render

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/extension"
)

type extensionListener struct {
	configir.ExtensionListener
	ID, Key, Address string
	BodyLimit        int
}

func extensionListeners(plan *configir.Plan) ([]extensionListener, error) {
	var out []extensionListener
	ports := map[uint32]bool{}
	for _, listener := range plan.Listeners {
		ports[listener.Port] = true
	}
	if plan.Tier != nil {
		ports[plan.Tier.Port] = true
	}
	for _, e := range plan.Extensions {
		if e.Scope != extension.ScopeNode || e.Dir == "" || e.State != "loaded" || !e.Enabled || plan.ExtensionsDisabled {
			continue
		}
		listeners, err := configir.NormalizeExtensionListeners(e.Listeners)
		if err != nil {
			return nil, fmt.Errorf("extension %q: %w", e.ID, err)
		}
		for _, listener := range listeners {
			if ports[listener.Port] {
				return nil, fmt.Errorf("extension %q listener %q: port conflict", e.ID, listener.Name)
			}
			for _, app := range plan.L4Apps {
				if app.Port <= listener.Port && listener.Port <= max(app.Port, app.PortEnd) {
					return nil, fmt.Errorf("extension %q listener %q: layer-4 port conflict", e.ID, listener.Name)
				}
			}
			ports[listener.Port] = true
			address := net.JoinHostPort(listener.Bind, strconv.Itoa(int(listener.Port)))
			if strings.Contains(listener.Bind, ":") {
				address += " ipv6only=on"
			}
			out = append(out, extensionListener{
				ExtensionListener: listener, ID: e.ID, Key: hex.EncodeToString([]byte(e.ID)) + "_" + listener.Name,
				Address: address, BodyLimit: max(listener.MaxBody, 1),
			})
		}
	}
	return out, nil
}
