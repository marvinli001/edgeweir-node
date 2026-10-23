package configir

import (
	"fmt"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// FeatureConnLimit (proto v1.6.0): the node understands
// NodeConfig.connection_limits and reports whether it enforces them
// (BanStatus.connection_limits_active). No configuration requires it.
const FeatureConnLimit = "conn-limit-v1"

// FeatureGreylist (proto v1.6.0): the node asks GetBans for greylist
// entries (GetBansRequest.greylist) and acts on them. No configuration
// requires it.
const FeatureGreylist = "greylist-v1"

// Bounds of NodeConfig.connection_limits (proto v1.6.0).
const (
	MaxConnectionLimit = 100000
	MaxConnectionBurst = 1000000
	MaxLimitPortRanges = 256
)

// ConnectionLimits are the validated per-client TCP connection limits,
// enforced in the kernel by internal/nft (never by the data plane).
type ConnectionLimits struct {
	PerIP        uint32
	NewPerSecond uint32
	// Burst is at least NewPerSecond when that is set.
	Burst uint32
	Ports []PortRange
}

// PortRange is the TCP ports Start..End.
type PortRange struct {
	Start, End uint16
}

// ParseConnectionLimits validates NodeConfig.connection_limits: nil
// without limits, an error for anything the proto comment refuses.
func ParseConnectionLimits(c *nodev1.ConnectionLimits) (*ConnectionLimits, error) {
	if c == nil {
		return nil, nil
	}
	fail := func(format string, args ...any) error {
		return fmt.Errorf("%w: connection_limits: %s", ErrRejected, fmt.Sprintf(format, args...))
	}
	l := &ConnectionLimits{PerIP: c.GetPerIpConnections(), NewPerSecond: c.GetNewPerSecond(), Burst: c.GetBurst()}
	if l.PerIP == 0 && l.NewPerSecond == 0 {
		return nil, fail("neither per_ip_connections nor new_per_second")
	}
	if l.PerIP > MaxConnectionLimit {
		return nil, fail("per_ip_connections %d above %d", l.PerIP, MaxConnectionLimit)
	}
	if l.NewPerSecond > MaxConnectionLimit {
		return nil, fail("new_per_second %d above %d", l.NewPerSecond, MaxConnectionLimit)
	}
	switch {
	case l.NewPerSecond == 0 && l.Burst != 0:
		return nil, fail("burst without new_per_second")
	case l.NewPerSecond > 0 && l.Burst == 0:
		l.Burst = l.NewPerSecond
	case l.NewPerSecond > 0 && (l.Burst < l.NewPerSecond || l.Burst > MaxConnectionBurst):
		return nil, fail("burst %d outside %d-%d", l.Burst, l.NewPerSecond, MaxConnectionBurst)
	}
	ports := c.GetPorts()
	if len(ports) == 0 || len(ports) > MaxLimitPortRanges {
		return nil, fail("%d port ranges (1-%d)", len(ports), MaxLimitPortRanges)
	}
	for i, r := range ports {
		if r.GetStart() < 1 || r.GetEnd() > 65535 || r.GetEnd() < r.GetStart() {
			return nil, fail("invalid port range %d-%d", r.GetStart(), r.GetEnd())
		}
		// Sorted, neither overlapping nor adjacent (nftables refuses
		// overlapping interval elements).
		if i > 0 && r.GetStart() <= ports[i-1].GetEnd()+1 {
			return nil, fail("port range %d-%d overlaps or follows %d-%d", r.GetStart(), r.GetEnd(), ports[i-1].GetStart(), ports[i-1].GetEnd())
		}
		l.Ports = append(l.Ports, PortRange{Start: uint16(r.GetStart()), End: uint16(r.GetEnd())})
	}
	return l, nil
}
