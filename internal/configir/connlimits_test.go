package configir

import (
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func ports(pairs ...uint32) []*nodev1.PortRange {
	var out []*nodev1.PortRange
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, &nodev1.PortRange{Start: pairs[i], End: pairs[i+1]})
	}
	return out
}

func TestParseConnectionLimits(t *testing.T) {
	if l, err := ParseConnectionLimits(nil); l != nil || err != nil {
		t.Fatalf("unset = %+v, %v", l, err)
	}
	l, err := ParseConnectionLimits(&nodev1.ConnectionLimits{PerIpConnections: 100, NewPerSecond: 20, Ports: ports(80, 80, 443, 443, 10000, 10999)})
	if err != nil || l.PerIP != 100 || l.NewPerSecond != 20 || l.Burst != 20 || len(l.Ports) != 3 || l.Ports[2] != (PortRange{10000, 10999}) {
		t.Fatalf("limits = %+v, %v", l, err)
	}
	l, err = ParseConnectionLimits(&nodev1.ConnectionLimits{PerIpConnections: 100000, Ports: ports(1, 65535)})
	if err != nil || l.NewPerSecond != 0 || l.Burst != 0 {
		t.Fatalf("connection count only = %+v, %v", l, err)
	}
	many := make([]uint32, 0, 2*257)
	for i := uint32(0); i < 257; i++ {
		many = append(many, 10+2*i, 10+2*i)
	}
	for name, c := range map[string]*nodev1.ConnectionLimits{
		"nothing":          {Ports: ports(80, 80)},
		"too many conns":   {PerIpConnections: 100001, Ports: ports(80, 80)},
		"too fast":         {NewPerSecond: 100001, Ports: ports(80, 80)},
		"burst below rate": {NewPerSecond: 10, Burst: 5, Ports: ports(80, 80)},
		"burst too large":  {NewPerSecond: 10, Burst: 1000001, Ports: ports(80, 80)},
		"burst alone":      {PerIpConnections: 10, Burst: 5, Ports: ports(80, 80)},
		"no ports":         {PerIpConnections: 10},
		"port 0":           {PerIpConnections: 10, Ports: ports(0, 80)},
		"port above 65535": {PerIpConnections: 10, Ports: ports(80, 65536)},
		"reversed":         {PerIpConnections: 10, Ports: ports(90, 80)},
		"unsorted":         {PerIpConnections: 10, Ports: ports(443, 443, 80, 80)},
		"overlapping":      {PerIpConnections: 10, Ports: ports(80, 90, 85, 100)},
		"adjacent":         {PerIpConnections: 10, Ports: ports(80, 80, 81, 81)},
		"too many ranges":  {PerIpConnections: 10, Ports: ports(many...)},
	} {
		if _, err := ParseConnectionLimits(c); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestConnectionLimitsTravelInDiffs: diffs carry the limits in full both
// ways, and an invalid value rejects the configuration.
func TestConnectionLimitsTravelInDiffs(t *testing.T) {
	limits := &nodev1.ConnectionLimits{PerIpConnections: 64, Ports: ports(443, 443)}
	base := &nodev1.NodeConfig{Revision: 1, ClusterId: "c"}
	target := &nodev1.NodeConfig{Revision: 2, ClusterId: "c", ConnectionLimits: limits}
	hash, err := ContentHash(target)
	if err != nil {
		t.Fatal(err)
	}
	target.ContentHash = hash
	d := Diff(base, target)
	if !proto.Equal(d.GetConnectionLimits(), limits) {
		t.Fatalf("diff limits = %v", d.GetConnectionLimits())
	}
	got, err := ApplyDiff(base, d)
	if err != nil || !proto.Equal(got.GetConnectionLimits(), limits) {
		t.Fatalf("applied limits = %v, %v", got.GetConnectionLimits(), err)
	}
	if _, err := Build(&nodev1.NodeConfig{Revision: 3, ConnectionLimits: &nodev1.ConnectionLimits{Ports: ports(80, 80)}}, Options{}); !errors.Is(err, ErrRejected) {
		t.Fatalf("invalid limits accepted: %v", err)
	}
}
