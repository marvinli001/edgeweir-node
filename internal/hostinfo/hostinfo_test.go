package hostinfo

import (
	"net"
	"runtime"
	"slices"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/version"
)

func TestCollect(t *testing.T) {
	info := Collect("1.31.1.1")
	if info.GetEngine() != "openresty" || info.GetEngineVersion() != "1.31.1.1" {
		t.Fatalf("engine = %q %q", info.GetEngine(), info.GetEngineVersion())
	}
	if info.GetAgentVersion() != version.Version || info.GetOs() != runtime.GOOS || info.GetArch() != runtime.GOARCH {
		t.Fatalf("info = %v", info)
	}
	if info.GetHostname() == "" {
		t.Fatal("empty hostname")
	}
	if !slices.Equal(info.GetIpAddresses(), IPAddresses()) {
		t.Fatalf("addresses %v differ from IPAddresses() %v", info.GetIpAddresses(), IPAddresses())
	}
}

// TestIPAddresses: only addresses worth reporting, sorted and unique.
func TestIPAddresses(t *testing.T) {
	addrs := IPAddresses()
	if !slices.IsSorted(addrs) || len(slices.Compact(slices.Clone(addrs))) != len(addrs) {
		t.Fatalf("addresses not sorted/unique: %v", addrs)
	}
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			t.Errorf("reported %q", a)
		}
	}
}

func TestHostnameAndProbes(t *testing.T) {
	if Hostname() == "" {
		t.Fatal("Hostname() is empty")
	}
	// The probes must not fail or leak a listener; their result depends on
	// the host.
	_ = HasGlobalIPv6()
	_ = CanListenIPv6()
	if runtime.GOOS != "windows" && NofileHardLimit() == 0 {
		t.Fatal("no RLIMIT_NOFILE hard limit on a unix host")
	}
}
