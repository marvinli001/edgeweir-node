package hostinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
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

func TestMachineID(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	id := "0123456789abcdef0123456789ABCDEF"
	got := machineIDFrom(write("machine-id", id+"\n"))
	sum := sha256.Sum256([]byte("edgeweir-node:" + strings.ToLower(id)))
	if got != hex.EncodeToString(sum[:]) || strings.Contains(got, strings.ToLower(id)) {
		t.Fatalf("machine id = %q", got)
	}
	for name, content := range map[string]string{"empty": "", "uninit": "uninitialized\n", "short": "0123", "nothex": strings.Repeat("z", 32)} {
		if got := machineIDFrom(write(name, content)); got != "" {
			t.Errorf("%s: machine id = %q, want none", name, got)
		}
	}
	if got := machineIDFrom(filepath.Join(dir, "missing")); got != "" {
		t.Errorf("missing file: %q", got)
	}
}
