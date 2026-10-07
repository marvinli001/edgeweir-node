// Package hostinfo collects the NodeInfo reported to the console. It only
// describes this host (name, addresses, software versions) and is sent to
// the operator's own console; nothing is sent anywhere else.
package hostinfo

import (
	"github.com/marvinli001/edgeweir-node/internal/configir"
	"net"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/version"
)

// Engine is the data plane engine name reported to the console.
const Engine = "openresty"

// Hostname returns the host name, or "unknown".
func Hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}

// IPAddresses returns the host's unicast addresses, excluding loopback and
// link-local ones, sorted for stable reports.
func IPAddresses() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipn.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			continue
		}
		out = append(out, ip.String())
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// HasGlobalIPv6 reports whether any interface has a global IPv6 address,
// used to decide whether the nginx resolver should query AAAA records.
func HasGlobalIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if ok && ipn.IP.To4() == nil && ipn.IP.IsGlobalUnicast() && !ipn.IP.IsPrivate() {
			return true
		}
	}
	return false
}

// CanListenIPv6 reports whether the host can bind IPv6 sockets, used to
// decide whether to render `listen [::]:port`.
func CanListenIPv6() bool {
	l, err := net.Listen("tcp6", "[::]:0")
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// Collect builds the NodeInfo message.
func Collect(engineVersion string) *nodev1.NodeInfo {
	return &nodev1.NodeInfo{
		Hostname:          Hostname(),
		AgentVersion:      version.Version,
		SupportedFeatures: slices.Clone(configir.SupportedFeatures),
		Os:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		Engine:            Engine,
		EngineVersion:     engineVersion,
		IpAddresses:       IPAddresses(),
	}
}

// OnlineCPUs is an upper bound of the CPUs nginx counts for
// `worker_processes auto`: the online CPUs of the host (Linux), at least
// the CPUs this process may run on.
func OnlineCPUs() int {
	n := runtime.NumCPU()
	data, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return n
	}
	online := 0
	for _, part := range strings.Split(strings.TrimSpace(string(data)), ",") {
		first, last, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(first)
		if err != nil {
			return n
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(last); err != nil || b < a {
				return n
			}
		}
		online += b - a + 1
	}
	return max(n, online)
}
