//go:build linux

package sidecar

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const agentCaps = 1<<unix.CAP_KILL | 1<<unix.CAP_SETGID | 1<<unix.CAP_SETUID

// InheritCapabilities carries only the caller's existing sidecar privileges
// across an internal agent or sandbox-helper exec without file capabilities.
// The target must call ClearInheritedCapabilities before starting any children.
func InheritCapabilities(cmd *exec.Cmd) error {
	if os.Geteuid() == 0 {
		return nil
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("read sidecar capabilities: %w", err)
	}
	required := data[0].Effective & data[0].Permitted & agentCaps
	if required == 0 {
		return nil
	}
	for _, cap := range []uintptr{unix.CAP_KILL, unix.CAP_SETGID, unix.CAP_SETUID} {
		if required&(1<<cap) == 0 {
			continue
		}
		bounded, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, cap, 0, 0, 0)
		if err != nil {
			return fmt.Errorf("read sidecar capability bounding set: %w", err)
		}
		if bounded == 0 {
			return fmt.Errorf("sidecar capability %d is outside the bounding set", cap)
		}
	}
	var caps [24]byte
	n, err := unix.Getxattr(cmd.Path, "security.capability", caps[:])
	if err != nil && !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.EOPNOTSUPP) {
		return fmt.Errorf("read target sidecar file capabilities: %w", err)
	}
	if n > 0 {
		// The kernel exposes applicable namespaced file capabilities as v2.
		// Any file capability clears ambient at exec, so it must cover the
		// required privileges itself; never combine a partial filecap with a bridge.
		magic := binary.LittleEndian.Uint32(caps[:4])
		if (n == 12 && magic == 0x01000001 || n == 20 && magic == 0x02000001) && binary.LittleEndian.Uint32(caps[4:8])&required == required {
			return nil
		}
		return fmt.Errorf("target file capabilities do not cover sidecar privileges %x", required)
	}
	// Probe without the bridge. Older signed agents only print their version
	// and must be rejected before they can start privileged descendants.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	probe := exec.CommandContext(ctx, cmd.Path, "version", "--sidecar-capabilities")
	probe.Env = cmd.Env
	out, err := probe.Output()
	if err != nil || string(out) != CapabilityHandoff+"\n" {
		return fmt.Errorf("target does not support safe sidecar capability handoff")
	}
	for _, cap := range []uintptr{unix.CAP_KILL, unix.CAP_SETGID, unix.CAP_SETUID} {
		if required&(1<<cap) == 0 {
			continue
		}
		cmd.SysProcAttr.AmbientCaps = append(cmd.SysProcAttr.AmbientCaps, cap)
	}
	return nil
}

// CapabilityHandoffSupported excludes cgo builds, whose non-Go threads cannot
// participate in the process-wide removal of the temporary inheritable bits.
func CapabilityHandoffSupported() (supported bool) {
	// Pure-Go dynamic loaders can enable runtime cgo without syscall's cgo hooks.
	defer func() {
		if recover() != nil {
			supported = false
		}
	}()
	_, _, errno := syscall.AllThreadsSyscall(syscall.SYS_GETPID, 0, 0, 0)
	return errno == 0
}

// ClearInheritedCapabilities keeps the agent's effective/permitted privileges
// but removes the sidecar exec bridge before nginx or other helpers can inherit it.
func ClearInheritedCapabilities() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("read inherited sidecar capabilities: %w", err)
	}
	if data[0].Inheritable&agentCaps == 0 {
		return nil
	}
	if !CapabilityHandoffSupported() {
		return errors.New("clear inherited sidecar capabilities requires a non-cgo build")
	}
	// Lowering inheritable also lowers ambient. Capabilities are per-thread;
	// changing just the current thread would leak them through another exec.
	data[0].Inheritable &^= agentCaps
	_, _, errno := syscall.AllThreadsSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0)
	if errno != 0 {
		return fmt.Errorf("clear inherited sidecar capabilities (requires a non-cgo build): %w", errno)
	}
	return nil
}
