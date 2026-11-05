//go:build linux

package upgrade

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func processAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
}

func processHealthy(cmd *exec.Cmd) error {
	if os.Geteuid() == 0 {
		return nil
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("read supervisor capabilities: %w", err)
	}
	const sidecarCaps = 1<<unix.CAP_KILL | 1<<unix.CAP_SETGID | 1<<unix.CAP_SETUID
	required := data[0].Effective & data[0].Permitted & sidecarCaps
	if required == 0 {
		return nil
	}
	hdr.Pid = int32(cmd.Process.Pid)
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("read node capabilities: %w", err)
	}
	if data[0].Effective&data[0].Permitted&required != required || data[0].Inheritable&sidecarCaps != 0 {
		return fmt.Errorf("node did not retain and isolate sidecar capabilities: effective=%x permitted=%x inheritable=%x required=%x", data[0].Effective, data[0].Permitted, data[0].Inheritable, required)
	}
	return nil
}
