//go:build linux

package agent

import "syscall"

// sidecarProcAttr puts the sandbox helper (and the sidecar it becomes) in
// a process group of its own, killed when the agent dies.
func sidecarProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
