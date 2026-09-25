//go:build linux

package engine

import "syscall"

// sysProcAttr puts nginx in its own process group (terminal signals only
// reach the agent, which forwards them) and makes the kernel stop nginx if
// the agent dies without cleaning up.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
}
