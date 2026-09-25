//go:build unix && !linux

package engine

import "syscall"

// sysProcAttr puts nginx in its own process group so terminal signals only
// reach the agent, which forwards them.
func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}
