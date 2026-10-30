//go:build unix && !linux

package agent

import "syscall"

func sidecarProcAttr() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }
