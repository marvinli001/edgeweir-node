//go:build !linux

package upgrade

import (
	"os/exec"
	"syscall"
)

func processAttributes() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

func processHealthy(*exec.Cmd) error { return nil }
