// Package sandbox runs the agent's converters' work in limited child
// processes of the agent's own binary (the WebP / AVIF and Markdown
// converters, ADR-0043): bounded memory, no files, few descriptors, no
// capabilities, no_new_privs, killed with the agent.
package sandbox

import (
	"context"
	"os"
	"os/exec"
	"runtime"
)

// SelfExecutable is the binary children run: this process's own
// (/proc/self/exe on Linux, so a replaced binary on disk changes nothing
// until the agent restarts).
func SelfExecutable() string {
	if runtime.GOOS == "linux" {
		return "/proc/self/exe"
	}
	exe, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return exe
}

// SelfCommand returns a converter's Command for exe: the child gets no
// environment but GOMAXPROCS=1 (one CPU per child; the agent's environment
// may hold secrets) and dies with the agent.
func SelfCommand(exe string) func(ctx context.Context, args []string) *exec.Cmd {
	return func(ctx context.Context, args []string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, exe, args...)
		cmd.Env = []string{"GOMAXPROCS=1"}
		childProcess(cmd)
		return cmd
	}
}
