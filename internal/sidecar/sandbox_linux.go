//go:build linux

package sidecar

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Supported reports whether this platform can isolate sidecars.
func Supported() bool { return runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64" }

func execSandboxed(s *Spec) error {
	runtime.LockOSThread()
	if s.UID <= 0 || s.GID <= 0 {
		return fmt.Errorf("refusing to run as uid %d gid %d", s.UID, s.GID)
	}
	// Into the sidecar's cgroup while still privileged.
	if s.Cgroup != "" {
		if err := os.WriteFile(filepath.Join(s.Cgroup, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
			return fmt.Errorf("cgroup: %w", err)
		}
	}
	limits := []struct {
		res int
		val uint64
	}{
		{unix.RLIMIT_CORE, 0},
		{unix.RLIMIT_NOFILE, 65536},
	}
	if s.Cgroup == "" {
		limits = append(limits, struct {
			res int
			val uint64
		}{unix.RLIMIT_DATA, s.MemoryBytes}, struct {
			res int
			val uint64
		}{unix.RLIMIT_NPROC, s.Tasks})
	}
	for _, l := range limits {
		if l.val == 0 && l.res != unix.RLIMIT_CORE {
			continue
		}
		if err := unix.Setrlimit(l.res, &unix.Rlimit{Cur: l.val, Max: l.val}); err != nil {
			return fmt.Errorf("rlimit %d: %w", l.res, err)
		}
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("dumpable: %w", err)
	}
	if err := os.Chdir(s.Dir); err != nil {
		return err
	}
	// The sidecar user only: no supplementary groups, no capabilities left
	// after the switch from root.
	if err := syscall.Setgroups([]int{s.GID}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setresgid(s.GID, s.GID, s.GID); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setresuid(s.UID, s.UID, s.UID); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		return fmt.Errorf("still privileged after the switch")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	prog := filter()
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&fprog)), 0, 0); err != nil {
		return fmt.Errorf("seccomp: %w", err)
	}
	// Sockets and files are guarded by their directories (the sidecar's
	// socket directory is nginx's and the sidecar group's only).
	unix.Umask(0)
	return syscall.Exec(s.Binary, append([]string{s.Binary}, s.Args...), s.Env)
}
