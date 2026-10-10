//go:build linux

package imageconv

import (
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// dataHeadroom is writable memory beyond a conversion's estimate: the Go
// runtime's own structures and the data segment.
const dataHeadroom = 256 << 20

// limitSelf bounds the child: its writable private memory (RLIMIT_DATA,
// which Linux counts for anonymous mappings; RLIMIT_AS would also count the
// address space the Go runtime reserves without using it) to memory plus
// headroom, no
// file it could write, at most 16 descriptors, and no capabilities (the
// agent may hold CAP_NET_BIND_SERVICE as an ambient capability).
func limitSelf(memory int64) error {
	limits := []struct {
		resource int
		value    uint64
	}{
		{unix.RLIMIT_DATA, uint64(memory) + dataHeadroom},
		{unix.RLIMIT_FSIZE, 0},
		{unix.RLIMIT_NOFILE, 16},
		{unix.RLIMIT_CORE, 0},
	}
	for _, l := range limits {
		if err := unix.Setrlimit(l.resource, &unix.Rlimit{Cur: l.value, Max: l.value}); err != nil {
			return err
		}
	}
	// Ambient capabilities first, then the permitted, effective and
	// inheritable sets of every thread (capabilities are per thread).
	if _, _, errno := syscall.AllThreadsSyscall6(syscall.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0, 0); errno != 0 && errno != syscall.EINVAL {
		return errno
	}
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		return errno
	}
	return nil
}

// childProcess sets what the agent asks of the child process: killed with
// the agent, in its own process group.
func childProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
}
