//go:build linux

package imageconv

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// dataHeadroom is writable memory beyond a conversion's estimate: the Go
// runtime's own structures and the data segment.
const dataHeadroom = 256 << 20

// limitSelf bounds the child: its writable private memory (RLIMIT_DATA,
// which Linux counts for anonymous mappings; RLIMIT_AS would also count the
// address space the Go runtime reserves without using it) to what it already
// has plus memory plus headroom, no file it could write, at most 16
// descriptors, and no capabilities (the agent may hold CAP_NET_BIND_SERVICE
// as an ambient capability).
func limitSelf(memory int64) error {
	limits := []struct {
		resource int
		value    uint64
	}{
		{unix.RLIMIT_DATA, dataInUse() + uint64(memory) + dataHeadroom},
		{unix.RLIMIT_FSIZE, 0},
		{unix.RLIMIT_NOFILE, 16},
		{unix.RLIMIT_CORE, 0},
	}
	for _, l := range limits {
		if err := unix.Setrlimit(l.resource, &unix.Rlimit{Cur: l.value, Max: l.value}); err != nil {
			return err
		}
	}
	return dropCapabilities()
}

// dataInUse is the process's data size now (VmData, what RLIMIT_DATA
// counts): a few MiB in release builds, terabytes of shadow memory in a
// race-detector build, which a limit of memory plus headroom alone would
// leave no room beyond.
func dataInUse() uint64 {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for line := range strings.SplitSeq(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "VmData:"); ok {
			kb, err := strconv.ParseUint(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "kB")), 10, 64)
			if err != nil {
				return 0
			}
			return kb << 10
		}
	}
	return 0
}

// dropCapabilities clears the ambient set, then the permitted, effective
// and inheritable sets of every thread (capabilities are per thread). A
// runtime that counts as cgo (a build without the release tags links
// purego's stand-in for it) cannot change every thread: then the calling
// goroutine stays on its thread, which drops them, and does the conversion
// there (RunChild runs it on the calling goroutine).
func dropCapabilities() error {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	ambient := [3]uintptr{syscall.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL}
	capset := [3]uintptr{syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&header)), uintptr(unsafe.Pointer(&data[0]))}
	errno, ok := allThreads(ambient)
	if ok {
		if errno != 0 && errno != syscall.EINVAL {
			return errno
		}
		if errno, _ = allThreads(capset); errno != 0 {
			return errno
		}
		droppedEveryThread = true
		return nil
	}
	runtime.LockOSThread()
	if _, _, errno := syscall.RawSyscall(ambient[0], ambient[1], ambient[2], 0); errno != 0 && errno != syscall.EINVAL {
		return errno
	}
	if _, _, errno := syscall.RawSyscall(capset[0], capset[1], capset[2], 0); errno != 0 {
		return errno
	}
	return nil
}

// droppedEveryThread records which way dropCapabilities went (tests).
var droppedEveryThread bool

// allThreads runs a system call on every thread; ok is false when the
// runtime cannot: it panics when it counts as cgo (purego's stand-in) and
// returns ENOTSUP when it is linked with cgo (CGO_ENABLED=1 builds).
func allThreads(call [3]uintptr) (errno syscall.Errno, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	_, _, errno = syscall.AllThreadsSyscall(call[0], call[1], call[2], 0)
	if errno == syscall.ENOTSUP {
		return 0, false
	}
	return errno, true
}

// childProcess sets what the agent asks of the child process: killed with
// the agent, in its own process group.
func childProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
}
