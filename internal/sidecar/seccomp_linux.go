//go:build linux

package sidecar

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// Seccomp return values and BPF opcodes (linux/seccomp.h, linux/filter.h).
const (
	retKillProcess = 0x80000000
	retErrno       = 0x00050000
	retAllow       = 0x7fff0000

	ldAbs = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
	jeq   = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
	jge   = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
	jset  = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
	ret   = unix.BPF_RET | unix.BPF_K

	auditArchX8664   = 0xc000003e
	auditArchAArch64 = 0xc00000b7
	x32SyscallBit    = 0x40000000

	// Offsets in struct seccomp_data.
	offNr   = 0
	offArch = 4
	offArg0 = 16 // low 32 bits on little-endian

	cloneNamespaces = unix.CLONE_NEWNS | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC | unix.CLONE_NEWUSER |
		unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWCGROUP
)

// denied are refused with EPERM: tracing and other processes' memory,
// mounts and namespaces, BPF, perf, keyrings, kernel modules, reboot and
// kexec, the clocks, swap and accounting, file handles and userfaultfd.
var denied = []uint32{
	unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
	unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_UNSHARE, unix.SYS_SETNS,
	unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
	unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE, unix.SYS_REBOOT, unix.SYS_KEXEC_LOAD,
	unix.SYS_SETTIMEOFDAY, unix.SYS_CLOCK_SETTIME, unix.SYS_CLOCK_ADJTIME, unix.SYS_ADJTIMEX,
	unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_ACCT, unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_NAME_TO_HANDLE_AT,
	unix.SYS_USERFAULTFD, unix.SYS_FSOPEN, unix.SYS_FSMOUNT, unix.SYS_MOVE_MOUNT, unix.SYS_OPEN_TREE,
}

func stmt(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k, Jt: jt, Jf: jf}
}

// filter is a denylist: anything not listed is allowed. clone3 answers
// ENOSYS (its flags are out of reach of a filter; libc falls back to
// clone), clone with namespace flags EPERM; another architecture or the
// x32 ABI kills the process.
func filter() []unix.SockFilter {
	arch := uint32(auditArchX8664)
	if runtime.GOARCH == "arm64" {
		arch = auditArchAArch64
	}
	p := []unix.SockFilter{
		stmt(ldAbs, offArch),
		jump(jeq, arch, 1, 0),
		stmt(ret, retKillProcess),
		stmt(ldAbs, offNr),
		jump(jge, x32SyscallBit, 0, 1),
		stmt(ret, retKillProcess),
		jump(jeq, unix.SYS_CLONE3, 0, 1),
		stmt(ret, retErrno|uint32(unix.ENOSYS)),
		jump(jeq, unix.SYS_CLONE, 0, 4),
		stmt(ldAbs, offArg0),
		jump(jset, cloneNamespaces, 0, 1),
		stmt(ret, retErrno|uint32(unix.EPERM)),
		stmt(ret, retAllow),
	}
	for _, nr := range denied {
		p = append(p, jump(jeq, nr, 0, 1), stmt(ret, retErrno|uint32(unix.EPERM)))
	}
	return append(p, stmt(ret, retAllow))
}
