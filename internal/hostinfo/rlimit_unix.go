//go:build unix

package hostinfo

import "syscall"

// NofileHardLimit returns the hard RLIMIT_NOFILE of this process, or 0 if
// unknown. nginx workers may raise their soft limit up to it
// (worker_rlimit_nofile); os/exec children otherwise inherit the original
// soft limit, often only 1024.
func NofileHardLimit() uint64 {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0
	}
	return uint64(rl.Max)
}
