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

// RaiseNofile sets the soft RLIMIT_NOFILE of this process to its hard
// limit. Go raises it at start-up but gives os/exec children the original
// soft limit back unless the program sets the limit itself: the nginx
// master opens every listening socket (layer-4 port ranges: one per port,
// one per worker with reuseport) under its own soft limit.
func RaiseNofile() {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return
	}
	rl.Cur = rl.Max
	_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rl)
}
