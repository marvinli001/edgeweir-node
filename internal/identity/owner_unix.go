//go:build unix

package identity

import (
	"os"
	"path/filepath"
	"syscall"
)

// matchDirOwner makes files written by root (e.g. `sudo edgeweir-node
// enroll`) readable by the unprivileged service user that owns the state
// directory. It is a no-op for non-root callers.
func matchDirOwner(dir string, names ...string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid == 0 {
		return nil
	}
	for _, n := range names {
		if err := os.Lchown(filepath.Join(dir, n), int(sys.Uid), int(sys.Gid)); err != nil {
			return err
		}
	}
	return nil
}
