//go:build unix

package agent

import (
	"io/fs"
	"syscall"
)

// allocatedBytes is the space a file occupies on disk (st_blocks are 512
// bytes), its size where the platform does not say.
func allocatedBytes(info fs.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Blocks) * 512
	}
	return uint64(max(info.Size(), 0))
}
