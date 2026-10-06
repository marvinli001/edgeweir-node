//go:build !unix

package agent

import "io/fs"

// allocatedBytes is the file's size where the platform does not report
// allocated blocks.
func allocatedBytes(info fs.FileInfo) uint64 { return uint64(max(info.Size(), 0)) }
