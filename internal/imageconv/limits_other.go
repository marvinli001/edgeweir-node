//go:build !linux

package imageconv

import "os/exec"

// limitSelf sets no limits outside Linux (nodes run on Linux; other
// systems only run the tests).
func limitSelf(int64) error { return nil }

func childProcess(*exec.Cmd) {}
