//go:build !linux

package sandbox

import "os/exec"

// Limit sets no limits outside Linux (nodes run on Linux; other
// systems only run the tests).
func Limit(int64) error { return nil }

func childProcess(*exec.Cmd) {}
