//go:build !linux

package sidecar

func execSandboxed(*Spec) error { return ErrUnsupported }

// Supported reports whether this platform can isolate sidecars.
func Supported() bool { return false }
