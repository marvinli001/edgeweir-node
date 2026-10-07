//go:build !unix

package hostinfo

// NofileHardLimit is unknown on this platform.
func NofileHardLimit() uint64 { return 0 }

// RaiseNofile does nothing on this platform.
func RaiseNofile() {}
