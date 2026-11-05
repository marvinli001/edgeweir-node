//go:build !linux

package sidecar

import "os/exec"

func InheritCapabilities(*exec.Cmd) error { return nil }
func ClearInheritedCapabilities() error   { return nil }
func CapabilityHandoffSupported() bool    { return false }
