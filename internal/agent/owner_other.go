//go:build !unix

package agent

func chownToUser(string, ...string) error { return nil }
