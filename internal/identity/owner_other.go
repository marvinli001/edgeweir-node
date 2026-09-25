//go:build !unix

package identity

func matchDirOwner(string, ...string) error { return nil }
