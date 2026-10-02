//go:build !unix

package identity

// LockRun is a no-op without flock.
func (s Store) LockRun() (release func(), err error) { return func() {}, nil }
