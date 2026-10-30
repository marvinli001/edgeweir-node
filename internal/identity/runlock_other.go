//go:build !unix

package identity

// LockRun is a no-op without flock.
func (s Store) LockRun() (release func(), err error) { return func() {}, nil }

// LockEnroll is a no-op without flock.
func (s Store) LockEnroll() (release func(), err error) { return func() {}, nil }

// lockIdentity is a no-op without flock.
func (s Store) lockIdentity() (release func(), err error) { return func() {}, nil }
