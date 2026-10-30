//go:build unix

package identity

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// LockRun takes the run lock of the state directory (RunLockFile, flock):
// `edgeweir-node run` holds it while it uses the identity, `enroll --force`
// while it replaces one, so that an identity is never replaced under a
// running agent. It fails with ErrRunning when another process holds it.
func (s Store) LockRun() (release func(), err error) {
	if err := s.EnsureDir(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.Path(RunLockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open run lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrRunning
		}
		return nil, fmt.Errorf("run lock: %w", err)
	}
	return func() { _ = f.Close() }, nil
}

// LockEnroll takes the enrollment lock of the state directory
// (EnrollLockFile, flock): two enrollments of one host at the same time
// (a retried batch install while the first attempt still runs) would
// both use a token and leave the console with two nodes. It fails with
// ErrEnrolling when another process holds it.
func (s Store) LockEnroll() (release func(), err error) {
	if err := s.EnsureDir(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.Path(EnrollLockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open enroll lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrEnrolling
		}
		return nil, fmt.Errorf("enroll lock: %w", err)
	}
	return func() { _ = f.Close() }, nil
}

// lockIdentity takes the identity lock (IdentityLockFile, flock), waiting
// for another process that changes the console address. The file is opened
// read-only (flock needs no write access) and created 0644, so the agent's
// service user and `sudo edgeweir-node set-server` share it whoever
// created it.
func (s Store) lockIdentity() (release func(), err error) {
	if err := s.EnsureDir(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(s.Path(IdentityLockFile), os.O_CREATE|os.O_RDONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open identity lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("identity lock: %w", err)
	}
	return func() { _ = f.Close() }, nil
}
