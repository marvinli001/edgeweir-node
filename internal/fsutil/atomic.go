// Package fsutil contains crash-safe file helpers used for all persistent
// agent state (identity, keys, last-known-good configuration).
package fsutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// WriteFileAtomic replaces path with data so that concurrent readers and a
// crash at any point observe either the complete old or the complete new
// content, never a mix:
//
//  1. write a temporary file in the same directory,
//  2. set its permissions and fsync it,
//  3. rename it over path,
//  4. fsync the directory so the rename itself is durable.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", path, err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	// CreateTemp uses 0600; fchmod is not subject to the umask.
	if err = f.Chmod(perm); err != nil {
		return fmt.Errorf("chmod %s: %w", tmp, err)
	}
	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("fsync %s: %w", tmp, err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s: %w", path, err)
	}
	return SyncDir(dir)
}

// Rename renames oldpath to newpath and fsyncs the containing directory.
func Rename(oldpath, newpath string) error {
	if err := os.Rename(oldpath, newpath); err != nil {
		return err
	}
	return SyncDir(filepath.Dir(newpath))
}

// SyncDir fsyncs a directory so that entries created, renamed or removed in
// it survive a power loss. Filesystems that do not support fsync on
// directories are tolerated.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return fmt.Errorf("fsync dir %s: %w", dir, err)
	}
	return nil
}

// Exists reports whether path exists (following symlinks).
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
