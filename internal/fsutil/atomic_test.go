package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")

	if err := WriteFileAtomic(path, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(path, []byte("two"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "two" {
		t.Fatalf("content = %q, want %q", got, "two")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", st.Mode().Perm())
	}
	// No temporary files may be left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory has %d entries, want 1: %v", len(entries), entries)
	}
}

func TestWriteFileAtomicPermIgnoresUmask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "public.crt")
	if err := WriteFileAtomic(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", st.Mode().Perm())
	}
}

func TestWriteFileAtomicMissingDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "file")
	if err := WriteFileAtomic(path, []byte("x"), 0o600); err == nil {
		t.Fatal("expected error for missing directory")
	}
}
