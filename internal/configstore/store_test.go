package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func cfg(t *testing.T, rev uint64, siteID string) *nodev1.NodeConfig {
	t.Helper()
	c := &nodev1.NodeConfig{
		Revision:  rev,
		ClusterId: "c1",
		Sites:     []*nodev1.Site{{Id: siteID, Enabled: true, Domains: []*nodev1.Domain{{Name: siteID + ".test"}}}},
	}
	h, err := configir.ContentHash(c)
	if err != nil {
		t.Fatal(err)
	}
	c.ContentHash = h
	return c
}

func TestSaveLoadAndBackup(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "config")}
	if _, _, err := s.Load(); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("empty store: err = %v, want ErrNoConfig", err)
	}

	c1 := cfg(t, 1, "a")
	c2 := cfg(t, 2, "b")
	if err := s.Save(c1); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(c2); err != nil {
		t.Fatal(err)
	}

	got, file, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if file != CurrentFile || !proto.Equal(got, c2) {
		t.Fatalf("Load = %v from %s, want revision 2 from current", got, file)
	}
	for _, name := range []string{CurrentFile, PreviousFile} {
		st, err := os.Stat(filepath.Join(s.Dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, want 0600", name, st.Mode().Perm())
		}
	}

	// A new Store instance (agent restart) reloads the same LKG.
	again, _, err := Store{Dir: s.Dir}.Load()
	if err != nil || again.GetRevision() != 2 {
		t.Fatalf("reload after restart: %v, %v", again, err)
	}
}

func TestLoadFallsBackToBackup(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if err := s.Save(cfg(t, 1, "a")); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(cfg(t, 2, "b")); err != nil {
		t.Fatal(err)
	}

	// Corrupt the current file: the hash check must reject it.
	cur := filepath.Join(s.Dir, CurrentFile)
	tampered := cfg(t, 2, "b")
	tampered.Sites[0].Id = "evil"
	data, _ := proto.Marshal(tampered)
	if err := os.WriteFile(cur, data, 0o600); err != nil {
		t.Fatal(err)
	}
	got, file, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if file != PreviousFile || got.GetRevision() != 1 {
		t.Fatalf("Load = revision %d from %s, want revision 1 from backup", got.GetRevision(), file)
	}

	// Garbage in both files: error.
	if err := os.WriteFile(filepath.Join(s.Dir, PreviousFile), []byte("\xff\xff"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load(); !errors.Is(err, ErrNoConfig) {
		t.Fatalf("err = %v, want ErrNoConfig", err)
	}
}
