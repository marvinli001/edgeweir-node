package upgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
)

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Installing a new image/system package must take precedence over an older
// self-updated agent left in the state volume. Normal restarts preserve it.
func baseDigest(opts Options) (string, error) {
	binary, err := fileHash(opts.Executable)
	if err != nil {
		return "", err
	}
	files, err := filepath.Glob(filepath.Join(opts.LuaDir, "edgeweir", "*.lua"))
	if err != nil {
		return "", err
	}
	type entry struct {
		Name   string
		SHA256 string
	}
	entries := []entry{}
	for _, file := range files {
		sum, err := fileHash(file)
		if err != nil {
			return "", err
		}
		entries = append(entries, entry{filepath.Base(file), sum})
	}
	raw, err := json.Marshal(struct {
		Version, Binary, LuaDir string
		Lua                     []entry
	}{opts.Version, binary, opts.LuaDir, entries})
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}
