package extension

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata vectors")

// testKey is derived from a fixed seed, so that no private key is stored;
// the console's tests derive the same key (apps/console/test/server/extensions.test.ts).
func testKey() JWK {
	seed := sha256.Sum256([]byte("edgeweir extension test key"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	enc := base64.RawURLEncoding
	return JWK{Kty: "OKP", Crv: "Ed25519", X: enc.EncodeToString(priv.Public().(ed25519.PublicKey)), D: enc.EncodeToString(seed[:])}
}

func exampleFiles(t *testing.T) []File {
	t.Helper()
	root := "../../examples/extensions/hello-header"
	var files []File
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		rel, _ := filepath.Rel(root, path)
		files = append(files, File{Path: filepath.ToSlash(rel), Data: data})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// TestVectors keeps testdata/hello-header-1.0.0.ewx(.sig) in step with the
// example; the console's tests read the same files.
func TestVectors(t *testing.T) {
	archive, err := Pack(exampleFiles(t))
	if err != nil {
		t.Fatal(err)
	}
	key := testKey()
	jws, err := Sign(archive, key, 1793318400)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := json.Marshal(JWK{Kty: key.Kty, Crv: key.Crv, X: key.X})
	files := map[string][]byte{
		"hello-header-1.0.0.ewx":     archive,
		"hello-header-1.0.0.ewx.sig": []byte(jws + "\n"),
		"test-key.pub.jwk":           append(pub, '\n'),
	}
	for name, want := range files {
		path := filepath.Join("testdata", name)
		if *update {
			if err := os.WriteFile(path, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s differs from the example (go test ./internal/extension -update)", name)
		}
	}
	pkg, err := Verify(archive, jws, JWK{Kty: "OKP", Crv: "Ed25519", X: key.X}, "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Manifest.ID != "hello-header" || len(pkg.Manifest.SharedDicts) != 1 || pkg.KID != Thumbprint(key.X) {
		t.Fatalf("unexpected package %+v", pkg.Manifest)
	}
}

func tarGz(t *testing.T, entries ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, h := range entries {
		if h.Format == 0 {
			h.Format = tar.FormatUSTAR
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write(bytes.Repeat([]byte("x"), int(h.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestReadArchiveRejects(t *testing.T) {
	cases := map[string][]byte{
		"symlink":   tarGz(t, &tar.Header{Typeflag: tar.TypeSymlink, Name: "lua/main.lua", Linkname: "/etc/passwd"}),
		"traversal": tarGz(t, &tar.Header{Typeflag: tar.TypeReg, Name: "lua/../../x.lua", Size: 1}),
		"absolute":  tarGz(t, &tar.Header{Typeflag: tar.TypeReg, Name: "/lua/main.lua", Size: 1}),
		"native":    tarGz(t, &tar.Header{Typeflag: tar.TypeReg, Name: "assets/x.so", Size: 1}),
		"other dir": tarGz(t, &tar.Header{Typeflag: tar.TypeReg, Name: "bin/run", Size: 1}),
		"not lua":   tarGz(t, &tar.Header{Typeflag: tar.TypeReg, Name: "lua/x.txt", Size: 1}),
		"duplicate": tarGz(t, &tar.Header{Typeflag: tar.TypeReg, Name: "lua/a.lua", Size: 1}, &tar.Header{Typeflag: tar.TypeReg, Name: "lua/a.lua", Size: 1}),
		"not gzip":  []byte("plain"),
	}
	for name, archive := range cases {
		if _, err := ReadArchive(archive); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVerifyRejects(t *testing.T) {
	archive, _ := Pack(exampleFiles(t))
	key := testKey()
	pub := JWK{Kty: "OKP", Crv: "Ed25519", X: key.X}
	jws, _ := Sign(archive, key, 1)
	other := sha256.Sum256([]byte("other"))
	otherKey := ed25519.NewKeyFromSeed(other[:])
	wrong := JWK{Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(otherKey.Public().(ed25519.PublicKey))}
	tampered := bytes.Clone(archive)
	tampered[len(tampered)-5] ^= 1
	parts := strings.Split(jws, ".")
	if _, err := Verify(tampered, jws, pub, ""); err == nil {
		t.Error("tampered package accepted")
	}
	if _, err := Verify(archive, jws, wrong, ""); err == nil {
		t.Error("another key accepted")
	}
	if _, err := Verify(archive, jws, pub, "evil.example"); err == nil {
		t.Error("another publisher accepted")
	}
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"x","typ":"edgeweir-ext+jws"}`))
	if _, err := Verify(archive, none+"."+parts[1]+".", pub, ""); err == nil {
		t.Error("alg none accepted")
	}
}

func TestManifestRules(t *testing.T) {
	base := `{"format":"edgeweir-node-extension-v1","id":"a-b","version":"1.0.0","publisher":"example.org","name":{"en":"A"},"requires":{"lua_api":1},"hooks":["access"]%s}`
	if _, err := ParseManifest([]byte(strings.Replace(base, "%s", "", 1))); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{
		`,"unknown":1`,
		`,"capabilities":["root"]`,
		`,"counters":["faults"]`,
		`,"endpoints":[{"path":"x","methods":["GET"]}]`,
		`,"shared_dicts":[{"name":"a","size_kb":20000},{"name":"b","size_kb":20000}]`,
		`,"requires":{"lua_api":1,"node":"~1"}`,
	} {
		if _, err := ParseManifest([]byte(strings.Replace(base, "%s", extra, 1))); err == nil {
			t.Errorf("accepted %s", extra)
		}
	}
	r, _ := ParseRange(">=1.7.0 <2.0.0")
	for v, want := range map[string]bool{"v1.7.0": true, "1.9.9": true, "2.0.0": false, "1.7.0-rc.1": false} {
		parsed, _ := ParseVersion(v)
		if r.Contains(parsed) != want {
			t.Errorf("%s in range: %v", v, !want)
		}
	}
}

// TestVersion11Manifest checks the members of extension version 1.1.
func TestVersion11Manifest(t *testing.T) {
	base := `{"format":"edgeweir-node-extension-v1","id":"a-b","version":"1.0.0","publisher":"example.org","name":{"en":"A"},"hooks":["access_late"]%s}`
	sidecar := `"capabilities":["sidecar"],"sidecar":{"binary":"run","memory_mb":256}`
	for _, ok := range []string{
		`,"requires":{"lua_api":2},"secret":true`,
		`,"requires":{"lua_api":2},"counters":["a","b","c","d","e","f","g","h","i"]`,
		`,"requires":{"lua_api":2},` + sidecar,
		`,"requires":{"lua_api":2},` + sidecar + `,"data":{"max_bytes":1024,"max_items":2,"max_total_bytes":2048}`,
	} {
		if _, err := ParseManifest([]byte(strings.Replace(base, "%s", ok, 1))); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{
		`,"requires":{"lua_api":1},"secret":true`,
		`,"requires":{"lua_api":1},"counters":["a","b","c","d","e","f","g","h","i"]`,
		`,"requires":{"lua_api":2},"sidecar":{"binary":"run","memory_mb":256}`,
		`,"requires":{"lua_api":2},"capabilities":["sidecar"]`,
		`,"requires":{"lua_api":2},"data":{"max_bytes":1024,"max_items":2,"max_total_bytes":2048}`,
		`,"requires":{"lua_api":2},"capabilities":["sidecar"],"sidecar":{"binary":"run","memory_mb":8}`,
		`,"requires":{"lua_api":2},"capabilities":["sidecar"],"sidecar":{"binary":"run","memory_mb":256,"timeout_s":61}`,
		`,"requires":{"lua_api":2},"capabilities":["sidecar"],"sidecar":{"binary":"run","memory_mb":256,"env":{"EDGEWEIR_X":"1"}}`,
		`,"requires":{"lua_api":2},"capabilities":["sidecar"],"sidecar":{"binary":"../run","memory_mb":256}`,
	} {
		if _, err := ParseManifest([]byte(strings.Replace(base, "%s", bad, 1))); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// elf returns the start of a 64-bit little-endian ELF executable for an
// e_machine.
func elf(machine uint16) []byte {
	b := make([]byte, 64)
	copy(b, "\x7fELF")
	b[4], b[5] = 2, 1
	b[18], b[19] = byte(machine), byte(machine>>8)
	return b
}

// TestSidecarPackages: sidecar binaries only with a manifest sidecar and
// for their architecture.
func TestSidecarPackages(t *testing.T) {
	manifest := func(sidecar bool) File {
		m := `{"format":"edgeweir-node-extension-v1","id":"a-b","version":"1.0.0","publisher":"example.org","name":{"en":"A"},"requires":{"lua_api":2},"hooks":["access_late"]`
		if sidecar {
			m += `,"capabilities":["sidecar"],"sidecar":{"binary":"run","memory_mb":256}`
		}
		return File{Path: "manifest.json", Data: []byte(m + "}")}
	}
	main := File{Path: "lua/main.lua", Data: []byte("return {}")}
	pkg := func(files ...File) error {
		_, err := Pack(files)
		return err
	}
	if err := pkg(manifest(true), main, File{Path: "sidecar/linux-amd64/run", Data: elf(62)}, File{Path: "sidecar/linux-arm64/run", Data: elf(183)}); err != nil {
		t.Fatal(err)
	}
	for name, files := range map[string][]File{
		"no binary":       {manifest(true), main},
		"no sidecar":      {manifest(false), main, {Path: "sidecar/linux-amd64/run", Data: elf(62)}},
		"other binary":    {manifest(true), main, {Path: "sidecar/linux-amd64/other", Data: elf(62)}},
		"wrong machine":   {manifest(true), main, {Path: "sidecar/linux-amd64/run", Data: elf(183)}},
		"not elf":         {manifest(true), main, {Path: "sidecar/linux-amd64/run", Data: []byte("#!/bin/sh\n")}},
		"other arch":      {manifest(true), main, {Path: "sidecar/linux-riscv64/run", Data: elf(243)}},
		"nested":          {manifest(true), main, {Path: "sidecar/linux-amd64/x/run", Data: elf(62)}},
		"big without one": {manifest(false), main, {Path: "assets/big", Data: make([]byte, MaxFileBytes+1)}},
	} {
		if err := pkg(files...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
