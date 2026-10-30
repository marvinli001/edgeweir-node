package extension

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// File is one regular file of a package.
type File struct {
	Path string
	Data []byte
}

// Package is a verified package.
type Package struct {
	Manifest *Manifest
	SHA256   string
	Size     int
	KID      string
	Files    []File
}

var (
	segmentRE  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	topFileRE  = regexp.MustCompile(`^(LICENSE|NOTICE|README)[A-Za-z0-9._-]*$`)
	nativeRE   = regexp.MustCompile(`(?i)\.(so|dll|dylib|node|exe|bin)$`)
	b64url     = base64.RawURLEncoding
	errNotGzip = errors.New("not a gzip stream within the size limit")
)

func checkSegments(p string) error {
	for _, s := range strings.Split(p, "/") {
		if !segmentRE.MatchString(s) || s == "." || s == ".." {
			return fmt.Errorf("bad path %q", p)
		}
	}
	return nil
}

func checkPath(p string) error {
	if p == "" || len(p) > MaxPathBytes {
		return fmt.Errorf("bad path length %q", p)
	}
	if err := checkSegments(p); err != nil {
		return err
	}
	segments := strings.Split(p, "/")
	switch {
	case len(segments) == 1:
		if p != "manifest.json" && !topFileRE.MatchString(p) {
			return fmt.Errorf("unexpected file %q", p)
		}
	case segments[0] != "lua" && segments[0] != "assets":
		return fmt.Errorf("unexpected directory %q", segments[0])
	case segments[0] == "lua" && !strings.HasSuffix(p, ".lua"):
		return fmt.Errorf("not a Lua module: %q", p)
	}
	if nativeRE.MatchString(p) {
		return fmt.Errorf("native code: %q", p)
	}
	return nil
}

// ReadArchive parses a package: gzip, then a ustar stream of regular files
// and directories only.
func ReadArchive(archive []byte) ([]File, error) {
	if len(archive) > MaxArchiveBytes {
		return nil, errors.New("archive larger than 4 MiB")
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, errNotGzip
	}
	tr := tar.NewReader(io.LimitReader(gz, MaxUnpackedBytes+(1<<20)))
	var (
		files   []File
		seen    = map[string]bool{}
		total   int64
		entries int
	)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("archive: %w", err)
		}
		if entries++; entries > MaxEntries {
			return nil, errors.New("too many entries")
		}
		if h.Format != tar.FormatUSTAR && h.Format != tar.FormatPAX {
			return nil, fmt.Errorf("not a ustar entry: %q", h.Name)
		}
		for k := range h.PAXRecords {
			if k != "path" && k != "mtime" && k != "atime" && k != "ctime" {
				return nil, fmt.Errorf("unsupported pax record %s", k)
			}
		}
		name := strings.TrimPrefix(h.Name, "./")
		switch h.Typeflag {
		case tar.TypeDir:
			name = strings.TrimSuffix(name, "/")
			if name == "" {
				continue
			}
			if err := checkSegments(name); err != nil {
				return nil, err
			}
			if top := strings.SplitN(name, "/", 2)[0]; top != "lua" && top != "assets" {
				return nil, fmt.Errorf("unexpected directory %q", top)
			}
			continue
		case tar.TypeReg:
		default:
			return nil, fmt.Errorf("not a regular file: %q", name)
		}
		if err := checkPath(name); err != nil {
			return nil, err
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate entry %q", name)
		}
		seen[name] = true
		if h.Size > MaxFileBytes {
			return nil, fmt.Errorf("file larger than 4 MiB: %q", name)
		}
		if total += h.Size; total > MaxUnpackedBytes {
			return nil, errors.New("unpacked size larger than 16 MiB")
		}
		data, err := io.ReadAll(io.LimitReader(tr, h.Size))
		if err != nil || int64(len(data)) != h.Size {
			return nil, fmt.Errorf("truncated entry %q", name)
		}
		files = append(files, File{Path: name, Data: data})
	}
	return files, nil
}

// ReadManifest validates the files of a package and returns its manifest.
func ReadManifest(files []File) (*Manifest, error) {
	var manifest *Manifest
	hasMain := false
	for _, f := range files {
		switch {
		case f.Path == "manifest.json":
			m, err := ParseManifest(f.Data)
			if err != nil {
				return nil, err
			}
			manifest = m
		case f.Path == "lua/main.lua":
			hasMain = true
		}
		if strings.HasSuffix(f.Path, ".lua") {
			if len(f.Data) > 0 && f.Data[0] == 0x1b {
				return nil, fmt.Errorf("bytecode: %q", f.Path)
			}
			if !utf8.Valid(f.Data) {
				return nil, fmt.Errorf("not UTF-8 text: %q", f.Path)
			}
		}
	}
	if manifest == nil {
		return nil, errors.New("manifest.json missing")
	}
	if !hasMain {
		return nil, errors.New("lua/main.lua missing")
	}
	return manifest, nil
}

// Payload is the JWS payload of a package signature.
type Payload struct {
	Format    string `json:"format"`
	ID        string `json:"id"`
	Version   string `json:"version"`
	Publisher string `json:"publisher"`
	SHA256    string `json:"sha256"`
	Size      int    `json:"size"`
	IAT       int64  `json:"iat"`
}

// JWK is an OKP / Ed25519 key; D is set only for private keys.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	D   string `json:"d,omitempty"`
}

// PublicKey decodes the key's x.
func (k JWK) PublicKey() (ed25519.PublicKey, error) {
	if k.Kty != "OKP" || k.Crv != "Ed25519" {
		return nil, errors.New("not an Ed25519 JWK")
	}
	x, err := b64url.DecodeString(k.X)
	if err != nil || len(x) != ed25519.PublicKeySize {
		return nil, errors.New("not a 32-byte Ed25519 key")
	}
	return ed25519.PublicKey(x), nil
}

// Thumbprint is the RFC 7638 JWK thumbprint (the kid).
func Thumbprint(x string) string {
	sum := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`))
	return b64url.EncodeToString(sum[:])
}

// ParseSignature splits the JWS and checks its header and payload shape.
func ParseSignature(jws string) (kid string, payload Payload, signingInput string, sig []byte, err error) {
	parts := strings.Split(strings.TrimSpace(jws), ".")
	if len(parts) != 3 {
		return "", Payload{}, "", nil, errors.New("signature: not a compact JWS")
	}
	hb, err1 := b64url.DecodeString(parts[0])
	pb, err2 := b64url.DecodeString(parts[1])
	sig, err3 := b64url.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return "", Payload{}, "", nil, errors.New("signature: not a compact JWS")
	}
	var header map[string]any
	if err := json.Unmarshal(hb, &header); err != nil {
		return "", Payload{}, "", nil, errors.New("signature: bad header")
	}
	keys := make([]string, 0, len(header))
	for k := range header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	kid, _ = header["kid"].(string)
	if strings.Join(keys, ",") != "alg,kid,typ" || header["alg"] != "EdDSA" || header["typ"] != "edgeweir-ext+jws" || kid == "" {
		return "", Payload{}, "", nil, errors.New("signature: bad header")
	}
	dec := json.NewDecoder(bytes.NewReader(pb))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil || payload.Format != Format || len(payload.SHA256) != 64 {
		return "", Payload{}, "", nil, errors.New("signature: bad payload")
	}
	return kid, payload, parts[0] + "." + parts[1], sig, nil
}

// Verify checks a package against its signature and the signing key:
// signature, digest, size and identity, then the archive and manifest.
// publisher, when set, must be the key's publisher.
func Verify(archive []byte, jws string, key JWK, publisher string) (*Package, error) {
	if len(archive) > MaxArchiveBytes {
		return nil, errors.New("archive larger than 4 MiB")
	}
	kid, payload, input, sig, err := ParseSignature(jws)
	if err != nil {
		return nil, err
	}
	pub, err := key.PublicKey()
	if err != nil {
		return nil, err
	}
	if kid != Thumbprint(key.X) {
		return nil, errors.New("signature: kid is not the key's thumbprint")
	}
	if !ed25519.Verify(pub, []byte(input), sig) {
		return nil, errors.New("signature: invalid")
	}
	if publisher != "" && payload.Publisher != publisher {
		return nil, fmt.Errorf("signature: publisher %q is not %q", payload.Publisher, publisher)
	}
	sum := sha256.Sum256(archive)
	digest := hex.EncodeToString(sum[:])
	if payload.SHA256 != digest || payload.Size != len(archive) {
		return nil, errors.New("signature: digest or size does not match the package")
	}
	files, err := ReadArchive(archive)
	if err != nil {
		return nil, err
	}
	manifest, err := ReadManifest(files)
	if err != nil {
		return nil, err
	}
	if manifest.ID != payload.ID || manifest.Version != payload.Version || manifest.Publisher != payload.Publisher {
		return nil, errors.New("signature: identity does not match the manifest")
	}
	return &Package{Manifest: manifest, SHA256: digest, Size: len(archive), KID: kid, Files: files}, nil
}

// Sign returns the compact JWS of a package for a private JWK.
func Sign(archive []byte, key JWK, iat int64) (string, error) {
	files, err := ReadArchive(archive)
	if err != nil {
		return "", err
	}
	manifest, err := ReadManifest(files)
	if err != nil {
		return "", err
	}
	d, err := b64url.DecodeString(key.D)
	if err != nil || len(d) != ed25519.SeedSize {
		return "", errors.New("not an Ed25519 private JWK")
	}
	priv := ed25519.NewKeyFromSeed(d)
	if b64url.EncodeToString(priv.Public().(ed25519.PublicKey)) != key.X {
		return "", errors.New("private key does not match x")
	}
	sum := sha256.Sum256(archive)
	header, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": Thumbprint(key.X), "typ": "edgeweir-ext+jws"})
	payload, _ := json.Marshal(Payload{
		Format: Format, ID: manifest.ID, Version: manifest.Version, Publisher: manifest.Publisher,
		SHA256: hex.EncodeToString(sum[:]), Size: len(archive), IAT: iat,
	})
	input := b64url.EncodeToString(header) + "." + b64url.EncodeToString(payload)
	return input + "." + b64url.EncodeToString(ed25519.Sign(priv, []byte(input))), nil
}

// Pack writes a reproducible package of the files below dir's allowed
// entries: sorted, mtime 0, uid/gid 0, mode 0644 (directories 0755).
func Pack(files []File) ([]byte, error) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	var buf bytes.Buffer
	gz, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	tw := tar.NewWriter(gz)
	dirs := map[string]bool{}
	for _, f := range files {
		if err := checkPath(f.Path); err != nil {
			return nil, err
		}
		for d := path.Dir(f.Path); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
	}
	names := make([]string, 0, len(dirs))
	for d := range dirs {
		names = append(names, d)
	}
	sort.Strings(names)
	for _, d := range names {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: d + "/", Mode: 0o755, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}); err != nil {
			return nil, err
		}
	}
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: f.Path, Mode: 0o644, Size: int64(len(f.Data)), ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	if buf.Len() > MaxArchiveBytes {
		return nil, errors.New("archive larger than 4 MiB")
	}
	if _, err := ReadManifest(files); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
