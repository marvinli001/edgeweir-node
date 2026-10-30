package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/extension"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
)

// cmdExtension packs, signs and verifies node extension packages for
// publishers (docs/reference/extensions.md in the console repository).
func cmdExtension(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		extensionUsage(stderr)
		return 2
	}
	switch args[0] {
	case "keygen":
		return cmdExtensionKeygen(args[1:], stdout, stderr)
	case "pack":
		return cmdExtensionPack(args[1:], stdout, stderr)
	case "sign":
		return cmdExtensionSign(args[1:], stdout, stderr)
	case "verify":
		return cmdExtensionVerify(args[1:], stdout, stderr)
	case "help", "--help", "-h":
		extensionUsage(stdout)
		return 0
	}
	fmt.Fprintf(stderr, "unknown extension command %q\n\n", args[0])
	extensionUsage(stderr)
	return 2
}

func extensionUsage(w io.Writer) {
	fmt.Fprint(w, `Usage:
  edgeweir-node extension keygen --out publisher.jwk
  edgeweir-node extension pack [--out FILE.ewx] DIR
  edgeweir-node extension sign --key publisher.jwk [--publisher NAME] FILE.ewx
  edgeweir-node extension verify --pubkey KEY [--publisher NAME] [--sig FILE.ewx.sig] FILE.ewx
`)
}

// positional parses flags and requires exactly one positional argument.
func positional(fs *flag.FlagSet, args []string) (string, bool, int) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", false, 0
		}
		return "", false, 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(fs.Output(), "exactly one file or directory is required (flags go first)")
		return "", false, 2
	}
	return fs.Arg(0), true, 0
}

func cmdExtensionKeygen(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("extension keygen", stderr)
	out := fs.String("out", "", "file for the private JWK (written 0600; must not exist)")
	if ok, code := parse(fs, args); !ok {
		return code
	}
	if *out == "" {
		fmt.Fprintln(stderr, "extension keygen: --out is required")
		return 2
	}
	if _, err := os.Stat(*out); err == nil {
		fmt.Fprintln(stderr, "extension keygen: refusing to overwrite", *out)
		return 1
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(stderr, "extension keygen:", err)
		return 1
	}
	enc := base64.RawURLEncoding
	key := extension.JWK{Kty: "OKP", Crv: "Ed25519", X: enc.EncodeToString(pub), D: enc.EncodeToString(priv.Seed())}
	data, _ := json.Marshal(key)
	if err := fsutil.WriteFileAtomic(*out, append(data, '\n'), 0o600); err != nil {
		fmt.Fprintln(stderr, "extension keygen:", err)
		return 1
	}
	public, _ := json.Marshal(extension.JWK{Kty: key.Kty, Crv: key.Crv, X: key.X})
	fmt.Fprintf(stdout, "public key: %s\nkid: %s\n", public, extension.Thumbprint(key.X))
	return 0
}

func cmdExtensionPack(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("extension pack", stderr)
	out := flags.String("out", "", "output file (default <id>-<version>.ewx)")
	dir, ok, code := positional(flags, args)
	if !ok {
		return code
	}
	var files []extension.File
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("not a regular file: %s", rel)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files = append(files, extension.File{Path: rel, Data: data})
		return nil
	})
	if err != nil {
		fmt.Fprintln(stderr, "extension pack:", err)
		return 1
	}
	archive, err := extension.Pack(files)
	if err != nil {
		fmt.Fprintln(stderr, "extension pack:", err)
		return 1
	}
	manifest, _ := extension.ReadManifest(files)
	name := *out
	if name == "" {
		name = manifest.ID + "-" + manifest.Version + ".ewx"
	}
	if err := fsutil.WriteFileAtomic(name, archive, 0o644); err != nil {
		fmt.Fprintln(stderr, "extension pack:", err)
		return 1
	}
	fmt.Fprintln(stdout, name)
	return 0
}

func readJWK(path string) (extension.JWK, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return extension.JWK{}, err
	}
	var key extension.JWK
	text := strings.TrimSpace(string(data))
	if strings.HasPrefix(text, "{") {
		if err := json.Unmarshal([]byte(text), &key); err != nil {
			return extension.JWK{}, fmt.Errorf("%s: not a JWK", path)
		}
		return key, nil
	}
	return extension.JWK{Kty: "OKP", Crv: "Ed25519", X: text}, nil
}

func cmdExtensionSign(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("extension sign", stderr)
	keyFile := fs.String("key", "", "private JWK from extension keygen")
	publisher := fs.String("publisher", "", "refuse unless the manifest's publisher is this")
	file, ok, code := positional(fs, args)
	if !ok {
		return code
	}
	key, err := readJWK(*keyFile)
	if err != nil {
		fmt.Fprintln(stderr, "extension sign:", err)
		return 2
	}
	archive, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintln(stderr, "extension sign:", err)
		return 1
	}
	jws, err := extension.Sign(archive, key, time.Now().Unix())
	if err != nil {
		fmt.Fprintln(stderr, "extension sign:", err)
		return 1
	}
	if _, err := extension.Verify(archive, jws, key, *publisher); err != nil {
		fmt.Fprintln(stderr, "extension sign:", err)
		return 1
	}
	if err := fsutil.WriteFileAtomic(file+".sig", []byte(jws+"\n"), 0o644); err != nil {
		fmt.Fprintln(stderr, "extension sign:", err)
		return 1
	}
	fmt.Fprintln(stdout, file+".sig")
	return 0
}

func cmdExtensionVerify(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("extension verify", stderr)
	keyFile := fs.String("pubkey", "", "public key: JWK file or a file with the base64url x")
	publisher := fs.String("publisher", "", "required publisher")
	sigFile := fs.String("sig", "", "signature file (default FILE.sig)")
	file, ok, code := positional(fs, args)
	if !ok {
		return code
	}
	key, err := readJWK(*keyFile)
	if err != nil {
		fmt.Fprintln(stderr, "extension verify:", err)
		return 2
	}
	key.D = ""
	if *sigFile == "" {
		*sigFile = file + ".sig"
	}
	archive, err1 := os.ReadFile(file)
	jws, err2 := os.ReadFile(*sigFile)
	if err := errors.Join(err1, err2); err != nil {
		fmt.Fprintln(stderr, "extension verify:", err)
		return 1
	}
	pkg, err := extension.Verify(archive, string(jws), key, *publisher)
	if err != nil {
		fmt.Fprintln(stderr, "extension verify:", err)
		return 1
	}
	fmt.Fprintf(stdout, "ok %s %s %s sha256:%s kid:%s\n", pkg.Manifest.ID, pkg.Manifest.Version, pkg.Manifest.Publisher, pkg.SHA256, pkg.KID)
	return 0
}
