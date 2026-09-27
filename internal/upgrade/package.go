// Package upgrade installs only release artifacts verified against an operator's
// local trust policy. The console cannot supply a new trust root or shell command.
package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/fsutil"
)

const DefaultSource = "https://github.com/marvinli001/edgeweir-node/releases/download"

var versionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
var taskRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Task struct {
	ID           string `json:"id"`
	Version      string `json:"version"`
	ArchiveURL   string `json:"archive_url"`
	SHA256       string `json:"sha256"`
	ChecksumsURL string `json:"checksums_url"`
	SignatureURL string `json:"signature_url"`
}
type Bundle struct {
	TaskID  string `json:"task_id"`
	Version string `json:"version"`
	Dir     string `json:"dir"`
	SHA256  string `json:"sha256"`
}
type Trust struct {
	StateDir  string
	Source    string
	Cosign    string
	PublicKey string // Optional operator-provided local public key; never from Task.
	AllowHTTP bool   // Explicitly configured local test/air-gap mirror only.
}

func (o Trust) validate(t Task) (string, error) {
	if !taskRE.MatchString(t.ID) || !versionRE.MatchString(t.Version) || len(t.Version) > 64 || !hashRE.MatchString(t.SHA256) {
		return "", errors.New("invalid upgrade task")
	}
	base := strings.TrimRight(o.Source, "/")
	if base == "" {
		base = DefaultSource
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(o.AllowHTTP && u.Scheme == "http")) {
		return "", errors.New("invalid local upgrade source policy")
	}
	prefix := base + "/v" + t.Version + "/"
	name := "edgeweir-node_" + t.Version + "_linux_" + runtime.GOARCH + ".tar.gz"
	if t.ArchiveURL != prefix+name || t.ChecksumsURL != prefix+"checksums.txt" || t.SignatureURL != prefix+"checksums.txt.sigstore.json" {
		return "", errors.New("upgrade URL is outside the locally trusted release source")
	}
	return name, nil
}
func (o Trust) client() *http.Client {
	base := strings.TrimRight(o.Source, "/")
	if base == "" {
		base = DefaultSource
	}
	origin, _ := url.Parse(base)
	return &http.Client{Timeout: 90 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 || r.URL.User != nil {
			return errors.New("upgrade redirect refused")
		}
		if origin != nil && r.URL.Host == origin.Host && r.URL.Scheme == origin.Scheme {
			return nil
		}
		if base == DefaultSource && r.URL.Scheme == "https" && (r.URL.Host == "release-assets.githubusercontent.com" || r.URL.Host == "objects.githubusercontent.com") {
			return nil
		}
		return errors.New("upgrade redirect left the trusted source")
	}}
}
func download(ctx context.Context, client *http.Client, source, destination string, limit int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("upgrade download failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > limit {
		return fmt.Errorf("upgrade download rejected (status %d or size limit)", resp.StatusCode)
	}
	// Download files also use the atomic state helper; each read has an explicit cap.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return errors.New("upgrade download exceeds size limit")
	}
	return fsutil.WriteFileAtomic(destination, raw, 0600)
}

// cappedOutput drains a subprocess without allowing its output to grow memory.
type cappedOutput struct {
	buf   bytes.Buffer
	limit int
}

func (w *cappedOutput) String() string { return w.buf.String() }
func (w *cappedOutput) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := w.limit - w.buf.Len(); remaining > 0 {
		_, _ = w.buf.Write(p[:min(n, remaining)])
	}
	return n, nil
}
func command(ctx context.Context, bin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	out := &cappedOutput{limit: 8192}
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	return out.String(), err
}
func Prepare(ctx context.Context, o Trust, t Task) (Bundle, error) {
	name, err := o.validate(t)
	if err != nil {
		return Bundle{}, err
	}
	verifier := o.Cosign
	if verifier == "" {
		verifier = "cosign"
	}
	verifier, err = exec.LookPath(verifier)
	if err != nil {
		return Bundle{}, errors.New("signature verifier is unavailable")
	}
	releases := filepath.Join(o.StateDir, "upgrades", "releases")
	if err = os.MkdirAll(releases, 0700); err != nil {
		return Bundle{}, err
	}
	staging, err := os.MkdirTemp(releases, ".stage-")
	if err != nil {
		return Bundle{}, err
	}
	defer os.RemoveAll(staging)
	client := o.client()
	for _, file := range []struct {
		url, name string
		limit     int64
	}{{t.ChecksumsURL, "checksums.txt", 2 << 20}, {t.SignatureURL, "bundle.json", 4 << 20}, {t.ArchiveURL, "archive.tar.gz", 128 << 20}} {
		if err = download(ctx, client, file.url, filepath.Join(staging, file.name), file.limit); err != nil {
			return Bundle{}, err
		}
	}
	args := []string{"verify-blob", "--bundle", filepath.Join(staging, "bundle.json")}
	if o.PublicKey != "" {
		args = append(args, "--key", o.PublicKey, "--insecure-ignore-tlog")
	} else {
		args = append(args, "--certificate-identity", "https://github.com/marvinli001/edgeweir-node/.github/workflows/release.yml@refs/tags/v"+t.Version, "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com")
	}
	args = append(args, filepath.Join(staging, "checksums.txt"))
	if _, err = command(ctx, verifier, args...); err != nil {
		return Bundle{}, errors.New("release signature verification failed")
	}
	sums, err := os.ReadFile(filepath.Join(staging, "checksums.txt"))
	if err != nil {
		return Bundle{}, err
	}
	matches := 0
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			matches++
			if fields[0] != t.SHA256 {
				return Bundle{}, errors.New("task checksum differs from the signed release manifest")
			}
		}
	}
	if matches != 1 {
		return Bundle{}, errors.New("signed release manifest must name the archive exactly once")
	}
	archive := filepath.Join(staging, "archive.tar.gz")
	file, err := os.Open(archive)
	if err != nil {
		return Bundle{}, err
	}
	digest := sha256.New()
	_, err = io.Copy(digest, file)
	_ = file.Close()
	if err != nil {
		return Bundle{}, err
	}
	if hex.EncodeToString(digest.Sum(nil)) != t.SHA256 {
		return Bundle{}, errors.New("archive checksum verification failed")
	}
	unpack := filepath.Join(staging, "unpacked")
	if err = extract(archive, unpack, strings.TrimSuffix(name, ".tar.gz")); err != nil {
		return Bundle{}, err
	}
	if err = validateExecutable(filepath.Join(unpack, "edgeweir-node")); err != nil {
		return Bundle{}, err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	output, err := command(checkCtx, filepath.Join(unpack, "edgeweir-node"), "version")
	cancel()
	if err != nil || !strings.HasPrefix(output, "edgeweir-node "+t.Version+" (") {
		return Bundle{}, errors.New("archive executable version or architecture is invalid")
	}
	dest := filepath.Join(releases, t.ID)
	if _, err = os.Lstat(dest); !os.IsNotExist(err) {
		return Bundle{}, errors.New("upgrade release directory already exists")
	}
	if err = fsutil.Rename(unpack, dest); err != nil {
		return Bundle{}, err
	}
	return Bundle{TaskID: t.ID, Version: t.Version, Dir: dest, SHA256: t.SHA256}, nil
}
func extract(archive, destination, root string) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	reader := tar.NewReader(io.LimitReader(gz, 256<<20))
	seen := map[string]bool{}
	count := 0
	var size int64
	for {
		h, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		count++
		size += h.Size
		if count > 512 || h.Size < 0 || h.Size > 128<<20 || size > 256<<20 {
			return errors.New("upgrade archive exceeds extraction limits")
		}
		clean := path.Clean(h.Name)
		if strings.Contains(h.Name, "\\") || strings.HasPrefix(clean, "/") || (clean != root && !strings.HasPrefix(clean, root+"/")) || strings.Contains(h.Name, "../") {
			return errors.New("unsafe upgrade archive path")
		}
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeRegA {
			return errors.New("upgrade archive contains a link or special file")
		}
		rel := strings.TrimPrefix(clean, root+"/")
		if seen[rel] {
			return errors.New("duplicate upgrade archive member")
		}
		seen[rel] = true
		if rel != "edgeweir-node" && !(strings.HasPrefix(rel, "lua/edgeweir/") && strings.HasSuffix(rel, ".lua") && !strings.Contains(strings.TrimPrefix(rel, "lua/edgeweir/"), "/")) {
			continue
		}
		target := filepath.Join(destination, filepath.FromSlash(rel))
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		raw, err := io.ReadAll(reader)
		if err != nil {
			return err
		}
		perm := os.FileMode(0600)
		if rel == "edgeweir-node" {
			perm = 0700
		}
		if err = fsutil.WriteFileAtomic(target, raw, perm); err != nil {
			return err
		}
	}
	for _, name := range []string{"edgeweir-node", "lua/edgeweir/init.lua"} {
		if !fsutil.Exists(filepath.Join(destination, name)) {
			return errors.New("upgrade bundle lacks executable or Lua entry point")
		}
	}
	for _, dir := range []string{"lua/edgeweir", "lua", ""} {
		if err = fsutil.SyncDir(filepath.Join(destination, dir)); err != nil {
			return err
		}
	}
	return nil
}

func validateExecutable(path string) error {
	file, err := elf.Open(path)
	if err != nil {
		return errors.New("upgrade executable is not an ELF binary")
	}
	defer file.Close()
	machine := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[runtime.GOARCH]
	if machine == 0 || file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Machine != machine || (file.Type != elf.ET_EXEC && file.Type != elf.ET_DYN) {
		return errors.New("upgrade executable architecture is incorrect")
	}
	return nil
}
