package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"connectrpc.com/connect"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/extension"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/version"
)

// ExtensionsConfig is the node's own say over node extensions
// (docs/reference/extensions.md in the console repository).
type ExtensionsConfig struct {
	// Disabled (--no-extensions): extensions-v1 is not announced and no
	// package is downloaded or loaded; the console cannot override it.
	Disabled bool
	// KeysFile (--extension-keys) lists the publisher keys (JWKs, one per
	// line, or a JSON array) this node accepts on top of the console's
	// trust store; empty: whatever key the console delivers.
	KeysFile string
}

// extensionsDir holds the packages (<sha256>.ewx) and their unpacked trees
// (<sha256>/), which nginx workers read.
func (a *Agent) extensionsDir() string { return filepath.Join(a.cfg.StateDir, "extensions") }

// localExtensionKeys reads --extension-keys; nil without one.
func (a *Agent) localExtensionKeys() ([]string, error) {
	if a.cfg.Extensions.KeysFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(a.cfg.Extensions.KeysFile)
	if err != nil {
		return nil, err
	}
	var keys []extension.JWK
	text := strings.TrimSpace(string(data))
	if strings.HasPrefix(text, "[") {
		if err := json.Unmarshal([]byte(text), &keys); err != nil {
			return nil, fmt.Errorf("%s: %w", a.cfg.Extensions.KeysFile, err)
		}
	} else {
		for _, line := range strings.Split(text, "\n") {
			if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			var k extension.JWK
			if err := json.Unmarshal([]byte(line), &k); err != nil {
				return nil, fmt.Errorf("%s: %w", a.cfg.Extensions.KeysFile, err)
			}
			keys = append(keys, k)
		}
	}
	xs := make([]string, 0, len(keys))
	for _, k := range keys {
		if _, err := k.PublicKey(); err != nil {
			return nil, fmt.Errorf("%s: %w", a.cfg.Extensions.KeysFile, err)
		}
		xs = append(xs, k.X)
	}
	return xs, nil
}

// errTransient marks a failure worth failing the apply for (it is retried).
type errTransient struct{ error }

// ensureExtensions makes each extension of the plan loadable: the package
// is fetched by digest (GetExtensionPackage), checked against size, digest,
// signature and key, unpacked and its manifest checked again; Dir is set
// for those that pass. A package that fails is reported and left out; the
// rest of the configuration applies. Only a console that cannot be reached
// fails the apply (retried with the next sync).
func (a *Agent) ensureExtensions(ctx context.Context, plan *configir.Plan) error {
	if len(plan.Extensions) == 0 {
		return nil
	}
	local, keysErr := a.localExtensionKeys()
	for i := range plan.Extensions {
		e := &plan.Extensions[i]
		if a.cfg.Extensions.Disabled {
			e.State, e.Message = "disabled", "extensions are turned off on this node (--no-extensions)"
			continue
		}
		if keysErr != nil {
			e.State, e.Message = "failed", "cannot read --extension-keys: "+keysErr.Error()
			continue
		}
		dir, err := a.extensionTree(ctx, e, local)
		var transient errTransient
		switch {
		case errors.As(err, &transient):
			return transient.error
		case err != nil:
			if e.State == "" {
				e.State = "failed"
			}
			e.Message = err.Error()
			a.log.Warn("extension not loaded", "extension", e.ID, "version", e.Version, "err", err)
		default:
			e.Dir, e.State = dir, "loaded"
		}
	}
	return nil
}

func (a *Agent) extensionTree(ctx context.Context, e *configir.Extension, localKeys []string) (string, error) {
	root := a.extensionsDir()
	dir := filepath.Join(root, e.SHA256)
	archivePath := dir + ".ewx"
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	if err := chownToUser(a.cfg.Render.User, root); err != nil {
		return "", err
	}
	var key extension.JWK
	if err := json.Unmarshal([]byte(e.PublicKey), &key); err != nil {
		return "", fmt.Errorf("invalid signing key: %w", err)
	}
	if localKeys != nil && !slices.Contains(localKeys, key.X) {
		return "", fmt.Errorf("the signing key %s is not in --extension-keys", extension.Thumbprint(key.X))
	}
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		if a.channel == nil {
			return "", errTransient{errors.New("extension package unavailable")}
		}
		cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
		res, err := a.channel.Client().GetExtensionPackage(cctx, connect.NewRequest(&nodev1.GetExtensionPackageRequest{Sha256: e.SHA256}))
		cancel()
		if err != nil {
			if code := connect.CodeOf(err); code == connect.CodeNotFound || code == connect.CodeUnimplemented {
				return "", fmt.Errorf("the console does not have the package: %w", err)
			}
			return "", errTransient{fmt.Errorf("fetch extension %s: %w", e.ID, err)}
		}
		archive = res.Msg.GetPackage()
	}
	if len(archive) != e.Size {
		return "", fmt.Errorf("package size %d is not %d", len(archive), e.Size)
	}
	pkg, err := extension.Verify(archive, e.Signature, key, e.Publisher)
	if err != nil {
		return "", err
	}
	if pkg.SHA256 != e.SHA256 || pkg.Manifest.ID != e.ID || pkg.Manifest.Version != e.Version {
		return "", errors.New("the package is not the configured extension")
	}
	if err := compatible(pkg.Manifest); err != nil {
		e.State = "incompatible"
		return "", err
	}
	dicts := make([]configir.ExtensionSharedDict, 0, len(pkg.Manifest.SharedDicts))
	for _, d := range pkg.Manifest.SharedDicts {
		dicts = append(dicts, configir.ExtensionSharedDict{Name: d.Name, SizeKB: d.SizeKB})
	}
	if !slices.Equal(dicts, e.SharedDicts) {
		return "", errors.New("the configured shared dicts differ from the manifest's")
	}
	if err := fsutil.WriteFileAtomic(archivePath, archive, 0o600); err != nil {
		return "", err
	}
	if _, err := os.Stat(filepath.Join(dir, ".verified")); err == nil {
		return dir, nil
	}
	if err := a.unpack(dir, pkg); err != nil {
		return "", fmt.Errorf("unpack: %w", err)
	}
	return dir, nil
}

// compatible checks the manifest's requirements against this node.
func compatible(m *extension.Manifest) error {
	if m.Requires.LuaAPI > extension.LuaAPI {
		return fmt.Errorf("needs Lua API %d, this node has %d", m.Requires.LuaAPI, extension.LuaAPI)
	}
	if m.Requires.Node == "" {
		return nil
	}
	r, err := extension.ParseRange(m.Requires.Node)
	if err != nil {
		return err
	}
	v, err := extension.ParseVersion(version.Version)
	if err != nil {
		return nil // a development build ("dev") loads every package
	}
	if !r.Contains(v) {
		return fmt.Errorf("needs node %s, this is %s", m.Requires.Node, version.Version)
	}
	return nil
}

// unpack writes the package's files into dir (through a temporary
// directory), readable by the nginx workers, and marks it verified.
func (a *Agent) unpack(dir string, pkg *extension.Package) error {
	tmp := dir + ".tmp"
	if err := os.RemoveAll(tmp); err != nil {
		return err
	}
	for _, f := range pkg.Files {
		path := filepath.Join(tmp, filepath.FromSlash(f.Path))
		if !strings.HasPrefix(path, tmp+string(filepath.Separator)) {
			return fmt.Errorf("path escapes the package: %s", f.Path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := fsutil.WriteFileAtomic(path, f.Data, 0o644); err != nil {
			return err
		}
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(tmp, ".verified"), []byte(pkg.SHA256+"\n"), 0o644); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return fsutil.Rename(tmp, dir)
}

// removeStaleExtensions deletes packages and trees neither plan references.
func (a *Agent) removeStaleExtensions(plans ...*configir.Plan) {
	keep := map[string]bool{}
	for _, p := range plans {
		if p == nil {
			continue
		}
		for _, e := range p.Extensions {
			keep[e.SHA256] = true
		}
	}
	entries, err := os.ReadDir(a.extensionsDir())
	if err != nil {
		return
	}
	for _, entry := range entries {
		sha := strings.TrimSuffix(strings.TrimSuffix(entry.Name(), ".ewx"), ".tmp")
		if keep[sha] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(a.extensionsDir(), entry.Name())); err != nil {
			a.log.Warn("cannot remove an unused extension package", "path", entry.Name(), "err", err)
		}
	}
}

// extensionDataPlane is the part of the control API with the extensions'
// load state and fault counters (GET /v1/extensions).
type extensionDataPlane interface {
	Extensions(ctx context.Context) (map[string]dataplane.ExtensionRuntime, error)
}

// extensionReport is the state of each extension of the applied plan.
func (a *Agent) extensionReport(ctx context.Context) []*nodev1.ExtensionStatus {
	a.mu.Lock()
	plan := a.plan
	a.mu.Unlock()
	if plan == nil || len(plan.Extensions) == 0 {
		return nil
	}
	var runtime map[string]dataplane.ExtensionRuntime
	if dp, ok := a.dp.(extensionDataPlane); ok {
		runtime, _ = dp.Extensions(ctx)
	}
	out := make([]*nodev1.ExtensionStatus, 0, len(plan.Extensions))
	for _, e := range plan.Extensions {
		s := &nodev1.ExtensionStatus{Id: e.ID, Version: e.Version, Sha256: e.SHA256, State: e.State, Message: e.Message}
		if r, ok := runtime[e.ID]; ok && r.SHA256 == e.SHA256 {
			s.Faults, s.Trips = r.Faults, r.Trips
			if r.Error != "" {
				s.State, s.Message = "failed", r.Error
			}
		}
		switch {
		case s.State == "loaded" && plan.ExtensionsDisabled:
			s.State, s.Message = "disabled", "kill switch"
		case s.State == "loaded" && !e.Enabled:
			s.State = "disabled"
		}
		if len(s.Message) > 500 {
			s.Message = s.Message[:500]
		}
		out = append(out, s)
	}
	return out
}
