package configir

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// FeatureExtensions (proto PROTO_NEXT): node extensions, signed Lua packages
// (docs/reference/extensions.md in the console repository). The agent
// announces it through Options.ExtraFeatures unless it runs with
// --no-extensions.
const FeatureExtensions = "extensions-v1"

// FeatureExtensionsV2: the node runs Lua API 2 packages (extension version
// 1.1), announced with FeatureExtensions.
const FeatureExtensionsV2 = "extensions-v2"

// Extension is an installed extension's active package and the operator's
// settings. The agent fills in Dir, State and Message once it has the
// package (internal/agent/extensions.go).
type Extension struct {
	ID          string                `json:"id"`
	Version     string                `json:"version"`
	Publisher   string                `json:"publisher"`
	SHA256      string                `json:"sha256"`
	Size        int                   `json:"-"`
	Signature   string                `json:"-"`
	PublicKey   string                `json:"-"`
	Enabled     bool                  `json:"enabled"`
	FailureMode string                `json:"failure_mode"`
	Config      json.RawMessage       `json:"config"`
	SharedDicts []ExtensionSharedDict `json:"-"`
	// Dir is the unpacked package (empty while it is not loadable).
	Dir string `json:"-"`
	// State is loaded, failed, incompatible or disabled (see ExtensionStatus).
	State   string `json:"state"`
	Message string `json:"-"`
	// SecretVersion is the console secret's version (0: none, extension
	// version 1.1); the agent fetches the secret when it changes.
	SecretVersion uint32 `json:"-"`
	// Sidecar is the package's sidecar (set by the agent from the verified
	// manifest), DataLimits its data limits.
	Sidecar *ExtensionSidecar `json:"-"`
}

// ExtensionSidecar is what nginx.conf and the supervisor need of a
// package's sidecar.
type ExtensionSidecar struct {
	Binary           string
	Args             []string
	Env              map[string]string
	MemoryMB         int
	TasksMax         int
	CPUPercent       int
	HealthPath       string
	ConnectTimeoutMS int
	TimeoutS         int
	MaxBody          int
}

// ExtensionSharedDict is a lua_shared_dict of an extension.
type ExtensionSharedDict struct {
	Name   string
	SizeKB int
}

// DictName is the nginx name of an extension's shared dict.
func (d ExtensionSharedDict) DictName(id string) string {
	return "ewx_" + hex.EncodeToString([]byte(id)) + "_" + d.Name
}

// SiteExtension turns an extension on for a site.
type SiteExtension struct {
	ID     string          `json:"id"`
	Config json.RawMessage `json:"config"`
	// Data are the site's data items (extension version 1.1); the agent
	// keeps them for the extension's sidecar.
	Data []ExtensionDataItem `json:"-"`
}

// ExtensionDataItem is a per-site data item of an extension.
type ExtensionDataItem struct {
	Name   string
	SHA256 string
	Size   int64
}

var (
	extensionIDRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`)
	extensionDict  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,15}$`)
	extensionField = regexp.MustCompile(`^ext\.[a-z][a-z0-9-]{1,38}[a-z0-9]\.[a-z][a-z0-9_]{0,31}$`)
	extensionData  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	sha256Hex      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidExtensionName reports whether s names an extension's rule field,
// log field or counter ("ext.<id>.<name>").
func ValidExtensionName(s string) bool { return extensionField.MatchString(s) }

// ValidExtensionRuleID reports whether s is the block rule id of an
// extension's deny verdict ("ext:<id>").
func ValidExtensionRuleID(s string) bool {
	id, ok := strings.CutPrefix(s, "ext:")
	return ok && extensionIDRE.MatchString(id)
}

// jsonObject reports whether s is a JSON object (at most 64 KiB).
func jsonObject(s string) (json.RawMessage, bool) {
	if len(s) > 64<<10 {
		return nil, false
	}
	var v map[string]any
	if json.Unmarshal([]byte(s), &v) != nil || v == nil {
		return nil, false
	}
	var buf bytes.Buffer
	if json.Compact(&buf, []byte(s)) != nil {
		return nil, false
	}
	return buf.Bytes(), true
}

// buildExtensions validates NodeConfig.extensions.
func buildExtensions(c *nodev1.NodeConfig) ([]Extension, error) {
	var out []Extension
	seen := map[string]bool{}
	for _, e := range c.GetExtensions() {
		bad := func(what string) error {
			return fmt.Errorf("%w: extension %q: invalid %s", ErrRejected, e.GetId(), what)
		}
		switch {
		case !extensionIDRE.MatchString(e.GetId()) || seen[e.GetId()]:
			return nil, bad("id")
		case !sha256Hex.MatchString(e.GetSha256()) || e.GetSize() == 0 || e.GetSize() > 64<<20:
			return nil, bad("digest")
		case e.GetFailureMode() != "open" && e.GetFailureMode() != "closed":
			return nil, bad("failure mode")
		case len(e.GetSignature()) > 4096 || len(e.GetPublicKey()) > 1024 || e.GetSignature() == "" || e.GetPublicKey() == "":
			return nil, bad("signature")
		case len(e.GetSharedDicts()) > 4:
			return nil, bad("shared dicts")
		}
		seen[e.GetId()] = true
		config, ok := jsonObject(e.GetConfigJson())
		if !ok {
			return nil, bad("configuration")
		}
		ext := Extension{
			ID: e.GetId(), Version: e.GetVersion(), Publisher: e.GetPublisher(), SHA256: e.GetSha256(),
			Size: int(e.GetSize()), Signature: e.GetSignature(), PublicKey: e.GetPublicKey(),
			Enabled: e.GetEnabled(), FailureMode: e.GetFailureMode(), Config: config,
			SecretVersion: e.GetSecretVersion(),
		}
		total := 0
		names := map[string]bool{}
		for _, d := range e.GetSharedDicts() {
			if !extensionDict.MatchString(d.GetName()) || d.GetSizeKb() < 16 || d.GetSizeKb() > 16384 || names[d.GetName()] {
				return nil, bad("shared dict")
			}
			names[d.GetName()] = true
			total += int(d.GetSizeKb())
			ext.SharedDicts = append(ext.SharedDicts, ExtensionSharedDict{Name: d.GetName(), SizeKB: int(d.GetSizeKb())})
		}
		if total > 32768 {
			return nil, bad("shared dicts")
		}
		out = append(out, ext)
	}
	return out, nil
}

// buildSiteExtensions validates a site's extensions against the delivered ones.
func buildSiteExtensions(s *nodev1.Site, exts []Extension) ([]SiteExtension, error) {
	var out []SiteExtension
	for _, e := range s.GetExtensions() {
		if !slices.ContainsFunc(exts, func(x Extension) bool { return x.ID == e.GetId() }) ||
			slices.ContainsFunc(out, func(x SiteExtension) bool { return x.ID == e.GetId() }) {
			return nil, fmt.Errorf("%w: unknown or repeated extension %q", ErrRejected, e.GetId())
		}
		config, ok := jsonObject(e.GetConfigJson())
		if !ok {
			return nil, fmt.Errorf("%w: invalid configuration of extension %q", ErrRejected, e.GetId())
		}
		x := SiteExtension{ID: e.GetId(), Config: config}
		var total uint64
		for _, d := range e.GetData() {
			if !extensionData.MatchString(d.GetName()) || !sha256Hex.MatchString(d.GetSha256()) || d.GetSize() > 24<<20 ||
				slices.ContainsFunc(x.Data, func(y ExtensionDataItem) bool { return y.Name == d.GetName() }) {
				return nil, fmt.Errorf("%w: invalid data item of extension %q", ErrRejected, e.GetId())
			}
			total += d.GetSize()
			x.Data = append(x.Data, ExtensionDataItem{Name: d.GetName(), SHA256: d.GetSha256(), Size: int64(d.GetSize())})
		}
		if len(x.Data) > 32 || total > 256<<20 {
			return nil, fmt.Errorf("%w: too much data for extension %q", ErrRejected, e.GetId())
		}
		out = append(out, x)
	}
	return out, nil
}
