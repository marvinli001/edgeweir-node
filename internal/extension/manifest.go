// Package extension reads, verifies, packs and signs node extension packages
// (format edgeweir-node-extension-v1). The console checks the same rules
// before it installs a package (apps/console/src/server/lib/extension-package.ts
// and packages/contract/src/extensions.ts); the node repeats them before it
// unpacks anything, so that a package never runs on the console's word alone.
package extension

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Format is the only package format this node reads.
const Format = "edgeweir-node-extension-v1"

// LuaAPI is the Lua API version the node provides.
const LuaAPI = 1

// Limits of a package (docs/reference/extensions.md).
const (
	MaxArchiveBytes  = 4 << 20
	MaxUnpackedBytes = 16 << 20
	MaxEntries       = 512
	MaxFileBytes     = 4 << 20
	MaxManifestBytes = 64 << 10
	MaxPathBytes     = 200
)

var (
	idRE        = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`)
	publisherRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`)
	semverRE    = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?$`)
	nameRE      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	shortNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,15}$`)
	endpointRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

var reservedIDs = []string{"edgeweir", "core", "challenge", "session", "health", "ext", "settings", "verify"}

// Hooks and capabilities of Lua API 1.
var (
	Hooks        = []string{"init", "access", "access_late", "header_filter", "body_filter", "log", "endpoint"}
	Capabilities = []string{"verdicts", "request_headers", "request_body", "response_headers", "html_inject", "body_rewrite", "http_client", "timers"}
	methods      = []string{"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"}
	fieldTypes   = []string{"string", "number", "boolean"}
)

// Manifest is manifest.json. Config schemas stay raw: the console validates
// them; the node only passes configuration through.
type Manifest struct {
	Format       string            `json:"format"`
	ID           string            `json:"id"`
	Version      string            `json:"version"`
	Publisher    string            `json:"publisher"`
	Name         map[string]string `json:"name"`
	Description  map[string]string `json:"description,omitempty"`
	License      string            `json:"license,omitempty"`
	Homepage     string            `json:"homepage,omitempty"`
	Requires     Requires          `json:"requires"`
	Hooks        []string          `json:"hooks"`
	Capabilities []string          `json:"capabilities,omitempty"`
	Config       json.RawMessage   `json:"config,omitempty"`
	Fields       []Field           `json:"fields,omitempty"`
	LogFields    []string          `json:"log_fields,omitempty"`
	Counters     []string          `json:"counters,omitempty"`
	Endpoints    []Endpoint        `json:"endpoints,omitempty"`
	SharedDicts  []SharedDict      `json:"shared_dicts,omitempty"`
}

// Requires names the Lua API and, optionally, a node version range.
type Requires struct {
	LuaAPI int    `json:"lua_api"`
	Node   string `json:"node,omitempty"`
}

// Field is a rule field ext.<id>.<name>.
type Field struct {
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	Description json.RawMessage `json:"description,omitempty"`
}

// Endpoint is served at /.edgeweir/ext/<id>/<path>.
type Endpoint struct {
	Path    string   `json:"path"`
	Methods []string `json:"methods"`
	MaxBody *int     `json:"max_body,omitempty"`
}

// SharedDict is a lua_shared_dict of the extension.
type SharedDict struct {
	Name   string `json:"name"`
	SizeKB int    `json:"size_kb"`
}

// ParseManifest decodes and validates manifest.json strictly (unknown
// members are errors).
func ParseManifest(data []byte) (*Manifest, error) {
	if len(data) > MaxManifestBytes {
		return nil, errors.New("manifest larger than 64 KiB")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if dec.More() {
		return nil, errors.New("manifest: trailing data")
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	return &m, nil
}

func unique[T comparable](list []T) bool {
	seen := make(map[T]bool, len(list))
	for _, v := range list {
		if seen[v] {
			return false
		}
		seen[v] = true
	}
	return true
}

func (m *Manifest) validate() error {
	switch {
	case m.Format != Format:
		return fmt.Errorf("format %q is not %s", m.Format, Format)
	case !idRE.MatchString(m.ID) || slices.Contains(reservedIDs, m.ID):
		return fmt.Errorf("invalid id %q", m.ID)
	case !semverRE.MatchString(m.Version):
		return fmt.Errorf("invalid version %q", m.Version)
	case !publisherRE.MatchString(m.Publisher):
		return fmt.Errorf("invalid publisher %q", m.Publisher)
	case m.Name["en"] == "":
		return errors.New("name.en is required")
	case m.Requires.LuaAPI < 1:
		return errors.New("requires.lua_api is required")
	case len(m.Hooks) == 0 || !unique(m.Hooks):
		return errors.New("hooks must be a non-empty set")
	case !unique(m.Capabilities):
		return errors.New("duplicate capability")
	case len(m.Fields) > 16 || len(m.LogFields) > 8 || len(m.Counters) > 8 || len(m.Endpoints) > 8 || len(m.SharedDicts) > 4:
		return errors.New("too many fields, log fields, counters, endpoints or shared dicts")
	}
	for k, v := range m.Name {
		if (k != "en" && k != "zh-CN") || len([]rune(v)) > 64 || v == "" {
			return fmt.Errorf("invalid name.%s", k)
		}
	}
	if m.Requires.Node != "" {
		if _, err := ParseRange(m.Requires.Node); err != nil {
			return fmt.Errorf("requires.node: %w", err)
		}
	}
	for _, h := range m.Hooks {
		if !slices.Contains(Hooks, h) {
			return fmt.Errorf("unknown hook %q", h)
		}
	}
	for _, c := range m.Capabilities {
		if !slices.Contains(Capabilities, c) {
			return fmt.Errorf("unknown capability %q", c)
		}
	}
	if slices.Contains(m.Hooks, "body_filter") && !m.Has("body_rewrite") {
		return errors.New("body_filter needs body_rewrite")
	}
	if slices.Contains(m.Hooks, "endpoint") != (len(m.Endpoints) > 0) {
		return errors.New("endpoint hook and endpoints go together")
	}
	names := map[string]bool{}
	for _, f := range m.Fields {
		if !nameRE.MatchString(f.Name) || !slices.Contains(fieldTypes, f.Type) || names[f.Name] {
			return fmt.Errorf("invalid field %q", f.Name)
		}
		names[f.Name] = true
	}
	if !unique(m.LogFields) || !unique(m.Counters) || slices.Contains(m.Counters, "faults") {
		return errors.New("duplicate or reserved log field or counter")
	}
	for _, n := range append(slices.Clone(m.LogFields), m.Counters...) {
		if !nameRE.MatchString(n) {
			return fmt.Errorf("invalid name %q", n)
		}
	}
	paths := map[string]bool{}
	for _, e := range m.Endpoints {
		if !endpointRE.MatchString(e.Path) || e.Path == "assets" || paths[e.Path] || len(e.Methods) == 0 || !unique(e.Methods) {
			return fmt.Errorf("invalid endpoint %q", e.Path)
		}
		for _, method := range e.Methods {
			if !slices.Contains(methods, method) {
				return fmt.Errorf("invalid endpoint method %q", method)
			}
		}
		if e.MaxBody != nil && (*e.MaxBody < 0 || *e.MaxBody > 65536) {
			return fmt.Errorf("invalid max_body of %q", e.Path)
		}
		paths[e.Path] = true
	}
	total := 0
	dicts := map[string]bool{}
	for _, d := range m.SharedDicts {
		if !shortNameRE.MatchString(d.Name) || d.SizeKB < 16 || d.SizeKB > 16384 || dicts[d.Name] {
			return fmt.Errorf("invalid shared dict %q", d.Name)
		}
		dicts[d.Name] = true
		total += d.SizeKB
	}
	if total > 32768 {
		return errors.New("shared dicts larger than 32 MiB")
	}
	return nil
}

// Has reports whether the manifest declares a capability.
func (m *Manifest) Has(capability string) bool { return slices.Contains(m.Capabilities, capability) }

// Version is a parsed semantic version.
type Version struct {
	Major, Minor, Patch int
	Pre                 []string
}

// ParseVersion parses a semantic version ("v" prefix allowed).
func ParseVersion(s string) (Version, error) {
	m := semverRE.FindStringSubmatch(strings.TrimPrefix(s, "v"))
	if m == nil {
		return Version{}, fmt.Errorf("invalid version %q", s)
	}
	v := Version{}
	v.Major, _ = strconv.Atoi(m[1])
	v.Minor, _ = strconv.Atoi(m[2])
	v.Patch, _ = strconv.Atoi(m[3])
	if m[4] != "" {
		v.Pre = strings.Split(m[4], ".")
	}
	return v, nil
}

// Compare orders versions by Semantic Versioning 2.0.0 precedence.
func Compare(a, b Version) int {
	for _, d := range []int{a.Major - b.Major, a.Minor - b.Minor, a.Patch - b.Patch} {
		if d != 0 {
			return d
		}
	}
	if len(a.Pre) == 0 || len(b.Pre) == 0 {
		return len(b.Pre) - len(a.Pre)
	}
	for i := 0; i < min(len(a.Pre), len(b.Pre)); i++ {
		x, y := a.Pre[i], b.Pre[i]
		if x == y {
			continue
		}
		xn, xerr := strconv.Atoi(x)
		yn, yerr := strconv.Atoi(y)
		switch {
		case xerr == nil && yerr == nil:
			return xn - yn
		case xerr == nil:
			return -1
		case yerr == nil:
			return 1
		}
		return strings.Compare(x, y)
	}
	return len(a.Pre) - len(b.Pre)
}

type comparator struct {
	op string
	v  Version
}

// Range is a set of comparators that all have to hold.
type Range []comparator

var comparatorRE = regexp.MustCompile(`^(>=|<=|>|<|=)?(\S+)$`)

// ParseRange parses space-separated comparators (">=1.7.0 <2.0.0").
func ParseRange(s string) (Range, error) {
	parts := strings.Fields(s)
	if len(parts) == 0 || len(parts) > 4 {
		return nil, fmt.Errorf("invalid range %q", s)
	}
	r := Range{}
	for _, p := range parts {
		m := comparatorRE.FindStringSubmatch(p)
		if m == nil {
			return nil, fmt.Errorf("invalid range %q", s)
		}
		v, err := ParseVersion(m[2])
		if err != nil || strings.HasPrefix(m[2], "v") {
			return nil, fmt.Errorf("invalid range %q", s)
		}
		op := m[1]
		if op == "" {
			op = "="
		}
		r = append(r, comparator{op, v})
	}
	return r, nil
}

// Contains reports whether v satisfies every comparator.
func (r Range) Contains(v Version) bool {
	for _, c := range r {
		d := Compare(v, c.v)
		ok := map[string]bool{">=": d >= 0, "<=": d <= 0, ">": d > 0, "<": d < 0, "=": d == 0}[c.op]
		if !ok {
			return false
		}
	}
	return true
}
