package apisecurity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

const Feature = "api-security-v1"

type Settings struct {
	Version    int             `json:"version"`
	Discovery  Discovery       `json:"discovery"`
	Schema     SchemaSettings  `json:"schema"`
	JWT        JWTSettings     `json:"jwt"`
	GraphQL    GraphQLSettings `json:"graphql"`
	Exceptions []Exception     `json:"exceptions"`
	keys       map[string]verificationKey
}

type Discovery struct {
	Enabled    bool `json:"enabled"`
	SampleRate int  `json:"sampleRate"`
}
type SchemaSettings struct {
	Mode             string        `json:"mode"`
	UnknownEndpoints string        `json:"unknownEndpoints"`
	Endpoints        []Endpoint    `json:"endpoints"`
	Issues           []ImportIssue `json:"issues"`
}
type ImportIssue struct {
	Location string `json:"location"`
	Code     string `json:"code"`
}
type Endpoint struct {
	Method     string      `json:"method"`
	Path       string      `json:"path"`
	Parameters []Parameter `json:"parameters"`
	Body       *Body       `json:"body,omitempty"`
}
type Parameter struct {
	Name     string  `json:"name"`
	In       string  `json:"in"`
	Required bool    `json:"required"`
	Schema   *Schema `json:"schema"`
}
type Body struct {
	Required bool    `json:"required"`
	Schema   *Schema `json:"schema"`
}
type Schema struct {
	Type                 string             `json:"type"`
	Nullable             bool               `json:"nullable,omitempty"`
	Properties           map[string]*Schema `json:"properties,omitempty"`
	Required             []string           `json:"required,omitempty"`
	AdditionalProperties *bool              `json:"additionalProperties,omitempty"`
	Items                *Schema            `json:"items,omitempty"`
	Enum                 []any              `json:"enum,omitempty"`
	MinLength            *int               `json:"minLength,omitempty"`
	MaxLength            *int               `json:"maxLength,omitempty"`
	Minimum              *float64           `json:"minimum,omitempty"`
	Maximum              *float64           `json:"maximum,omitempty"`
	MinItems             *int               `json:"minItems,omitempty"`
	MaxItems             *int               `json:"maxItems,omitempty"`
}
type Scope struct {
	Domains             []string `json:"domains,omitempty"`
	PathPrefixes        []string `json:"pathPrefixes,omitempty"`
	Extensions          []string `json:"extensions,omitempty"`
	ExcludePathPrefixes []string `json:"excludePathPrefixes,omitempty"`
}
type JWTSettings struct {
	Mode                  string   `json:"mode"`
	Scope                 Scope    `json:"scope"`
	Issuer                string   `json:"issuer"`
	Audiences             []string `json:"audiences"`
	Algorithms            []string `json:"algorithms"`
	Keys                  []JWK    `json:"keys"`
	ClockToleranceSeconds int      `json:"clockToleranceSeconds"`
}
type JWK struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Kty string `json:"kty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}
type verificationKey struct {
	alg    string
	public crypto.PublicKey
}
type GraphQLSettings struct {
	Mode             string   `json:"mode"`
	PathPrefixes     []string `json:"pathPrefixes"`
	MaxDepth         int      `json:"maxDepth"`
	MaxFields        int      `json:"maxFields"`
	MaxAliases       int      `json:"maxAliases"`
	MaxBatch         int      `json:"maxBatch"`
	MaxDocumentBytes int      `json:"maxDocumentBytes"`
	Introspection    bool     `json:"introspection"`
}
type Exception struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Check   string `json:"check"`
	Reason  string `json:"reason"`
}

var (
	segmentRE     = regexp.MustCompile(`^[A-Za-z0-9_~.!$&'()+,=:@-]+$`)
	placeholderRE = regexp.MustCompile(`^\{[A-Za-z][A-Za-z0-9_]{0,31}\}$`)
	uuidRE        = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	headerRE      = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
)

func ValidPath(path string) bool {
	if len(path) == 0 || len(path) > 512 || path[0] != '/' || strings.Contains(path, "//") {
		return false
	}
	for _, s := range segments(path) {
		if s == "." || s == ".." || (!segmentRE.MatchString(s) && !placeholderRE.MatchString(s)) {
			return false
		}
	}
	return true
}
func validMethod(m string) bool {
	return slices.Contains([]string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}, m)
}
func mode(m string) bool           { return m == "off" || m == "observe" || m == "enforce" }
func check(c string) bool          { return c == "schema" || c == "jwt" || c == "graphql" }
func chars(s string, max int) bool { return utf8.ValidString(s) && utf8.RuneCountInString(s) <= max }

// Parse preserves the wire document's identity; the plan sends its digest,
// never a re-encoded configuration, to the data plane.
func Parse(raw string) (*Settings, string, error) {
	if raw == "" {
		return nil, "", nil
	}
	if len(raw) > 1048576 {
		return nil, "", fmt.Errorf("API security configuration too large")
	}
	v, err := decodeJSON(context.Background(), []byte(raw), 32, 100000)
	if err != nil {
		return nil, "", err
	}
	if err := configShape(v, reflect.TypeFor[Settings]()); err != nil {
		return nil, "", err
	}
	d := json.NewDecoder(bytes.NewBufferString(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	var out Settings
	if err := d.Decode(&out); err != nil {
		return nil, "", err
	}
	if err := out.validate(); err != nil {
		return nil, "", err
	}
	h := sha256.Sum256([]byte(raw))
	return &out, hex.EncodeToString(h[:]), nil
}

// Match the case-sensitive TS object shape, including required fields and
// non-null arrays. encoding/json alone accepts missing keys and case aliases.
func configShape(v any, t reflect.Type) error {
	if t.Kind() == reflect.Interface {
		return nil
	}
	if v == nil {
		return fmt.Errorf("null API security setting")
	}
	if t.Kind() == reflect.Pointer {
		return configShape(v, t.Elem())
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("object required")
		}
		fields := map[string]reflect.StructField{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := f.Tag.Get("json")
			if tag == "" || tag == "-" {
				continue
			}
			name := strings.Split(tag, ",")[0]
			fields[name] = f
			if !strings.Contains(tag, ",omitempty") {
				if _, ok := m[name]; !ok {
					return fmt.Errorf("missing API security setting %s", name)
				}
			}
		}
		for k, child := range m {
			f, ok := fields[k]
			if !ok {
				return fmt.Errorf("unknown API security setting %s", k)
			}
			if err := configShape(child, f.Type); err != nil {
				return fmt.Errorf("%s: %w", k, err)
			}
		}
	case reflect.Slice:
		a, ok := v.([]any)
		if !ok {
			return fmt.Errorf("array required")
		}
		for _, child := range a {
			if err := configShape(child, t.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("object required")
		}
		for _, child := range m {
			if err := configShape(child, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Settings) validate() error {
	bad := func() error { return fmt.Errorf("invalid API security setting") }
	if s.Version != 1 || !mode(s.Schema.Mode) || !mode(s.JWT.Mode) || !mode(s.GraphQL.Mode) || s.Discovery.SampleRate < 1 || s.Discovery.SampleRate > 10000 {
		return bad()
	}
	if !slices.Contains([]string{"allow", "block"}, s.Schema.UnknownEndpoints) || len(s.Schema.Endpoints) > 200 || len(s.Schema.Issues) > 200 || (s.Schema.Mode == "enforce" && len(s.Schema.Issues) > 0) {
		return bad()
	}
	for _, i := range s.Schema.Issues {
		if !chars(i.Location, 1024) || !chars(i.Code, 80) {
			return bad()
		}
	}
	nodes := 0
	for i, e := range s.Schema.Endpoints {
		if !validMethod(e.Method) || !ValidPath(e.Path) || len(e.Parameters) > 64 {
			return bad()
		}
		for j := 0; j < i; j++ {
			if endpointsAmbiguous(e, s.Schema.Endpoints[j]) {
				return fmt.Errorf("ambiguous API endpoint templates")
			}
		}
		seen := map[string]bool{}
		pathParams := map[string]bool{}
		for _, p := range segments(e.Path) {
			if placeholderRE.MatchString(p) {
				name := p[1 : len(p)-1]
				if pathParams[name] {
					return bad()
				}
				pathParams[name] = true
			}
		}
		for _, p := range e.Parameters {
			name := p.Name
			if p.In == "header" {
				name = strings.ToLower(name)
			}
			if len(p.Name) == 0 || !chars(p.Name, 128) || !slices.Contains([]string{"path", "query", "header"}, p.In) || seen[p.In+":"+name] {
				return bad()
			}
			seen[p.In+":"+name] = true
			if p.In == "header" && !headerRE.MatchString(p.Name) {
				return bad()
			}
			if p.In == "path" && (!p.Required || !pathParams[p.Name]) {
				return bad()
			}
			if err := validSchema(p.Schema, 1, &nodes); err != nil {
				return err
			}
			if p.Schema.Nullable || p.Schema.Type == "object" || p.Schema.Type == "array" || p.Schema.Type == "null" {
				return fmt.Errorf("unsupported parameter serialization")
			}
		}
		for name := range pathParams {
			if !seen["path:"+name] {
				return bad()
			}
		}
		if e.Body != nil {
			if err := validSchema(e.Body.Schema, 1, &nodes); err != nil {
				return err
			}
		}
	}
	j := s.JWT
	if !chars(j.Issuer, 512) || len(j.Audiences) > 16 || len(j.Algorithms) < 1 || len(j.Algorithms) > 3 || len(j.Keys) > 8 || j.ClockToleranceSeconds < 0 || j.ClockToleranceSeconds > 120 {
		return bad()
	}
	if j.Mode != "off" && (j.Issuer == "" || len(j.Audiences) == 0 || len(j.Keys) == 0) {
		return bad()
	}
	for _, a := range j.Audiences {
		if a == "" || !chars(a, 256) {
			return bad()
		}
	}
	algs := map[string]bool{}
	for _, a := range j.Algorithms {
		if !slices.Contains([]string{"RS256", "ES256", "EdDSA"}, a) || algs[a] {
			return bad()
		}
		algs[a] = true
	}
	s.keys = map[string]verificationKey{}
	for _, k := range j.Keys {
		if k.Kid == "" || !chars(k.Kid, 128) || !algs[k.Alg] {
			return bad()
		}
		if _, ok := s.keys[k.Kid]; ok {
			return fmt.Errorf("duplicate JWK kid")
		}
		key, err := publicKey(k)
		if err != nil {
			return err
		}
		s.keys[k.Kid] = verificationKey{alg: k.Alg, public: key}
	}
	g := s.GraphQL
	if len(g.PathPrefixes) < 1 || len(g.PathPrefixes) > 16 || g.MaxDepth < 1 || g.MaxDepth > 30 || g.MaxFields < 1 || g.MaxFields > 1000 || g.MaxAliases < 0 || g.MaxAliases > 200 || g.MaxBatch < 1 || g.MaxBatch > 20 || g.MaxDocumentBytes < 256 || g.MaxDocumentBytes > 65536 {
		return bad()
	}
	for _, p := range g.PathPrefixes {
		if !ValidPath(p) {
			return bad()
		}
	}
	if len(s.Exceptions) > 100 {
		return bad()
	}
	ids := map[string]bool{}
	for _, e := range s.Exceptions {
		if !uuidRE.MatchString(e.ID) || ids[e.ID] || !check(e.Check) || !ValidPath(e.Path) || (e.Method != "*" && !validMethod(e.Method)) || strings.TrimSpace(e.Reason) == "" || !chars(e.Reason, 256) {
			return bad()
		}
		ids[e.ID] = true
	}
	return nil
}

func validSchema(s *Schema, depth int, nodes *int) error {
	*nodes++
	bad := func() error { return fmt.Errorf("invalid or unsupported API schema") }
	if s == nil || depth > 8 || *nodes > 2000 || !slices.Contains([]string{"string", "number", "integer", "boolean", "object", "array", "null"}, s.Type) {
		return bad()
	}
	if len(s.Required) > 128 || len(s.Enum) > 100 {
		return bad()
	}
	if (s.Properties != nil || s.Required != nil || s.AdditionalProperties != nil) && s.Type != "object" {
		return bad()
	}
	if (s.Items != nil || s.MinItems != nil || s.MaxItems != nil) && s.Type != "array" {
		return bad()
	}
	if s.Type == "array" && s.Items == nil {
		return bad()
	}
	if (s.MinLength != nil || s.MaxLength != nil) && s.Type != "string" {
		return bad()
	}
	if (s.Minimum != nil || s.Maximum != nil) && s.Type != "number" && s.Type != "integer" {
		return bad()
	}
	for _, bound := range []*int{s.MinLength, s.MaxLength, s.MinItems, s.MaxItems} {
		if bound != nil && (*bound < 0 || *bound > 131072) {
			return bad()
		}
	}
	for _, bound := range []*int{s.MinItems, s.MaxItems} {
		if bound != nil && *bound > 10000 {
			return bad()
		}
	}
	if s.MinLength != nil && s.MaxLength != nil && *s.MinLength > *s.MaxLength || s.MinItems != nil && s.MaxItems != nil && *s.MinItems > *s.MaxItems || s.Minimum != nil && s.Maximum != nil && *s.Minimum > *s.Maximum {
		return bad()
	}
	for _, n := range []*float64{s.Minimum, s.Maximum} {
		if n != nil && (math.IsNaN(*n) || math.IsInf(*n, 0)) {
			return bad()
		}
	}
	for k, child := range s.Properties {
		if !chars(k, 128) {
			return bad()
		}
		if err := validSchema(child, depth+1, nodes); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, k := range s.Required {
		if !chars(k, 128) || seen[k] {
			return bad()
		}
		seen[k] = true
	}
	if s.Items != nil {
		if err := validSchema(s.Items, depth+1, nodes); err != nil {
			return err
		}
	}
	for _, v := range s.Enum {
		switch x := v.(type) {
		case nil, bool:
		case string:
			if !chars(x, 1024) {
				return bad()
			}
		case json.Number:
			if _, err := x.Float64(); err != nil {
				return bad()
			}
		default:
			return bad()
		}
	}
	return nil
}
