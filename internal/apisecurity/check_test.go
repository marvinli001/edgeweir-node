package apisecurity

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

const defaultsJSON = `{"version":1,"discovery":{"enabled":false,"sampleRate":1000},"schema":{"mode":"off","unknownEndpoints":"allow","endpoints":[],"issues":[]},"jwt":{"mode":"off","scope":{"domains":[],"pathPrefixes":[],"extensions":[],"excludePathPrefixes":[]},"issuer":"","audiences":[],"algorithms":["RS256"],"keys":[],"clockToleranceSeconds":30},"graphql":{"mode":"off","pathPrefixes":["/graphql"],"maxDepth":10,"maxFields":200,"maxAliases":30,"maxBatch":5,"maxDocumentBytes":65536,"introspection":false},"exceptions":[]}`

func settings(t *testing.T, edit func(*Settings)) *Settings {
	t.Helper()
	s, _, err := Parse(defaultsJSON)
	if err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(s)
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	s, _, err = Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func integer(v int) *int        { return &v }
func number(v float64) *float64 { return &v }
func boolean(v bool) *bool      { return &v }
func schemaSettings(t *testing.T) *Settings {
	return settings(t, func(s *Settings) {
		s.Schema.Mode = "enforce"
		s.Schema.Endpoints = []Endpoint{{Method: "POST", Path: "/api/items/{id}", Parameters: []Parameter{
			{Name: "id", In: "path", Required: true, Schema: &Schema{Type: "integer", Minimum: number(1)}},
			{Name: "count", In: "query", Required: true, Schema: &Schema{Type: "integer", Maximum: number(10)}},
			{Name: "x-client", In: "header", Required: true, Schema: &Schema{Type: "string", Enum: []any{"web", "mobile"}}},
		}, Body: &Body{Required: true, Schema: &Schema{Type: "object", Properties: map[string]*Schema{"name": {Type: "string", MinLength: integer(1), MaxLength: integer(8)}, "items": {Type: "array", Items: &Schema{Type: "integer"}, MaxItems: integer(2)}}, Required: []string{"name"}, AdditionalProperties: boolean(false)}}}}
	})
}
func validRequest() Request {
	return Request{Method: "POST", Path: "/api/items/1", RawPath: "/api/items/1", Query: "count=1", Headers: map[string][]string{"content-type": {"application/json"}, "x-client": {"web"}}, Body: []byte(`{"name":"valid"}`)}
}
func resultCode(r Result) string {
	if r.Log != nil && len(r.Log.Issues) > 0 {
		return r.Log.Issues[0].Code
	}
	return ""
}

func TestSchemaSecurityBoundaries(t *testing.T) {
	s := schemaSettings(t)
	for _, tc := range []struct {
		name, code string
		edit       func(*Request)
	}{
		{"valid", "", func(r *Request) {}},
		{"path type", "parameter-type", func(r *Request) { r.Path = "/api/items/not-a-number"; r.RawPath = r.Path }},
		{"required query", "parameter-required", func(r *Request) { r.Query = "" }},
		{"query range", "schema-range", func(r *Request) { r.Query = "count=99" }},
		{"duplicate query", "query-duplicate", func(r *Request) { r.Query = "count=1&count=2" }},
		{"decoded duplicate query", "query-duplicate", func(r *Request) { r.Query = "count=1&%63ount=2" }},
		{"query malformed", "query-invalid", func(r *Request) { r.Query = "count=%zz" }},
		{"query budget", "query-budget", func(r *Request) { r.Query = strings.Repeat("a=1&", 256) }},
		{"duplicate header", "header-duplicate", func(r *Request) { r.Headers["x-client"] = []string{"web", "mobile"} }},
		{"case duplicate header", "header-duplicate", func(r *Request) { r.Headers["X-Client"] = []string{"mobile"} }},
		{"header budget", "headers-budget", func(r *Request) { r.HeadersTruncated = true }},
		{"header missing", "parameter-required", func(r *Request) { delete(r.Headers, "x-client") }},
		{"duplicate json", "json-duplicate-key", func(r *Request) { r.Body = []byte(`{"name":"one","name":"two"}`) }},
		{"escaped duplicate json", "json-duplicate-key", func(r *Request) { r.Body = []byte(`{"name":"one","na\u006de":"two"}`) }},
		{"nested duplicate json", "json-duplicate-key", func(r *Request) { r.Body = []byte(`{"name":"ok","items":[{"x":1,"x":2}]}`) }},
		{"body required", "body-required", func(r *Request) { r.Body = nil }},
		{"body type", "schema-type", func(r *Request) { r.Body = []byte(`{"name":7}`) }},
		{"body length", "schema-length", func(r *Request) { r.Body = []byte(`{"name":"too long name"}`) }},
		{"body unknown property", "schema-additional", func(r *Request) { r.Body = []byte(`{"name":"ok","password":"secret"}`) }},
		{"body items", "schema-items", func(r *Request) { r.Body = []byte(`{"name":"ok","items":[1,2,3]}`) }},
		{"body parse", "json-invalid", func(r *Request) { r.Body = []byte(`{"name":`) }},
		{"invalid utf8", "json-invalid", func(r *Request) { r.Body = []byte{'"', 255, '"'} }},
		{"unpaired surrogate", "json-invalid", func(r *Request) { r.Body = []byte(`{"name":"\ud800"}`) }},
		{"low surrogate", "json-invalid", func(r *Request) { r.Body = []byte(`{"name":"\udfff"}`) }},
		{"paired surrogate", "", func(r *Request) { r.Body = []byte(`{"name":"\ud83d\ude00"}`) }},
		{"escaped unicode text", "", func(r *Request) { r.Body = []byte(`{"name":"\\ud800"}`) }},
		{"invalid query unicode", "query-invalid", func(r *Request) { r.Query = "count=1&name=%FF" }},
		{"body media", "body-media-type", func(r *Request) { r.Headers["content-type"] = []string{"text/plain"} }},
		{"unsupported json media", "body-media-type", func(r *Request) { r.Headers["content-type"] = []string{"application/problem+json"} }},
		{"unsupported charset", "body-media-type", func(r *Request) { r.Headers["content-type"] = []string{"application/json; charset=iso-8859-1"} }},
		{"utf8 charset", "", func(r *Request) { r.Headers["content-type"] = []string{"application/json; charset=UTF-8"} }},
		{"body truncated", "body-budget", func(r *Request) { r.BodyTruncated = true }},
		{"body bytes", "body-budget", func(r *Request) { r.Body = []byte(strings.Repeat("x", MaxBodyBytes+1)) }},
		{"json depth", "json-budget", func(r *Request) { r.Body = []byte(strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65)) }},
		{"json nodes", "json-budget", func(r *Request) { r.Body = []byte("[" + strings.Repeat("0,", 10000) + "0]") }},
		{"encoded slash", "path-ambiguous", func(r *Request) { r.RawPath = "/api%2fitems/1" }},
		{"semicolon", "path-ambiguous", func(r *Request) { r.RawPath = "/api;token/items/1" }},
		{"encoded semicolon", "path-ambiguous", func(r *Request) { r.RawPath = "/api%3btoken/items/1" }},
		{"double slash", "path-ambiguous", func(r *Request) { r.RawPath = "/api//items/1" }},
		{"encoded percent", "path-ambiguous", func(r *Request) { r.RawPath = "/api%252fitems/1" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := validRequest()
			tc.edit(&req)
			r := s.Check(context.Background(), req, time.Now())
			if got := resultCode(r); got != tc.code {
				t.Fatalf("code=%q want %q result=%+v", got, tc.code, r)
			}
			if (r.Status == 403) != (tc.code != "") {
				t.Fatalf("status=%d", r.Status)
			}
		})
	}
}

func TestUnknownEndpointsObserveAndExceptionIsolation(t *testing.T) {
	s := schemaSettings(t)
	req := validRequest()
	req.Path, req.RawPath = "/upload", "/upload"
	req.BodyTruncated = true
	if r := s.Check(context.Background(), req, time.Now()); r.Status != 0 || r.Log != nil {
		t.Fatalf("unknown allow: %+v", r)
	}
	s.Schema.UnknownEndpoints = "block"
	if r := s.Check(context.Background(), req, time.Now()); resultCode(r) != "endpoint-unknown" || r.Status != 403 {
		t.Fatalf("unknown block: %+v", r)
	}
	req = validRequest()
	req.Query = "count=100"
	s.Schema.Mode = "observe"
	if r := s.Check(context.Background(), req, time.Now()); r.Status != 0 || resultCode(r) != "schema-range" || r.Log.Issues[0].Mode != "observe" {
		t.Fatalf("observe: %+v", r)
	}
	s.Schema.Mode = "enforce"
	s.Exceptions = []Exception{{ID: "12345678-1234-4234-8234-123456789abc", Enabled: true, Method: "POST", Path: "/api/items/{id}", Check: "schema", Reason: "compatibility"}}
	if r := s.Check(context.Background(), req, time.Now()); r.Status != 0 || len(r.Log.ExceptionIDs) != 1 {
		t.Fatalf("exception: %+v", r)
	}
	req.RawPath = "/api%2fitems/1"
	if r := s.Check(context.Background(), req, time.Now()); r.Status != 403 || len(r.Log.ExceptionIDs) != 0 {
		t.Fatalf("ambiguous path exempt: %+v", r)
	}
	req = validRequest()
	req.JWTScoped = true
	s.JWT.Mode = "enforce"
	if r := s.Check(context.Background(), req, time.Now()); r.Status != 403 || resultCode(r) != "jwt-authorization" {
		t.Fatalf("schema exception exempted JWT: %+v", r)
	}
}

func TestEndpointPriorityAndTemplateAmbiguity(t *testing.T) {
	s := schemaSettings(t)
	s.Schema.Endpoints = append(s.Schema.Endpoints, Endpoint{Method: "POST", Path: "/api/items/admin", Parameters: []Parameter{}, Body: &Body{Required: true, Schema: &Schema{Type: "string"}}})
	req := validRequest()
	req.Path, req.RawPath = "/api/items/admin", "/api/items/admin"
	req.Body = []byte(`"ok"`)
	if r := s.Check(context.Background(), req, time.Now()); r.Status != 0 {
		t.Fatalf("static did not win: %+v", r)
	}
	s.Exceptions = []Exception{{ID: "12345678-1234-4234-8234-123456789abc", Enabled: true, Method: "POST", Path: "/api/items/{id}", Check: "schema", Reason: "compatibility"}}
	req.Body = []byte(`1`)
	if r := s.Check(context.Background(), req, time.Now()); r.Status != 403 {
		t.Fatal("broad schema exception exempted a different endpoint template")
	}
	s.Schema.Endpoints = []Endpoint{{Method: "GET", Path: "/api/{user}/me", Parameters: []Parameter{}}, {Method: "GET", Path: "/api/users/{id}", Parameters: []Parameter{}}}
	raw, _ := json.Marshal(s)
	if _, _, err := Parse(string(raw)); err == nil {
		t.Fatal("accepted equal-priority overlapping templates")
	}
	req = Request{Method: "GET", Path: "/api/users/me", RawPath: "/api/users/me"}
	if r := s.Check(context.Background(), req, time.Now()); resultCode(r) != "path-ambiguous" {
		t.Fatalf("runtime ambiguity: %+v", r)
	}
}

func TestSchemaExactNumbersNullAndArrayConstraints(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		schema    *Schema
		raw, want string
	}{
		{&Schema{Type: "integer"}, "1e2", ""},
		{&Schema{Type: "number", Minimum: number(0.1), Maximum: number(0.1)}, "0.1", ""},
		{&Schema{Type: "number", Minimum: number(0.3), Maximum: number(0.3)}, "3e-1", ""},
		{&Schema{Type: "number", Minimum: number(0.1)}, "0.09999999999999999", "schema-range"},
		{&Schema{Type: "number", Maximum: number(0.3)}, "0.30000000000000001", "schema-range"},
		{&Schema{Type: "number", Minimum: number(5e-324)}, "5e-324", ""},
		{&Schema{Type: "integer"}, "1.1", "schema-type"},
		{&Schema{Type: "integer", Maximum: number(9007199254740992)}, "9007199254740993", "schema-range"},
		{&Schema{Type: "integer"}, "1e" + strings.Repeat("9", 129), "number-budget"},
		{&Schema{Type: "number"}, "1e1000000000", "number-budget"},
		{&Schema{Type: "number"}, "1e-1000000000", "number-budget"},
		{&Schema{Type: "string", Nullable: true}, "null", ""},
		{&Schema{Type: "string", Nullable: true, Enum: []any{"x"}}, "null", "schema-enum"},
		{&Schema{Type: "string", Enum: []any{}}, `"x"`, "schema-enum"},
		{&Schema{Type: "string", MinLength: integer(2), MaxLength: integer(2)}, `"😀😀"`, ""},
	} {
		v, err := decodeJSON(ctx, []byte(tc.raw), 64, 10000)
		if err != nil {
			t.Fatal(err)
		}
		if got := validateValue(ctx, tc.schema, v); got != tc.want {
			t.Errorf("%s got %q want %q", tc.raw, got, tc.want)
		}
	}
}

func TestDeadlineAndDiscoveryDoNotExposeRequestSegments(t *testing.T) {
	s := schemaSettings(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if r := s.Check(ctx, validRequest(), time.Now()); r.Status != 403 || resultCode(r) != "check-deadline" {
		t.Fatalf("deadline: %+v", r)
	}
	s.Schema.Mode = "observe"
	if r := s.Check(ctx, validRequest(), time.Now()); r.Status != 0 || resultCode(r) != "check-deadline" {
		t.Fatalf("observe deadline: %+v", r)
	}
	for path, want := range map[string]string{"/api/users/42": "/api/users/{segment3}", "/random-secret-Slug/eyJhbGciOiJub25lIn0": "/{segment1}/{segment2}", "/Users/alice@example.com": "/{segment1}/{segment2}", "/api//users/x/": "/api/users/{segment3}/", "/": "/"} {
		if got := Discover(path); got != want {
			t.Errorf("Discover(%q)=%q want %q", path, got, want)
		}
	}
	if got := Discover("/" + strings.Repeat("api/", 21)); got != "/{segment1}" {
		t.Fatal(got)
	}
}
