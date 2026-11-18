package apisecurity

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func graphqlSettings(t *testing.T) *Settings {
	return settings(t, func(s *Settings) {
		s.GraphQL.Mode = "enforce"
		s.GraphQL.MaxDepth = 3
		s.GraphQL.MaxFields = 8
		s.GraphQL.MaxAliases = 2
		s.GraphQL.MaxBatch = 2
		s.GraphQL.MaxDocumentBytes = 1024
	})
}
func graphqlRequest(value any) Request {
	raw, _ := json.Marshal(value)
	return Request{Method: "POST", Path: "/graphql", RawPath: "/graphql", GraphQLScoped: true, Headers: map[string][]string{"content-type": {"application/json"}}, Body: raw}
}
func TestGraphQLASTAndTransportBoundaries(t *testing.T) {
	s := graphqlSettings(t)
	for _, tc := range []struct{ name, query, code string }{
		{"query", "{ user { id name } }", ""},
		{"fragment", "query A($id: ID!) { user(id:$id) { ...U } } fragment U on User { id name }", ""},
		{"depth", "{ user { parent { parent { id } } } }", "graphql-depth"},
		{"inline depth", "{ user { ... on User { parent { parent { id } } } } }", "graphql-depth"},
		{"fields", "{ a b c d e f g h i }", "graphql-fields"},
		{"aliases", "{ a:one b:one c:one }", "graphql-aliases"},
		{"same name aliases", "{ a:a b:b c:c }", "graphql-aliases"},
		{"introspection alias", "{ disguise:__schema { types { name } } }", "graphql-introspection"},
		{"introspection fragment", "{ user { ...U } } fragment U on User { __type(name:\"User\") { name } }", "graphql-introspection"},
		{"typename allowed", "{ __typename }", ""},
		{"multiple unselected", "query A { a } query B { b }", "graphql-operation"},
		{"anonymous mixed", "{ a } query B { b }", "graphql-operation"},
		{"duplicate operation", "query A { a } query A { b }", "graphql-operation"},
		{"unknown fragment", "{ ...Missing }", "graphql-fragment-unknown"},
		{"unused unknown fragment", "{ ok } fragment U on User { ...Missing }", "graphql-fragment-unknown"},
		{"fragment cycle", "{ ...A } fragment A on User { ...B } fragment B on User { ...A }", "graphql-fragment-cycle"},
		{"unused fragment cycle", "{ ok } fragment A on User { ...A }", "graphql-fragment-cycle"},
		{"fragment duplicate", "{ ...A } fragment A on User { a } fragment A on User { b }", "graphql-fragment-duplicate"},
		{"fragment expansion", "{ ...A ...A ...A } fragment A on User { a b c }", "graphql-fields"},
		{"conservative skip", "{ a:one @skip(if:true) b:one @include(if:false) c:one }", "graphql-aliases"},
		{"parse failure", "{ user( }", "graphql-invalid"},
		{"strings not fields", "{ value(arg:\"__schema { a:one b:one c:one }\") }", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := s.Check(context.Background(), graphqlRequest(map[string]any{"query": tc.query}), time.Now())
			if got := resultCode(r); got != tc.code {
				t.Fatalf("code=%q want %q result=%+v", got, tc.code, r.Log)
			}
			if (r.Status == 403) != (tc.code != "") {
				t.Fatalf("status %d", r.Status)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		value any
		code  string
	}{
		{"optional null", map[string]any{"query": "{ ok }", "variables": nil, "operationName": nil}, ""},
		{"empty operation name", map[string]any{"query": "{ ok }", "operationName": ""}, ""},
		{"variables array", map[string]any{"query": "{ ok }", "variables": []any{}}, "graphql-variables"},
		{"variables string", map[string]any{"query": "{ ok }", "variables": "{}"}, "graphql-variables"},
		{"operation name type", map[string]any{"query": "{ ok }", "operationName": 7}, "graphql-operation"},
		{"operation selected", map[string]any{"query": "query A { a } query B { b }", "operationName": "B"}, ""},
		{"operation unknown", map[string]any{"query": "query A { a }", "operationName": "B"}, "graphql-operation"},
		{"APQ", map[string]any{"extensions": map[string]any{"persistedQuery": map[string]any{"version": 1, "sha256Hash": "abc"}}}, "graphql-query-missing"},
		{"batch", []any{map[string]any{"query": "{ a }"}, map[string]any{"query": "{ b }"}}, ""},
		{"batch fields aggregate", []any{map[string]any{"query": "{ a b c d e }"}, map[string]any{"query": "{ f g h i }"}}, "graphql-fields"},
		{"batch aliases aggregate", []any{map[string]any{"query": "{ a:x b:x }"}, map[string]any{"query": "{ c:x }"}}, "graphql-aliases"},
		{"empty batch", []any{}, "graphql-batch"},
		{"batch count", []any{map[string]any{"query": "{a}"}, map[string]any{"query": "{b}"}, map[string]any{"query": "{c}"}}, "graphql-batch"},
		{"not envelope", 7, "graphql-envelope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := s.Check(context.Background(), graphqlRequest(tc.value), time.Now())
			if resultCode(r) != tc.code {
				t.Fatalf("%+v want %s", r.Log, tc.code)
			}
		})
	}
	for _, tc := range []struct {
		name, code string
		edit       func(*Request)
	}{
		{"GET", "", func(r *Request) {
			r.Method = "GET"
			r.Body = nil
			r.Query = url.Values{"query": {"{ ok }"}, "variables": {""}, "operationName": {""}}.Encode()
		}},
		{"GET mutation", "graphql-get-mutation", func(r *Request) {
			r.Method = "GET"
			r.Body = nil
			r.Query = url.Values{"query": {"mutation { change }"}}.Encode()
		}},
		{"GET mixed body", "graphql-envelope", func(r *Request) { r.Method = "GET"; r.Query = url.Values{"query": {"{ ok }"}}.Encode() }},
		{"POST mixed URL", "graphql-envelope", func(r *Request) { r.Query = url.Values{"query": {"{ dangerous }"}}.Encode() }},
		{"duplicate query", "query-duplicate", func(r *Request) { r.Query = "query=a&query=b" }},
		{"media", "graphql-media-type", func(r *Request) { r.Headers["content-type"] = []string{"application/graphql"} }},
		{"charset", "graphql-media-type", func(r *Request) { r.Headers["content-type"] = []string{"application/json; charset=latin1"} }},
		{"truncated", "body-budget", func(r *Request) { r.BodyTruncated = true }},
		{"duplicate JSON", "json-duplicate-key", func(r *Request) { r.Body = []byte(`{"query":"{a}","query":"{b}"}`) }},
		{"document bytes", "graphql-document-budget", func(r *Request) { r.Body = []byte(`{"query":"` + strings.Repeat(" ", 1024) + `{a}"}`) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := graphqlRequest(map[string]any{"query": "{ok}"})
			tc.edit(&req)
			r := s.Check(context.Background(), req, time.Now())
			if resultCode(r) != tc.code {
				t.Fatalf("%+v want %s", r.Log, tc.code)
			}
		})
	}
}

func TestGraphQLParserAndExpansionBudgets(t *testing.T) {
	s := graphqlSettings(t)
	s.GraphQL.MaxDocumentBytes = 65536
	for _, tc := range []struct{ query, code string }{
		{"{" + strings.Repeat("field ", 8500) + "}", "graphql-token-budget"},
		{strings.Repeat("{field ", 65) + "id" + strings.Repeat("}", 65), "graphql-parser-depth"},
	} {
		r := s.Check(context.Background(), graphqlRequest(map[string]any{"query": tc.query}), time.Now())
		if resultCode(r) != tc.code {
			t.Fatalf("%s want %s", resultCode(r), tc.code)
		}
	}
	variables := map[string]any{"data": make([]any, 4100)}
	r := s.Check(context.Background(), graphqlRequest(map[string]any{"query": "{ok}", "variables": variables}), time.Now())
	if resultCode(r) != "json-budget" {
		t.Fatalf("variables not bounded: %+v", r.Log)
	}
	s.GraphQL.Mode = "observe"
	if r := s.Check(context.Background(), graphqlRequest(map[string]any{"query": "{__schema{types{name}}}"}), time.Now()); r.Status != 0 || resultCode(r) != "graphql-introspection" {
		t.Fatal("observe blocked or lost issue")
	}
}
