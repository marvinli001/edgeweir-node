package apisecurity

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/lexer"
	"github.com/vektah/gqlparser/v2/parser"
)

const graphqlTokens = 8192

func (s *Settings) graphql(ctx context.Context, req Request) string {
	g := s.GraphQL
	queryParams, code := queryValues(req.Query)
	if code != "" {
		return code
	}
	var operations []any
	switch req.Method {
	case "GET":
		if len(req.Body) > 0 {
			return "graphql-envelope"
		}
		query := queryParams
		op := map[string]any{}
		for _, name := range []string{"query", "operationName"} {
			if v, ok := query[name]; ok && v[0] != "" {
				op[name] = v[0]
			}
		}
		if v, ok := query["variables"]; ok && v[0] != "" {
			variables, err := decodeJSON(ctx, []byte(v[0]), 32, 4096)
			if err != nil {
				return issueCode(err)
			}
			op["variables"] = variables
		}
		operations = []any{op}
	case "POST":
		for _, name := range []string{"query", "variables", "operationName"} {
			if _, ok := queryParams[name]; ok {
				return "graphql-envelope"
			}
		}
		if !jsonMedia(req.Headers) {
			return "graphql-media-type"
		}
		value, err := decodeJSON(ctx, req.Body, 64, 10000)
		if err != nil {
			return issueCode(err)
		}
		if batch, ok := value.([]any); ok {
			operations = batch
		} else {
			operations = []any{value}
		}
	default:
		return "graphql-method"
	}
	if len(operations) == 0 || len(operations) > g.MaxBatch {
		return "graphql-batch"
	}
	fields, aliases, tokens, documentBytes := 0, 0, 0, 0
	for _, op := range operations {
		object, ok := op.(map[string]any)
		if !ok {
			return "graphql-envelope"
		}
		query, ok := object["query"].(string)
		if !ok || strings.TrimSpace(query) == "" {
			return "graphql-query-missing"
		}
		documentBytes += len(query)
		if documentBytes > g.MaxDocumentBytes {
			return "graphql-document-budget"
		}
		name := ""
		if v, ok := object["operationName"]; ok && v != nil {
			var valid bool
			name, valid = v.(string)
			if !valid {
				return "graphql-operation"
			}
		}
		if variables, ok := object["variables"]; ok && variables != nil {
			if _, ok := variables.(map[string]any); !ok {
				return "graphql-variables"
			}
			nodes := 0
			if !variableBudget(variables, 1, &nodes) {
				return "json-budget"
			}
		}
		code := g.document(ctx, query, name, req.Method == "GET", &fields, &aliases, &tokens)
		if code != "" {
			return code
		}
	}
	return ""
}

func variableBudget(v any, depth int, nodes *int) bool {
	*nodes++
	if depth > 32 || *nodes > 4096 {
		return false
	}
	switch x := v.(type) {
	case map[string]any:
		for _, child := range x {
			if !variableBudget(child, depth+1, nodes) {
				return false
			}
		}
	case []any:
		for _, child := range x {
			if !variableBudget(child, depth+1, nodes) {
				return false
			}
		}
	}
	return true
}

// Lexing bounds parser recursion before entering the parser. The token
// positions also distinguish an explicit `name: name` alias in the AST.
func lexicalBudget(ctx context.Context, source *ast.Source, total *int) (map[int]bool, string) {
	if !utf8.ValidString(source.Input) {
		return nil, "graphql-invalid"
	}
	l := lexer.New(source)
	depth := 0
	previous := lexer.Token{}
	aliases := map[int]bool{}
	for {
		if ctx.Err() != nil {
			return nil, "check-deadline"
		}
		t, err := l.ReadToken()
		if err != nil {
			return nil, "graphql-invalid"
		}
		if t.Kind == lexer.EOF {
			break
		}
		*total++
		if *total > graphqlTokens {
			return nil, "graphql-token-budget"
		}
		if t.Kind == lexer.Comment {
			continue
		}
		switch t.Kind {
		case lexer.BraceL, lexer.BracketL, lexer.ParenL:
			depth++
			if depth > 64 {
				return nil, "graphql-parser-depth"
			}
		case lexer.BraceR, lexer.BracketR, lexer.ParenR:
			depth--
		}
		if previous.Kind == lexer.Name && t.Kind == lexer.Colon {
			aliases[previous.Pos.Start] = true
		}
		previous = t
	}
	return aliases, ""
}

func (g GraphQLSettings) document(ctx context.Context, query, name string, get bool, fields, aliasCount, tokens *int) string {
	source := &ast.Source{Input: query}
	aliases, code := lexicalBudget(ctx, source, tokens)
	if code != "" {
		return code
	}
	doc, err := parser.ParseQueryWithTokenLimit(source, graphqlTokens)
	if err != nil {
		return "graphql-invalid"
	}
	if ctx.Err() != nil {
		return "check-deadline"
	}
	fragments := map[string]*ast.FragmentDefinition{}
	for _, f := range doc.Fragments {
		if _, ok := fragments[f.Name]; ok {
			return "graphql-fragment-duplicate"
		}
		fragments[f.Name] = f
	}
	var selected *ast.OperationDefinition
	names := map[string]bool{}
	for _, op := range doc.Operations {
		if names[op.Name] || op.Name == "" && len(doc.Operations) > 1 {
			return "graphql-operation"
		}
		names[op.Name] = true
		if op.Name == name || name == "" && len(doc.Operations) == 1 {
			selected = op
		}
	}
	if selected == nil {
		return "graphql-operation"
	}
	if get && selected.Operation != ast.Query {
		return "graphql-get-mutation"
	}
	visiting, done := map[string]bool{}, map[string]bool{}
	var references func(ast.SelectionSet, int) string
	references = func(set ast.SelectionSet, depth int) string {
		if ctx.Err() != nil {
			return "check-deadline"
		}
		if depth > 64 {
			return "graphql-fragment-budget"
		}
		for _, selection := range set {
			switch node := selection.(type) {
			case *ast.Field:
				if code := references(node.SelectionSet, depth+1); code != "" {
					return code
				}
			case *ast.InlineFragment:
				if code := references(node.SelectionSet, depth+1); code != "" {
					return code
				}
			case *ast.FragmentSpread:
				f := fragments[node.Name]
				if f == nil {
					return "graphql-fragment-unknown"
				}
				if visiting[node.Name] {
					return "graphql-fragment-cycle"
				}
				if !done[node.Name] {
					visiting[node.Name] = true
					if code := references(f.SelectionSet, depth+1); code != "" {
						return code
					}
					delete(visiting, node.Name)
					done[node.Name] = true
				}
			}
		}
		return ""
	}
	for _, f := range doc.Fragments {
		if code := references(f.SelectionSet, 1); code != "" {
			return code
		}
	}
	for _, op := range doc.Operations {
		if code := references(op.SelectionSet, 1); code != "" {
			return code
		}
	}
	visits := 0
	var expand func(ast.SelectionSet, int, int) string
	expand = func(set ast.SelectionSet, depth, hops int) string {
		if ctx.Err() != nil {
			return "check-deadline"
		}
		if hops > 128 {
			return "graphql-fragment-budget"
		}
		for _, selection := range set {
			visits++
			if visits > 10000 {
				return "graphql-expansion-budget"
			}
			switch node := selection.(type) {
			case *ast.Field:
				*fields++
				if *fields > g.MaxFields {
					return "graphql-fields"
				}
				if depth > g.MaxDepth {
					return "graphql-depth"
				}
				if aliases[node.Position.Start] {
					*aliasCount++
					if *aliasCount > g.MaxAliases {
						return "graphql-aliases"
					}
				}
				if !g.Introspection && (node.Name == "__schema" || node.Name == "__type") {
					return "graphql-introspection"
				}
				if code := expand(node.SelectionSet, depth+1, hops+1); code != "" {
					return code
				}
			case *ast.InlineFragment:
				if code := expand(node.SelectionSet, depth, hops+1); code != "" {
					return code
				}
			case *ast.FragmentSpread:
				if code := expand(fragments[node.Name].SelectionSet, depth, hops+1); code != "" {
					return code
				}
			}
		}
		return ""
	}
	// Directives are deliberately counted conservatively, including variable
	// skip/include branches and every occurrence of a fragment.
	return expand(selected.SelectionSet, 1, 1)
}
