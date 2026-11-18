package apisecurity

import (
	"context"
	"encoding/json"
	"math/big"
	"mime"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

func segments(path string) []string {
	if path == "/" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/"), "/")
}

func staticSegments(path string) int {
	n := 0
	for _, p := range segments(path) {
		if !placeholderRE.MatchString(p) {
			n++
		}
	}
	return n
}

func endpointsAmbiguous(a, b Endpoint) bool {
	if a.Method != b.Method || staticSegments(a.Path) != staticSegments(b.Path) {
		return false
	}
	x, y := segments(a.Path), segments(b.Path)
	if len(x) != len(y) || strings.HasSuffix(a.Path, "/") != strings.HasSuffix(b.Path, "/") {
		return false
	}
	for i := range x {
		if x[i] != y[i] && !placeholderRE.MatchString(x[i]) && !placeholderRE.MatchString(y[i]) {
			return false
		}
	}
	return true
}

func matchTemplate(template, path string) (map[string]string, bool) {
	x, y := segments(template), segments(path)
	if len(x) != len(y) || strings.HasSuffix(template, "/") != strings.HasSuffix(path, "/") {
		return nil, false
	}
	params := map[string]string{}
	for i, p := range x {
		if placeholderRE.MatchString(p) {
			if y[i] == "" {
				return nil, false
			}
			params[p[1:len(p)-1]] = y[i]
		} else if p != y[i] {
			return nil, false
		}
	}
	return params, true
}

func (s *Settings) endpoint(method, path string) (*Endpoint, map[string]string, bool) {
	var chosen *Endpoint
	var params map[string]string
	priority := -1
	ambiguous := false
	for i := range s.Schema.Endpoints {
		e := &s.Schema.Endpoints[i]
		if e.Method != method {
			continue
		}
		p, match := matchTemplate(e.Path, path)
		if !match {
			continue
		}
		n := staticSegments(e.Path)
		if n > priority {
			chosen, params, priority, ambiguous = e, p, n, false
		} else if n == priority {
			ambiguous = true
		}
	}
	return chosen, params, ambiguous
}

func queryValues(query string) (url.Values, string) {
	if len(query) > 16384 {
		return nil, "query-budget"
	}
	if strings.Count(query, "&") >= 256 {
		return nil, "query-budget"
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return nil, "query-invalid"
	}
	for _, v := range values {
		if len(v) != 1 {
			return nil, "query-duplicate"
		}
	}
	for name, list := range values {
		if !utf8.ValidString(name) {
			return nil, "query-invalid"
		}
		for _, value := range list {
			if !utf8.ValidString(value) {
				return nil, "query-invalid"
			}
		}
	}
	return values, ""
}

func parameterValue(text string, s *Schema) (any, string) {
	switch s.Type {
	case "string":
		return text, ""
	case "boolean":
		if text == "true" {
			return true, ""
		}
		if text == "false" {
			return false, ""
		}
	case "integer", "number":
		v, err := decodeJSON(context.Background(), []byte(text), 1, 1)
		if err == nil {
			if n, ok := v.(json.Number); ok {
				return n, ""
			}
		}
	}
	return nil, "parameter-type"
}

func validateValue(ctx context.Context, s *Schema, v any) string {
	if ctx.Err() != nil {
		return "check-deadline"
	}
	if s.Enum != nil {
		found := false
		for _, e := range s.Enum {
			if scalarEqual(e, v) {
				found = true
				break
			}
		}
		if !found {
			return "schema-enum"
		}
	}
	if v == nil {
		if s.Type == "null" || s.Nullable {
			return ""
		}
		return "schema-type"
	}
	switch s.Type {
	case "string":
		x, ok := v.(string)
		if !ok {
			return "schema-type"
		}
		n := utf8.RuneCountInString(x)
		if s.MinLength != nil && n < *s.MinLength || s.MaxLength != nil && n > *s.MaxLength {
			return "schema-length"
		}
	case "number", "integer":
		x, ok := v.(json.Number)
		if !ok {
			return "schema-type"
		}
		n, ok := numberRat(x)
		if !ok {
			return "number-budget"
		}
		if s.Type == "integer" && !n.IsInt() {
			return "schema-type"
		}
		if s.Minimum != nil && n.Cmp(decimalBound(*s.Minimum)) < 0 || s.Maximum != nil && n.Cmp(decimalBound(*s.Maximum)) > 0 {
			return "schema-range"
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			return "schema-type"
		}
	case "object":
		x, ok := v.(map[string]any)
		if !ok {
			return "schema-type"
		}
		for _, k := range s.Required {
			if _, ok := x[k]; !ok {
				return "schema-required"
			}
		}
		for k, v := range x {
			if child := s.Properties[k]; child != nil {
				if code := validateValue(ctx, child, v); code != "" {
					return code
				}
			} else if s.AdditionalProperties != nil && !*s.AdditionalProperties {
				return "schema-additional"
			}
		}
	case "array":
		x, ok := v.([]any)
		if !ok {
			return "schema-type"
		}
		if s.MinItems != nil && len(x) < *s.MinItems || s.MaxItems != nil && len(x) > *s.MaxItems {
			return "schema-items"
		}
		if s.Items != nil {
			for _, v := range x {
				if code := validateValue(ctx, s.Items, v); code != "" {
					return code
				}
			}
		}
	default:
		return "schema-type"
	}
	return ""
}

func numberRat(n json.Number) (*big.Rat, bool) {
	if len(n) > 128 {
		return nil, false
	}
	if i := strings.IndexAny(string(n), "eE"); i >= 0 {
		exp, err := strconv.Atoi(string(n)[i+1:])
		if err != nil || exp < -1024 || exp > 1024 {
			return nil, false
		}
	}
	return new(big.Rat).SetString(string(n))
}

func decimalBound(n float64) *big.Rat {
	out, _ := numberRat(json.Number(strconv.FormatFloat(n, 'g', -1, 64)))
	return out
}

func scalarEqual(a, b any) bool {
	if n, ok := a.(json.Number); ok {
		m, ok := b.(json.Number)
		if !ok {
			return false
		}
		x, xok := numberRat(n)
		y, yok := numberRat(m)
		return xok && yok && x.Cmp(y) == 0
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	}
	return false
}

func validateEndpoint(ctx context.Context, e *Endpoint, params map[string]string, req Request) string {
	query, code := queryValues(req.Query)
	if code != "" {
		return code
	}
	headers := map[string][]string{}
	for name, values := range req.Headers {
		name = strings.ToLower(name)
		if len(values) != 1 || len(headers[name]) > 0 {
			return "header-duplicate"
		}
		headers[name] = values
	}
	for _, p := range e.Parameters {
		var text string
		present := false
		switch p.In {
		case "path":
			text, present = params[p.Name]
		case "query":
			if v, ok := query[p.Name]; ok {
				text, present = v[0], true
			}
		case "header":
			if v, ok := headers[strings.ToLower(p.Name)]; ok {
				text, present = v[0], true
			}
		}
		if !present {
			if p.Required {
				return "parameter-required"
			}
			continue
		}
		value, code := parameterValue(text, p.Schema)
		if code != "" {
			return code
		}
		if code := validateValue(ctx, p.Schema, value); code != "" {
			return code
		}
	}
	if len(req.Body) == 0 {
		if e.Body != nil && e.Body.Required {
			return "body-required"
		}
		return ""
	}
	if !jsonMedia(headers) {
		return "body-media-type"
	}
	value, err := decodeJSON(ctx, req.Body, 64, 10000)
	if err != nil {
		return issueCode(err)
	}
	if e.Body != nil {
		return validateValue(ctx, e.Body.Schema, value)
	}
	return ""
}

func jsonMedia(headers map[string][]string) bool {
	v := headers["content-type"]
	if len(v) != 1 {
		return false
	}
	media, params, err := mime.ParseMediaType(v[0])
	if err != nil {
		return false
	}
	charset := strings.ToLower(params["charset"])
	return media == "application/json" && (charset == "" || charset == "utf-8" || charset == "utf8")
}
