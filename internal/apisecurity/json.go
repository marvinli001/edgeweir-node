package apisecurity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

const MaxBodyBytes = 131072

func validUnicodeEscapes(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		for i++; i < len(raw) && raw[i] != '"'; i++ {
			if raw[i] != '\\' {
				continue
			}
			i++
			if i >= len(raw) {
				return false
			}
			if raw[i] != 'u' {
				continue
			}
			if i+4 >= len(raw) {
				return false
			}
			unit, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
			if err != nil {
				return false
			}
			i += 4
			if unit >= 0xd800 && unit <= 0xdbff {
				if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
					return false
				}
				low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return false
				}
				i += 6
			} else if unit >= 0xdc00 && unit <= 0xdfff {
				return false
			}
		}
		if i >= len(raw) {
			return false
		}
	}
	return true
}

type violation string

func (v violation) Error() string { return string(v) }

// Token traversal rejects duplicate keys before any consumer can select a
// different value, and bounds work before materializing the document.
func decodeJSON(ctx context.Context, raw []byte, depthLimit, nodeLimit int) (any, error) {
	if !utf8.Valid(raw) || !validUnicodeEscapes(raw) {
		return nil, violation("json-invalid")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		nodes++
		if nodes > nodeLimit || depth > depthLimit {
			return nil, violation("json-budget")
		}
		if err := ctx.Err(); err != nil {
			return nil, violation("check-deadline")
		}
		t, err := d.Token()
		if err != nil {
			return nil, violation("json-invalid")
		}
		switch t {
		case json.Delim('{'):
			out := map[string]any{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return nil, violation("json-invalid")
				}
				name, ok := key.(string)
				if !ok {
					return nil, violation("json-invalid")
				}
				if _, exists := out[name]; exists {
					return nil, violation("json-duplicate-key")
				}
				v, err := value(depth + 1)
				if err != nil {
					return nil, err
				}
				out[name] = v
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, violation("json-invalid")
			}
			return out, nil
		case json.Delim('['):
			out := []any{}
			for d.More() {
				v, err := value(depth + 1)
				if err != nil {
					return nil, err
				}
				out = append(out, v)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, violation("json-invalid")
			}
			return out, nil
		default:
			if _, delim := t.(json.Delim); delim {
				return nil, violation("json-invalid")
			}
			return t, nil
		}
	}
	v, err := value(1)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, violation("json-invalid")
	}
	return v, nil
}

func issueCode(err error) string {
	var v violation
	if errors.As(err, &v) {
		return string(v)
	}
	return "check-invalid"
}
