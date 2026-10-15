package nodelog

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRedactVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/redaction_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct{ Name, In, Out string }
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 10 {
		t.Fatalf("only %d vectors", len(vectors))
	}
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			if got := Redact(v.In); got != v.Out {
				t.Errorf("Redact(%q)\n got %q\nwant %q", v.In, got, v.Out)
			}
			if got := Redact(v.Out); got != v.Out {
				t.Errorf("Redact is not idempotent: %q -> %q", v.Out, got)
			}
		})
	}
}

func TestRedactField(t *testing.T) {
	for _, tc := range []struct{ key, value, want string }{
		{"err", `Get "https://u:p@h/x?a=1": refused`, `Get "https://[redacted]@h/x?[redacted]": refused`},
		{"token", "plain", Redacted},
		{"enroll.token_file", "/etc/x", Redacted},
		{"private_key_pem", "x", Redacted},
		{"authorization", "Basic x", Redacted},
		{"revision", "42", "42"},
		{"cert_key_type", "ec256", "ec256"},
	} {
		if got := RedactField(tc.key, tc.value); got != tc.want {
			t.Errorf("RedactField(%q, %q) = %q, want %q", tc.key, tc.value, got, tc.want)
		}
	}
}

func TestSanitizeLimits(t *testing.T) {
	fields := map[string]string{}
	for i := range 20 {
		fields["Key "+string(rune('a'+i))] = "v"
	}
	fields["long"] = strings.Repeat("é", MaxFieldValue)
	e := sanitize(Entry{
		Level: LevelWarn, Source: SourceAgent, Component: "Channel",
		Message: strings.Repeat("界", MaxMessage) + "\x00\x1b",
		Fields:  fields,
	})
	if len(e.Message) > MaxMessage || !strings.HasPrefix(e.Message, "界") || !e.Truncated {
		t.Fatalf("message %d bytes, truncated %v", len(e.Message), e.Truncated)
	}
	if strings.ContainsAny(e.Message, "\x00\x1b") {
		t.Fatal("control characters kept")
	}
	if len(e.Fields) != MaxFields {
		t.Fatalf("%d fields", len(e.Fields))
	}
	for k, v := range e.Fields {
		if k != strings.ToLower(k) || strings.Contains(k, " ") || len(v) > MaxFieldValue {
			t.Fatalf("field %q=%q", k, v)
		}
	}
	if e.Component != "channel" {
		t.Fatalf("component %q", e.Component)
	}
	// Newlines and tabs stay (nginx -t output, Lua tracebacks).
	if got := sanitize(Entry{Message: "a\n\tb"}).Message; got != "a\n\tb" {
		t.Fatalf("message %q", got)
	}
}

func TestCutKeepsRunes(t *testing.T) {
	if s, was := cut("aé", 2); s != "a" || !was {
		t.Fatalf("%q %v", s, was)
	}
	if s, was := cut("abc", 3); s != "abc" || was {
		t.Fatalf("%q %v", s, was)
	}
}
