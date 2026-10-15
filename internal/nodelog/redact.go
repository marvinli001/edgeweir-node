package nodelog

import (
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// The console applies the same rules again (packages/contract
// node-logs.ts); testdata/redaction_vectors.json is shared with it.
var (
	// PEM blocks, also one cut off before its END line.
	pemBlock = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]+-----.*?(?:-----END [A-Z0-9 ]+-----|$)`)
	// userinfo of a URL: scheme://user:password@host.
	userinfo = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@"'<>]+@`)
	// The query string of a URL or of a path (a request line, a Lua
	// message): everything from "?" to the end of the token.
	query = regexp.MustCompile(`(?i)((?:\b[a-z][a-z0-9+.-]*://[^\s"'<>?#]*|(?:^|[\s"'(=:,\[])/[^\s"'<>?#]*)\?)[^\s"'<>#]+`)
	// Credential headers written as "Name: value" or "name=value".
	header = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-amz-security-token)(["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^\r\n"']*)`)
	bearer = regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]{8,}`)
	// key=value and "key": "value" with a credential-like key.
	keyValue = regexp.MustCompile(`(?i)\b([a-z0-9_.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key|signature|credential|session[_-]?id)[a-z0-9_.-]*)(["']?\s*=\s*|["']\s*:\s*)("[^"]*"|'[^']*'|[^\s,;&"'<>)]+)`)
	// The console's tokens and keys (enrollment, probe, setup, service
	// account, AccessKey) and JWTs.
	consoleToken = regexp.MustCompile(`\bew[kpstw]_[A-Za-z0-9_-]{16,}`)
	jwt          = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	// Attribute keys whose values are always removed.
	sensitiveKey = regexp.MustCompile(`(?i)(token|secret|passw(?:or)?d|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?key|signature|credential|session[_-]?id|authorization|cookie)`)
)

// Redacted replaces what Redact removes.
const Redacted = "[redacted]"

// Redact removes secrets from s: PEM blocks, URL userinfo, query strings,
// credential headers, bearer tokens, values of credential-like keys, the
// console's tokens and JWTs. Applying it twice changes nothing more.
func Redact(s string) string {
	if s == "" {
		return s
	}
	s = pemBlock.ReplaceAllString(s, Redacted)
	s = userinfo.ReplaceAllString(s, "${1}"+Redacted+"@")
	s = query.ReplaceAllString(s, "${1}"+Redacted)
	s = header.ReplaceAllString(s, "${1}${2}"+Redacted)
	s = bearer.ReplaceAllString(s, "${1} "+Redacted)
	s = keyValue.ReplaceAllString(s, "${1}${2}"+Redacted)
	s = consoleToken.ReplaceAllString(s, Redacted)
	return jwt.ReplaceAllString(s, Redacted)
}

// RedactField returns value with secrets removed; a credential-like key
// removes the whole value.
func RedactField(key, value string) string {
	if sensitiveKey.MatchString(key) {
		return Redacted
	}
	return Redact(value)
}

// clean removes control characters other than newline and tab.
func clean(s string) string {
	if strings.IndexFunc(s, isControl) < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isControl(r) {
			return -1
		}
		return r
	}, s)
}

func isControl(r rune) bool {
	return r != '\n' && r != '\t' && (r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0))
}

// cut returns s cut to at most n bytes on a rune boundary, and whether it
// was cut.
func cut(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n], true
}

// fieldKey is key in [a-z0-9_.-], at most MaxFieldKey bytes; empty for
// none left.
func fieldKey(key string) string {
	key = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '_'
		}
	}, key)
	key, _ = cut(key, MaxFieldKey)
	return strings.Trim(key, "_")
}

// sanitize removes secrets and control characters and applies the size
// limits.
func sanitize(e Entry) Entry {
	var cutMessage bool
	e.Message, cutMessage = cut(clean(Redact(e.Message)), MaxMessage)
	e.Truncated = e.Truncated || cutMessage
	e.Component, _ = cut(fieldKey(e.Component), MaxFieldKey)
	if len(e.Fields) == 0 {
		e.Fields = nil
		return e
	}
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	fields := make(map[string]string, min(len(keys), MaxFields))
	for _, k := range keys {
		key := fieldKey(k)
		if key == "" {
			continue
		}
		if _, dup := fields[key]; dup {
			continue
		}
		if len(fields) == MaxFields {
			e.Truncated = true
			break
		}
		value, cutValue := cut(clean(RedactField(key, e.Fields[k])), MaxFieldValue)
		e.Truncated = e.Truncated || cutValue
		fields[key] = value
	}
	e.Fields = fields
	return e
}
