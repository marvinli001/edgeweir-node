package nodelog

import (
	"regexp"
	"strings"
	"time"
)

// An error log line: "2026/10/15 10:00:00 [error] 12#12: *34 message,
// client: ..." or, before the log is open, "nginx: [emerg] message".
var nginxLine = regexp.MustCompile(`^(?:\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} |nginx: )\[(emerg|alert|crit|error|warn|notice|info|debug)\] (?:\d+#\d+: )?(?:\*\d+ )?(.*)$`)

// luaHint marks messages of Lua code (ngx.log writes "[lua] file:line:").
var luaHint = regexp.MustCompile(`(?i)\blua\b|_by_lua`)

// contextKeys are the request context nginx appends, in its order.
var contextKeys = []string{"client", "server", "request", "subrequest", "upstream", "host", "referrer"}

// IsNginxLine reports whether line starts an error log message (other
// lines continue the previous one, e.g. a Lua stack traceback).
func IsNginxLine(line string) bool { return nginxLine.MatchString(line) }

// ParseNginx turns an error log message into an entry at time now; false
// for messages below warn and for ModSecurity's per-request lines (the
// statistics count those). The message keeps further lines of the same
// message after a newline.
func ParseNginx(message string, now time.Time) (Entry, bool) {
	e, ok := ParseNginxDebug(message, now)
	if !ok || (e.Level != LevelWarn && e.Level != LevelError) {
		return Entry{}, false
	}
	return e, true
}

// ParseNginxDebug is ParseNginx for a ring: messages of every level, info
// for notice and info (severity keeps which), debug for debug.
func ParseNginxDebug(message string, now time.Time) (Entry, bool) {
	first, rest, _ := strings.Cut(message, "\n")
	m := nginxLine.FindStringSubmatch(first)
	if m == nil {
		return Entry{}, false
	}
	e := Entry{Time: now, Source: SourceNginx}
	switch m[1] {
	case "warn":
		e.Level = LevelWarn
	case "error":
		e.Level = LevelError
	case "crit", "alert", "emerg":
		e.Level = LevelError
		e.Fields = map[string]string{"severity": m[1]}
	case "notice", "info":
		e.Level = LevelInfo
		e.Fields = map[string]string{"severity": m[1]}
	default:
		e.Level = LevelDebug
	}
	text := m[2]
	if strings.HasPrefix(text, "ModSecurity: Access denied") || strings.HasPrefix(text, "ModSecurity: Warning.") {
		return Entry{}, false
	}
	if msg, ctx, ok := strings.Cut(text, ", client: "); ok {
		text = msg
		if e.Fields == nil {
			e.Fields = map[string]string{}
		}
		parseContext("client", ctx, e.Fields)
	}
	if after, ok := strings.CutPrefix(text, "[lua] "); ok {
		e.Source, text = SourceLua, after
	} else if luaHint.MatchString(text) {
		e.Source = SourceLua
	}
	if rest != "" {
		text += "\n" + rest
	}
	e.Message = text
	return e, true
}

// parseContext reads "value, key: value, ..." starting with key into
// fields; what follows the known keys goes into "context".
func parseContext(key, s string, fields map[string]string) {
	for key != "" {
		var value string
		next := ""
		if strings.HasPrefix(s, `"`) {
			// A quoted value ends at a quote before ", " or the end.
			end := -1
			for i := 1; i < len(s); i++ {
				if s[i] == '"' && (i == len(s)-1 || strings.HasPrefix(s[i+1:], ", ")) {
					end = i
					break
				}
			}
			if end < 0 {
				value, s = s, ""
			} else {
				value, s = s[1:end], strings.TrimPrefix(s[end+1:], ", ")
			}
		} else {
			i := strings.Index(s, ", ")
			if i < 0 {
				value, s = s, ""
			} else {
				value, s = s[:i], s[i+2:]
			}
		}
		// nginx writes `server: ` for requests without a server name.
		if value != "" {
			fields[key] = value
		}
		for _, k := range contextKeys {
			if after, ok := strings.CutPrefix(s, k+": "); ok {
				next, s = k, after
				break
			}
		}
		key = next
	}
	if s != "" {
		fields["context"] = s
	}
}
