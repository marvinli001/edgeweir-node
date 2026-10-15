package nodelog

import (
	"testing"
	"time"
)

func TestParseNginx(t *testing.T) {
	now := time.Unix(100, 0)
	for _, tc := range []struct {
		name, line string
		ok         bool
		want       Entry
	}{
		{
			name: "upstream failure with request context",
			line: `2026/10/15 10:00:00 [error] 12#12: *34 connect() failed (111: Connection refused) while connecting to upstream, client: 192.0.2.1, server: , request: "GET /x?token=s HTTP/1.1", upstream: "http://127.0.0.1:9/x?token=s", host: "a.test", referrer: "https://r.test/"`,
			ok:   true,
			want: Entry{Level: LevelError, Source: SourceNginx, Message: "connect() failed (111: Connection refused) while connecting to upstream",
				Fields: map[string]string{"client": "192.0.2.1", "request": "GET /x?token=s HTTP/1.1", "upstream": "http://127.0.0.1:9/x?token=s", "host": "a.test", "referrer": "https://r.test/"}},
		},
		{
			name: "lua warning",
			line: `2026/10/15 10:00:00 [warn] 12#12: *34 [lua] router.lua:120: route(): unknown host, client: 192.0.2.1, server: _`,
			ok:   true,
			want: Entry{Level: LevelWarn, Source: SourceLua, Message: "router.lua:120: route(): unknown host",
				Fields: map[string]string{"client": "192.0.2.1", "server": "_"}},
		},
		{
			name: "lua runtime error with traceback",
			line: "2026/10/15 10:00:00 [error] 12#12: *1 lua entry thread aborted: runtime error: boom\nstack traceback:\n\t[C]: in function 'error'",
			ok:   true,
			want: Entry{Level: LevelError, Source: SourceLua, Message: "lua entry thread aborted: runtime error: boom\nstack traceback:\n\t[C]: in function 'error'"},
		},
		{
			name: "startup failure",
			line: `nginx: [emerg] unknown directive "foo" in /state/nginx/conf/nginx.conf:12`,
			ok:   true,
			want: Entry{Level: LevelError, Source: SourceNginx, Message: `unknown directive "foo" in /state/nginx/conf/nginx.conf:12`,
				Fields: map[string]string{"severity": "emerg"}},
		},
		{
			name: "stream context",
			line: `2026/10/15 10:00:00 [error] 7#7: *9 upstream timed out (110: Connection timed out) while proxying connection, client: 192.0.2.1, server: 0.0.0.0:9000, upstream: "192.0.2.9:22", bytes from/to client:0/0, bytes from/to upstream:0/0`,
			ok:   true,
			want: Entry{Level: LevelError, Source: SourceNginx, Message: "upstream timed out (110: Connection timed out) while proxying connection",
				Fields: map[string]string{"client": "192.0.2.1", "server": "0.0.0.0:9000", "upstream": "192.0.2.9:22", "context": "bytes from/to client:0/0, bytes from/to upstream:0/0"}},
		},
		{name: "notice", line: `2026/10/15 10:00:00 [notice] 1#1: signal process started`},
		{name: "modsecurity denial", line: `2026/10/15 10:00:00 [error] 1#1: *2 ModSecurity: Access denied with code 403 (phase 2)`},
		{name: "not a log line", line: `stack traceback:`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := ParseNginx(tc.line, now)
			if ok != tc.ok {
				t.Fatalf("ok %v", ok)
			}
			if !ok {
				return
			}
			tc.want.Time = now
			if got.Level != tc.want.Level || got.Source != tc.want.Source || got.Message != tc.want.Message || !got.Time.Equal(now) {
				t.Fatalf("got %+v\nwant %+v", got, tc.want)
			}
			if len(got.Fields) != len(tc.want.Fields) {
				t.Fatalf("fields %v, want %v", got.Fields, tc.want.Fields)
			}
			for k, v := range tc.want.Fields {
				if got.Fields[k] != v {
					t.Fatalf("field %s = %q, want %q", k, got.Fields[k], v)
				}
			}
		})
	}
}

func TestIsNginxLine(t *testing.T) {
	if !IsNginxLine(`2026/10/15 10:00:00 [warn] 1#1: x`) || !IsNginxLine(`nginx: [alert] x`) || IsNginxLine("\t[C]: in function") {
		t.Fatal("IsNginxLine")
	}
}
