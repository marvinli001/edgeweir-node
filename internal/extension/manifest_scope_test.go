package extension

import (
	"encoding/json"
	"testing"
)

func scopeManifest(t *testing.T, change func(map[string]any)) []byte {
	t.Helper()
	m := map[string]any{
		"format": Format, "id": "status-ext", "version": "1.0.0", "publisher": "example.org",
		"name": map[string]string{"en": "Status"}, "requires": map[string]int{"lua_api": 2},
		"scope": ScopeNode, "hooks": []string{"init"},
	}
	change(m)
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func listenerDeclaration() map[string]any {
	return map[string]any{"name": "http", "default_port": 9100, "methods": []string{"GET", "HEAD"}}
}

func TestManifestScopes(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"node init": func(m map[string]any) {},
		"node shared members": func(m map[string]any) {
			m["hooks"] = []string{"init", "log"}
			m["capabilities"] = []string{"request_body", "http_client", "timers"}
			m["config"] = map[string]any{"global": map[string]any{"type": "object"}}
			m["fields"], m["endpoints"] = []any{}, []any{}
			m["secret"], m["log_fields"], m["counters"] = true, []string{"status"}, []string{"requests"}
			m["shared_dicts"] = []any{map[string]any{"name": "state", "size_kb": 16}}
		},
		"empty node declarations": func(m map[string]any) { m["listeners"] = []any{} },
		"two declarations": func(m map[string]any) {
			other := listenerDeclaration()
			other["name"] = "other"
			m["hooks"], m["listeners"] = []string{"listen"}, []any{listenerDeclaration(), other}
		},
		"legacy site": func(m map[string]any) {
			delete(m, "scope")
			m["hooks"] = []string{"access"}
		},
		"explicit site": func(m map[string]any) { m["scope"] = ScopeSite },
	} {
		t.Run(name, func(t *testing.T) {
			m, err := ParseManifest(scopeManifest(t, change))
			if err != nil {
				t.Fatal(err)
			}
			if name == "legacy site" && m.Scope != ScopeSite {
				t.Fatalf("legacy scope %q", m.Scope)
			}
		})
	}
	for name, change := range map[string]func(map[string]any){
		"unknown scope":        func(m map[string]any) { m["scope"] = "sites" },
		"empty scope":          func(m map[string]any) { m["scope"] = "" },
		"null scope":           func(m map[string]any) { m["scope"] = nil },
		"scope type":           func(m map[string]any) { m["scope"] = 2 },
		"scope key case":       func(m map[string]any) { m["Scope"] = ScopeNode },
		"node API 1":           func(m map[string]any) { m["requires"] = map[string]int{"lua_api": 1} },
		"unknown API":          func(m map[string]any) { m["requires"] = map[string]int{"lua_api": 3} },
		"unknown requirement":  func(m map[string]any) { m["requires"] = map[string]any{"lua_api": 2, "other": true} },
		"requirement key case": func(m map[string]any) { m["requires"] = map[string]any{"Lua_API": 2} },
		"API type":             func(m map[string]any) { m["requires"] = map[string]string{"lua_api": "2"} },
		"site hook":            func(m map[string]any) { m["hooks"] = []string{"access"} },
		"empty hooks":          func(m map[string]any) { m["hooks"] = []string{} },
		"repeated hooks":       func(m map[string]any) { m["hooks"] = []string{"init", "init"} },
		"site capability":      func(m map[string]any) { m["capabilities"] = []string{"verdicts"} },
		"null capabilities":    func(m map[string]any) { m["capabilities"] = nil },
		"site config":          func(m map[string]any) { m["config"] = map[string]any{"site": map[string]any{}} },
		"null site config":     func(m map[string]any) { m["config"] = map[string]any{"site": nil} },
		"unknown config":       func(m map[string]any) { m["config"] = map[string]any{"listeners": map[string]any{}} },
		"config type":          func(m map[string]any) { m["config"] = []any{} },
		"site fields":          func(m map[string]any) { m["fields"] = []any{map[string]string{"name": "status", "type": "number"}} },
		"null fields":          func(m map[string]any) { m["fields"] = nil },
		"site endpoints": func(m map[string]any) {
			m["endpoints"] = []any{map[string]any{"path": "status", "methods": []string{"GET"}}}
		},
		"sidecar":      func(m map[string]any) { m["sidecar"] = map[string]any{"binary": "run", "memory_mb": 16} },
		"null sidecar": func(m map[string]any) { m["sidecar"] = nil },
		"data": func(m map[string]any) {
			m["data"] = map[string]int{"max_bytes": 1, "max_items": 1, "max_total_bytes": 1}
		},
		"null data": func(m map[string]any) { m["data"] = nil },
		"missing declarations": func(m map[string]any) {
			m["hooks"] = []string{"listen"}
		},
		"empty declarations with hook": func(m map[string]any) {
			m["hooks"], m["listeners"] = []string{"listen"}, []any{}
		},
		"declarations without hook": func(m map[string]any) { m["listeners"] = []any{listenerDeclaration()} },
		"site declarations": func(m map[string]any) {
			m["scope"], m["listeners"] = ScopeSite, []any{}
		},
		"site listen":       func(m map[string]any) { m["scope"], m["hooks"] = ScopeSite, []string{"listen"} },
		"null declarations": func(m map[string]any) { m["listeners"] = nil },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseManifest(scopeManifest(t, change)); err == nil {
				t.Fatal("invalid scope contract accepted")
			}
		})
	}
}

func TestManifestListeners(t *testing.T) {
	parse := func(change func(map[string]any)) (*Manifest, error) {
		return ParseManifest(scopeManifest(t, func(m map[string]any) {
			listener := listenerDeclaration()
			change(listener)
			m["hooks"], m["listeners"] = []string{"listen"}, []any{listener}
		}))
	}
	for name, values := range map[string]map[string]any{
		"default body": {},
		"zero body":    {"max_body": 0, "default_port": 1024},
		"upper limits": {"max_body": 65536, "default_port": 65535, "methods": []string{"POST", "HEAD", "GET"}},
	} {
		t.Run(name, func(t *testing.T) {
			m, err := parse(func(l map[string]any) {
				for key, value := range values {
					l[key] = value
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			want := 4096
			if body, ok := values["max_body"]; ok {
				want = body.(int)
			}
			if m.Listeners[0].BodyLimit() != want {
				t.Fatalf("body limit %d, want %d", m.Listeners[0].BodyLimit(), want)
			}
		})
	}
	for key, values := range map[string][]any{
		"name":         {"", "Bad", "abcdefghijklmnopq", nil},
		"default_port": {0, 1023, 8443, 65536, 9100.5, "9100", nil},
		"methods":      {[]string{}, []string{"GET", "GET"}, []string{"PUT"}, []string{"get"}, "GET", nil},
		"max_body":     {-1, 65537, 0.5, "0", nil},
		"unknown":      {true},
		"Max_Body":     {nil},
	} {
		for _, value := range values {
			if _, err := parse(func(l map[string]any) { l[key] = value }); err == nil {
				t.Errorf("accepted %s = %v", key, value)
			}
		}
	}
	for _, count := range []int{2, 3} {
		_, err := ParseManifest(scopeManifest(t, func(m map[string]any) {
			listeners := []any{listenerDeclaration(), listenerDeclaration()}
			if count == 3 {
				listeners = append(listeners, listenerDeclaration())
				for i, listener := range listeners {
					listener.(map[string]any)["name"] = []string{"http", "other", "third"}[i]
				}
			}
			m["hooks"], m["listeners"] = []string{"listen"}, listeners
		}))
		if err == nil {
			t.Errorf("accepted invalid set of %d declarations", count)
		}
	}
}
