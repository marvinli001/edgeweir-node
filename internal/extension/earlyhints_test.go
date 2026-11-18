package extension

import "testing"

func TestEarlyHintsCapability(t *testing.T) {
	for _, scope := range []string{ScopeSite, ScopeNode} {
		for _, api := range []int{1, 2} {
			_, err := ParseManifest(scopeManifest(t, func(m map[string]any) {
				if scope == ScopeSite {
					delete(m, "scope")
					m["hooks"] = []string{"access_late"}
				}
				m["requires"] = map[string]int{"lua_api": api}
				m["capabilities"] = []string{"early_hints"}
			}))
			if (err == nil) != (scope == ScopeSite && api == 2) {
				t.Errorf("scope=%s api=%d: %v", scope, api, err)
			}
		}
	}
}
