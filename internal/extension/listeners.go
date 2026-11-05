package extension

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

const (
	ScopeSite = "site"
	ScopeNode = "node"
)

// Listener is a signed declaration; DefaultPort never opens a listener.
type Listener struct {
	Name        string   `json:"name"`
	DefaultPort int      `json:"default_port"`
	Methods     []string `json:"methods"`
	MaxBody     *int     `json:"max_body,omitempty"`
}

// BodyLimit preserves an explicit zero while defaulting an omitted limit.
func (l Listener) BodyLimit() int {
	if l.MaxBody == nil {
		return 4096
	}
	return *l.MaxBody
}

// ValidListenerPort excludes privileged ports and the console's port.
func ValidListenerPort(port int) bool {
	return port >= 1024 && port <= 65535 && port != 8443
}

// ValidListenerMethods checks the non-empty method set shared by declarations and bindings.
func ValidListenerMethods(methods []string) bool {
	if len(methods) == 0 || len(methods) > 3 || !unique(methods) {
		return false
	}
	for _, method := range methods {
		if method != "GET" && method != "HEAD" && method != "POST" {
			return false
		}
	}
	return true
}

func (m *Manifest) validateScope(data []byte) error {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(data, &members); err != nil {
		return err
	}
	// encoding/json otherwise treats null as an absent optional member.
	for name, value := range members {
		switch name {
		case "format", "id", "version", "publisher", "name", "description", "license", "homepage", "requires",
			"scope", "hooks", "capabilities", "config", "fields", "log_fields", "counters", "endpoints", "listeners",
			"shared_dicts", "secret", "sidecar", "data":
		default:
			return fmt.Errorf("unknown member %q", name)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("%s cannot be null", name)
		}
	}
	var requires map[string]json.RawMessage
	if err := json.Unmarshal(members["requires"], &requires); err != nil {
		return errors.New("requires must be an object")
	}
	for name, value := range requires {
		if (name != "lua_api" && name != "node") || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("invalid requires member %q", name)
		}
	}
	if m.Scope != ScopeSite && m.Scope != ScopeNode {
		return fmt.Errorf("invalid scope %q", m.Scope)
	}
	var config map[string]json.RawMessage
	if len(m.Config) > 0 {
		if err := json.Unmarshal(m.Config, &config); err != nil {
			return errors.New("config must be an object")
		}
		for name := range config {
			if name != "global" && name != "site" {
				return fmt.Errorf("unknown config member %q", name)
			}
		}
	}
	if m.Scope == ScopeSite {
		if m.Listeners != nil || slices.Contains(m.Hooks, "listen") {
			return errors.New("listeners and listen need node scope")
		}
	} else {
		if m.Requires.LuaAPI != 2 {
			return errors.New("node scope needs lua_api 2")
		}
		for _, hook := range m.Hooks {
			if hook != "init" && hook != "log" && hook != "listen" {
				return fmt.Errorf("hook %q needs site scope", hook)
			}
		}
		for _, capability := range m.Capabilities {
			if capability != "request_body" && capability != "http_client" && capability != "timers" {
				return fmt.Errorf("capability %q needs site scope", capability)
			}
		}
		if config["site"] != nil || len(m.Fields) > 0 || len(m.Endpoints) > 0 || m.Sidecar != nil || m.Data != nil {
			return errors.New("config.site, fields, endpoints, sidecar and data need site scope")
		}
		if slices.Contains(m.Hooks, "listen") != (len(m.Listeners) > 0) {
			return errors.New("listen hook and listeners go together")
		}
	}
	if m.Requires.LuaAPI < 2 && members["secret"] != nil {
		return errors.New("secret needs lua_api 2")
	}
	if len(m.Listeners) > 2 {
		return errors.New("too many listeners")
	}
	var raw struct {
		Listeners []map[string]json.RawMessage `json:"listeners"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	names := map[string]bool{}
	for i, listener := range m.Listeners {
		for name := range raw.Listeners[i] {
			if name != "name" && name != "default_port" && name != "methods" && name != "max_body" {
				return fmt.Errorf("unknown listener member %q", name)
			}
		}
		if !shortNameRE.MatchString(listener.Name) || names[listener.Name] || !ValidListenerPort(listener.DefaultPort) ||
			!ValidListenerMethods(listener.Methods) || listener.BodyLimit() < 0 || listener.BodyLimit() > 65536 ||
			bytes.Equal(bytes.TrimSpace(raw.Listeners[i]["max_body"]), []byte("null")) {
			return fmt.Errorf("invalid listener %q", listener.Name)
		}
		names[listener.Name] = true
	}
	return nil
}
