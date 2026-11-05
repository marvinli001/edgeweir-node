package configir

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/marvinli001/edgeweir-node/internal/extension"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// ExtensionListener is an effective binding, separate from the extension's configuration.
type ExtensionListener struct {
	Name    string   `json:"name"`
	Port    uint32   `json:"port"`
	Bind    string   `json:"bind"`
	Allow   []string `json:"allow"`
	Methods []string `json:"methods"`
	MaxBody int      `json:"max_body"`
}

// NormalizeExtensionListeners rechecks bindings before they enter nginx.conf.
func NormalizeExtensionListeners(listeners []ExtensionListener) ([]ExtensionListener, error) {
	bindings := make([]*nodev1.ExtensionListener, 0, len(listeners))
	for _, listener := range listeners {
		if listener.MaxBody < 0 || listener.MaxBody > 65536 {
			return nil, errors.New("listener body limit")
		}
		limit := uint32(listener.MaxBody)
		bindings = append(bindings, &nodev1.ExtensionListener{
			Name: listener.Name, Port: listener.Port, Bind: listener.Bind, Allow: listener.Allow,
			Methods: listener.Methods, MaxBody: &limit,
		})
	}
	return buildExtensionListeners(bindings)
}

func buildExtensionListeners(bindings []*nodev1.ExtensionListener) ([]ExtensionListener, error) {
	if len(bindings) > 2 {
		return nil, errors.New("too many listeners")
	}
	var out []ExtensionListener
	for _, binding := range bindings {
		if !extensionDict.MatchString(binding.GetName()) || !extension.ValidListenerPort(int(binding.GetPort())) ||
			!extension.ValidListenerMethods(binding.GetMethods()) || len(binding.GetAllow()) < 1 || len(binding.GetAllow()) > 64 ||
			slices.ContainsFunc(out, func(l ExtensionListener) bool { return l.Name == binding.GetName() || l.Port == binding.GetPort() }) {
			return nil, errors.New("listener name, port, methods or ACL")
		}
		if len(binding.ProtoReflect().GetUnknown()) > 0 {
			return nil, errors.New("unknown listener fields")
		}
		bind, err := netip.ParseAddr(binding.GetBind())
		if err != nil || bind.Zone() != "" || bind.Is4In6() {
			return nil, errors.New("listener bind address")
		}
		listener := ExtensionListener{
			Name: binding.GetName(), Port: binding.GetPort(), Bind: bind.String(),
			Methods: slices.Clone(binding.GetMethods()), MaxBody: 4096,
		}
		if binding.MaxBody != nil {
			if binding.GetMaxBody() > 65536 {
				return nil, errors.New("listener body limit")
			}
			listener.MaxBody = int(binding.GetMaxBody())
		}
		for _, value := range binding.GetAllow() {
			var prefix netip.Prefix
			if strings.Contains(value, "/") {
				prefix, err = netip.ParsePrefix(value)
			} else {
				var ip netip.Addr
				ip, err = netip.ParseAddr(value)
				if err != nil || ip.Zone() != "" || ip.Is4In6() {
					return nil, errors.New("listener ACL address")
				}
				prefix = netip.PrefixFrom(ip, ip.BitLen())
			}
			if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
				return nil, errors.New("listener ACL address")
			}
			listener.Allow = append(listener.Allow, prefix.Masked().String())
		}
		slices.Sort(listener.Allow)
		listener.Allow = slices.Compact(listener.Allow)
		slices.Sort(listener.Methods)
		out = append(out, listener)
	}
	slices.SortFunc(out, func(a, b ExtensionListener) int { return cmp.Compare(a.Name, b.Name) })
	return out, nil
}

// CheckManifest compares delivered settings with the manifest after signature verification.
func (e Extension) CheckManifest(manifest *extension.Manifest) error {
	scope := manifest.Scope
	if scope == extension.ScopeSite {
		scope = ""
	}
	if e.Scope != scope {
		return errors.New("the configured scope differs from the signed manifest's")
	}
	if max(1, e.LuaAPI) != uint32(manifest.Requires.LuaAPI) {
		return errors.New("the configured Lua API differs from the signed manifest's")
	}
	if e.Scope == extension.ScopeNode && manifest.Secret != (e.SecretVersion > 0) {
		return errors.New("the configured secret differs from the signed manifest's")
	}
	for _, listener := range e.Listeners {
		index := slices.IndexFunc(manifest.Listeners, func(l extension.Listener) bool { return l.Name == listener.Name })
		if index < 0 {
			return fmt.Errorf("listener %q is not declared in the signed manifest", listener.Name)
		}
		declaration := manifest.Listeners[index]
		methods := slices.Clone(declaration.Methods)
		slices.Sort(methods)
		if !slices.Equal(listener.Methods, methods) || listener.MaxBody != declaration.BodyLimit() {
			return fmt.Errorf("listener %q methods or body limit differ from the signed manifest's", listener.Name)
		}
	}
	return nil
}
