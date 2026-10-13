package controlplane

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/identity"
)

// maxAddressURL bounds a node channel URL (the console's limit).
const maxAddressURL = 2048

// Address is a node channel URL and the TLS server name the console's
// certificate is verified against (empty: the URL's host). Whatever the
// address, the certificate must come from the CA pinned at enrollment.
type Address struct {
	URL        string
	ServerName string
}

// Empty reports whether a has no URL.
func (a Address) Empty() bool { return a.URL == "" }

// Host returns the URL's host name or IP ("" for an unparsable URL).
func (a Address) Host() string {
	u, err := url.Parse(a.URL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// Name returns the server name, or the URL's host when it is empty.
func (a Address) Name() string {
	if a.ServerName != "" {
		return strings.ToLower(a.ServerName)
	}
	return strings.ToLower(a.Host())
}

// Equal reports whether a and b reach the same URL (default ports and the
// case of the host aside) and verify the same name.
func (a Address) Equal(b Address) bool {
	if a.Empty() || b.Empty() {
		return a.Empty() && b.Empty()
	}
	return canonicalURL(a.URL) == canonicalURL(b.URL) && a.Name() == b.Name()
}

// Proto returns a as a ChannelAddress (nil when empty).
func (a Address) Proto() *nodev1.ChannelAddress {
	if a.Empty() {
		return nil
	}
	return &nodev1.ChannelAddress{Url: a.URL, ServerName: a.ServerName}
}

func (a Address) String() string {
	if a.ServerName == "" || strings.EqualFold(a.ServerName, a.Host()) {
		return a.URL
	}
	return a.URL + " (server name " + a.ServerName + ")"
}

// CurrentAddress and FallbackAddress are the addresses of an identity file.
func CurrentAddress(id identity.Identity) Address {
	return Address{URL: id.ServerURL, ServerName: id.ServerName}
}

func FallbackAddress(id identity.Identity) Address {
	return Address{URL: id.FallbackServerURL, ServerName: id.FallbackServerName}
}

// canonicalURL is the URL with a lowercase host and without the scheme's
// default port; the input as is when it does not parse.
func canonicalURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	host, port := strings.ToLower(u.Hostname()), u.Port()
	if (port == "443" && (u.Scheme == "https" || u.Scheme == "wss")) || (port == "80" && u.Scheme == "ws") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return u.Scheme + "://" + host
}

// ParseAddress validates an address the console gives out or an operator
// types (set-server): https://, wss:// or ws:// with a host and an optional
// port, nothing else (no userinfo, path, query or fragment), and a server
// name that is a DNS name or an IP. It returns the address with the URL in
// its canonical form (scheme://host[:port], default port left out).
func ParseAddress(rawURL, serverName string) (Address, error) {
	if len(rawURL) > maxAddressURL {
		return Address{}, errors.New("the URL is longer than 2048 bytes")
	}
	u, err := ParseServerURL(rawURL)
	if err != nil {
		return Address{}, err
	}
	if u.Path != "" && u.Path != "/" || u.RawPath != "" || u.Opaque != "" || u.ForceQuery {
		return Address{}, fmt.Errorf("invalid server URL %q: a node channel URL has no path", rawURL)
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Address{}, fmt.Errorf("invalid server URL %q: port out of range", rawURL)
		}
	}
	if err := validName(u.Hostname()); err != nil {
		return Address{}, fmt.Errorf("invalid server URL %q: %w", rawURL, err)
	}
	if serverName != "" {
		if err := validName(serverName); err != nil {
			return Address{}, fmt.Errorf("invalid server name %q: %w", serverName, err)
		}
	}
	return Address{URL: canonicalURL(u.String()), ServerName: strings.ToLower(serverName)}, nil
}

// validName accepts an IP literal or a DNS name (letters, digits and
// hyphens in labels of at most 63 bytes, at most 253 bytes in all); no
// wildcards.
func validName(name string) error {
	if name == "" {
		return errors.New("missing host")
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return nil
	}
	if net.ParseIP(name) != nil {
		return nil
	}
	name = strings.TrimSuffix(name, ".")
	if len(name) > 253 {
		return errors.New("host name longer than 253 bytes")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return errors.New("empty or overlong label in the host name")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("a label of the host name starts or ends with a hyphen")
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return fmt.Errorf("character %q in the host name", r)
			}
		}
	}
	return nil
}
