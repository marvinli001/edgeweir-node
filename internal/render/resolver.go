package render

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"strings"
)

// ParseResolvConf extracts nameserver addresses from resolv.conf content in
// nginx `resolver` syntax: IPv4 as is, IPv6 in brackets. Scoped IPv6
// addresses (fe80::1%eth0) are skipped because nginx cannot use them.
// Docker's embedded DNS (127.0.0.11) is returned like any other address.
func ParseResolvConf(r io.Reader) []string {
	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil || addr.Zone() != "" || addr.IsUnspecified() {
			continue
		}
		s := addr.String()
		if addr.Is6() && !addr.Is4In6() {
			s = "[" + s + "]"
		} else if addr.Is4In6() {
			s = addr.Unmap().String()
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Resolvers reads nameservers from path. When the file is missing or has
// no usable entry it returns 127.0.0.1, matching the resolv.conf(5)
// default of querying the local host.
func Resolvers(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{"127.0.0.1"}
	}
	defer f.Close()
	if rs := ParseResolvConf(f); len(rs) > 0 {
		return rs
	}
	return []string{"127.0.0.1"}
}

func validResolver(s string) bool {
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		a, err := netip.ParseAddr(s[1 : len(s)-1])
		return err == nil && a.Is6() && a.Zone() == ""
	}
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4()
}
