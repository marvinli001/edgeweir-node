package upgrade

import (
	"strconv"
	"strings"
)

// compareVersions compares two release versions ("1.2.3", "1.2.3-rc.1",
// see versionRE) by semantic versioning precedence: -1, 0 or 1. ok is false
// when either is not such a version (a "dev" build): nothing is known then.
func compareVersions(a, b string) (cmp int, ok bool) {
	if !versionRE.MatchString(a) || !versionRE.MatchString(b) {
		return 0, false
	}
	split := func(v string) (core []string, pre string) {
		core1, pre, _ := strings.Cut(v, "-")
		return strings.Split(core1, "."), pre
	}
	ca, pa := split(a)
	cb, pb := split(b)
	for i := range 3 {
		if c := compareNumeric(ca[i], cb[i]); c != 0 {
			return c, true
		}
	}
	switch {
	case pa == pb:
		return 0, true
	case pa == "":
		return 1, true // a release ranks above its pre-releases
	case pb == "":
		return -1, true
	}
	ia, ib := strings.Split(pa, "."), strings.Split(pb, ".")
	for i := 0; i < len(ia) && i < len(ib); i++ {
		na, ea := strconv.ParseUint(ia[i], 10, 64)
		nb, eb := strconv.ParseUint(ib[i], 10, 64)
		switch {
		case ea == nil && eb == nil:
			if na != nb {
				if na < nb {
					return -1, true
				}
				return 1, true
			}
		case ea == nil:
			return -1, true // numeric identifiers rank below alphanumeric ones
		case eb == nil:
			return 1, true
		default:
			if c := strings.Compare(ia[i], ib[i]); c != 0 {
				return c, true
			}
		}
	}
	switch {
	case len(ia) < len(ib):
		return -1, true
	case len(ia) > len(ib):
		return 1, true
	}
	return 0, true
}

func compareNumeric(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}
