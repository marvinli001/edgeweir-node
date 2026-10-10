package agent

import (
	"cmp"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// Bounds of the statistics dimensions (feature stats-dims-v1, ADR-0041);
// the data plane keeps the same.
const (
	maxStatsCountries  = 250
	maxStatsTop        = 50
	maxStatsNameBytes  = 128
	maxRefererHostSize = 253
)

// Keys of the dimension maps (the console's STATS_DIMENSION_KEYS).
var (
	statsBrowsers = setOf("chrome", "edge", "firefox", "safari", "opera", "samsung", "uc", "qq", "wechat", "yandex", "ie",
		"crawler", "tool", "other")
	statsOSes         = setOf("windows", "macos", "ios", "android", "linux", "chromeos", "harmonyos", "other")
	statsDevices      = setOf("desktop", "mobile", "tablet", "crawler", "other")
	statsHTTPVersions = setOf("1.0", "1.1", "2", "3", "other")
	statsTLSVersions  = setOf("1.2", "1.3", "none", "other")
	statsBlockReasons = setOf(dataplane.BlockReasons...)

	statsCountryRE = regexp.MustCompile(`^[A-Z]{2}$`)
	hostLabelRE    = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)
)

func setOf(keys ...string) map[string]bool {
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[k] = true
	}
	return out
}

// statsCountries converts the countries of a minute: "" (unknown) or an
// uppercase ISO 3166-1 alpha-2 code, the heaviest maxStatsCountries by
// requests (ties: the code).
func statsCountries(in map[string]dataplane.CountryCount) []*nodev1.CountryCounter {
	var out []*nodev1.CountryCounter
	for country, c := range in {
		if (country == "" || statsCountryRE.MatchString(country)) && c.Requests > 0 {
			out = append(out, &nodev1.CountryCounter{Country: country, Requests: c.Requests, BytesSent: c.BytesSent})
		}
	}
	slices.SortFunc(out, func(a, b *nodev1.CountryCounter) int {
		return cmp.Or(cmp.Compare(b.Requests, a.Requests), strings.Compare(a.Country, b.Country))
	})
	if len(out) > maxStatsCountries {
		out = out[:maxStatsCountries]
	}
	return out
}

// statsASNs converts the networks of a minute: AS numbers above 0, names
// of at most 128 bytes, the heaviest maxStatsTop (ties: the number).
func statsASNs(in map[string]dataplane.ASNCount) []*nodev1.AsnCounter {
	var out []*nodev1.AsnCounter
	for key, c := range in {
		n, err := strconv.ParseUint(key, 10, 32)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != key || c.Requests == 0 {
			continue
		}
		out = append(out, &nodev1.AsnCounter{Asn: uint32(n), Name: dataplane.Text(c.Name, maxStatsNameBytes), Requests: c.Requests})
	}
	slices.SortFunc(out, func(a, b *nodev1.AsnCounter) int {
		return cmp.Or(cmp.Compare(b.Requests, a.Requests), cmp.Compare(a.Asn, b.Asn))
	})
	if len(out) > maxStatsTop {
		out = out[:maxStatsTop]
	}
	return out
}

// validRefererHost reports whether host is a lowercase host name (labels of
// [a-z0-9_-]) or an IPv4 address of at most 253 bytes.
func validRefererHost(host string) bool {
	if host == "" || len(host) > maxRefererHostSize {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if !hostLabelRE.MatchString(label) {
			return false
		}
	}
	return true
}

// statsReferers converts the referring hosts of a minute (the heaviest
// maxStatsTop valid host names).
func statsReferers(in map[string]uint64) []*nodev1.TopCounter {
	valid := make(map[string]uint64, len(in))
	for host, n := range in {
		if n > 0 && validRefererHost(host) {
			valid[host] = n
		}
	}
	out := topCounters(valid)
	if len(out) == 0 {
		return nil
	}
	return out
}

// statsKeyed keeps the counts of known keys.
func statsKeyed(in map[string]uint64, keys map[string]bool) map[string]uint64 {
	var out map[string]uint64
	for k, n := range in {
		if keys[k] && n > 0 {
			if out == nil {
				out = make(map[string]uint64, len(in))
			}
			out[k] = n
		}
	}
	return out
}

// applyDimensions sets the dimensions of m on out (MinuteStats 14-24).
func applyDimensions(out *nodev1.MinuteStats, m dataplane.MinuteStats) {
	out.Countries = statsCountries(m.Countries)
	out.Asns = statsASNs(m.ASNs)
	out.Referers = statsReferers(m.Referers)
	out.Browsers = statsKeyed(m.Browsers, statsBrowsers)
	out.OperatingSystems = statsKeyed(m.OperatingSystems, statsOSes)
	out.Devices = statsKeyed(m.Devices, statsDevices)
	out.HttpVersions = statsKeyed(m.HTTPVersions, statsHTTPVersions)
	out.TlsVersions = statsKeyed(m.TLSVersions, statsTLSVersions)
	out.BlockReasons = statsKeyed(m.BlockReasons, statsBlockReasons)
	out.ChallengesIssued = m.ChallengesIssued
	out.ChallengesPassed = m.ChallengesPassed
}
