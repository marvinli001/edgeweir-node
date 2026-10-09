package configir

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// Features of proto v0.29.0 (ADR-0040). FeatureWAFV2: the custom WAF
// actions ban, respond, close and skip, access log lines from log rules,
// rate limit bans, the config rules' CRS override and CRS exclusions by
// path or target (SiteWaf.exclusions). FeatureRulesBody: the request body
// fields, form_value and json_value (Site.rules_body_limit).
// FeatureChallengeV2: verified crawlers (SiteProtection.allow_verified_bots,
// http.request.bot.*), challenge page texts and challenge failure bans.
const (
	FeatureWAFV2       = "waf-v2"
	FeatureRulesBody   = "rules-body-v1"
	FeatureChallengeV2 = "challenge-v2"
)

// Bounds of the CRS exclusion entries (SiteWaf.exclusions).
const (
	MaxWAFExclusions       = 100
	MaxWAFExclusionPath    = 1024
	MaxWAFExclusionTargets = 16
)

// wafTargetRE matches the targets of an exclusion: ARGS and
// REQUEST_COOKIES by a name of [A-Za-z0-9_.-[]], REQUEST_HEADERS by a name
// of [A-Za-z0-9-] (the console's WAF_TARGET_RE).
var wafTargetRE = regexp.MustCompile(`^(?:(?:ARGS|REQUEST_COOKIES):[A-Za-z0-9_.\-\[\]]{1,64}|REQUEST_HEADERS:[A-Za-z0-9-]{1,64})$`)

// crsEvaluationFiles are the CRS rule files whose rules set up or evaluate
// the detection rules (901 initialization, 949 and 959 blocking
// evaluation, 980 correlation): their rules cannot be excluded by path.
var crsEvaluationFiles = map[uint32]bool{901: true, 949: true, 959: true, 980: true}

// WAFExclusion is a CRS exclusion entry of a site (site table field
// "waf.exclusions"): the data plane matches Path against the client's
// normalized path (exact, or as a byte prefix; empty matches every path)
// and hands ModSecurity the tokens of the entries that match in
// X-Edgeweir-Waf-Ex; the generated rules select their entries by Token.
type WAFExclusion struct {
	Path  string `json:"path"`
	Exact bool   `json:"exact,omitempty"`
	Token string `json:"token"`
	// RuleIDs and Targets are rendered into the ModSecurity configuration,
	// not the site table: with targets ctl:ruleRemoveTargetById for every
	// rule and target, else ctl:ruleRemoveById.
	RuleIDs []uint32 `json:"-"`
	Targets []string `json:"-"`
}

// jsSpace reports whether r is whitespace for JavaScript's \s (the
// console's check of exclusion paths).
func jsSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// ValidWAFExclusionPath reports whether path is an exclusion's path: empty
// (every path), or starting with "/", at most 1024 bytes, without "?",
// "#", whitespace or control characters.
func ValidWAFExclusionPath(path string) bool {
	if path == "" {
		return true
	}
	if path[0] != '/' || len(path) > MaxWAFExclusionPath {
		return false
	}
	return !strings.ContainsFunc(path, func(r rune) bool {
		return r <= 32 || r == 127 || r == '?' || r == '#' || jsSpace(r)
	})
}

// WAFExclusionToken returns the token of an exclusion entry: the first 16
// lowercase hex characters of the SHA-256 of its canonical encoding (site
// id, path, exact, rule ids and targets, NUL-separated; none of them holds
// a NUL or a comma). The ModSecurity configuration and the site table carry
// the same value: an entry whose content changed before nginx reloads
// matches no rule until then.
func WAFExclusionToken(siteID, path string, exact bool, ruleIDs []uint32, targets []string) string {
	ids := make([]string, len(ruleIDs))
	for i, id := range ruleIDs {
		ids[i] = strconv.FormatUint(uint64(id), 10)
	}
	flag := "0"
	if exact {
		flag = "1"
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{"edgeweir-waf-exclusion-v1", siteID, path, flag,
		strings.Join(ids, ","), strings.Join(targets, ",")}, "\x00")))
	return hex.EncodeToString(sum[:])[:16]
}

// buildWAFExclusions validates the exclusion entries of a site's CRS
// setting (proto v0.29.0, feature waf-v2): at most 100; paths as
// ValidWAFExclusionPath; 1-200 rule ids, sorted and unique, of the CRS
// detection rules (900000-999999 outside the evaluation files); at most 16
// targets, sorted and unique (wafTargetRE).
func buildWAFExclusions(siteID string, list []*nodev1.WafExclusion) ([]WAFExclusion, error) {
	if len(list) > MaxWAFExclusions {
		return nil, fmt.Errorf("%w: %d CRS exclusions (at most %d)", ErrRejected, len(list), MaxWAFExclusions)
	}
	var out []WAFExclusion
	for i, e := range list {
		ids, targets := e.GetRuleIds(), e.GetTargets()
		switch {
		case !ValidWAFExclusionPath(e.GetPath()):
			return nil, fmt.Errorf("%w: CRS exclusion %d: invalid path", ErrRejected, i+1)
		case len(ids) == 0 || len(ids) > MaxWAFExcludedRuleIDs:
			return nil, fmt.Errorf("%w: CRS exclusion %d: %d rule ids (1-%d)", ErrRejected, i+1, len(ids), MaxWAFExcludedRuleIDs)
		case len(targets) > MaxWAFExclusionTargets:
			return nil, fmt.Errorf("%w: CRS exclusion %d: %d targets (at most %d)", ErrRejected, i+1, len(targets), MaxWAFExclusionTargets)
		}
		for j, id := range ids {
			if id < MinWAFRuleID || id > MaxWAFRuleID || crsEvaluationFiles[id/1000] {
				return nil, fmt.Errorf("%w: CRS exclusion %d: rule id %d is no CRS detection rule", ErrRejected, i+1, id)
			}
			if j > 0 && id <= ids[j-1] {
				return nil, fmt.Errorf("%w: CRS exclusion %d: rule ids must be sorted and unique", ErrRejected, i+1)
			}
		}
		for j, t := range targets {
			if !wafTargetRE.MatchString(t) {
				return nil, fmt.Errorf("%w: CRS exclusion %d: invalid target %q", ErrRejected, i+1, t)
			}
			if j > 0 && t <= targets[j-1] {
				return nil, fmt.Errorf("%w: CRS exclusion %d: targets must be sorted and unique", ErrRejected, i+1)
			}
		}
		out = append(out, WAFExclusion{
			Path: e.GetPath(), Exact: e.GetExact(),
			Token:   WAFExclusionToken(siteID, e.GetPath(), e.GetExact(), ids, targets),
			RuleIDs: append([]uint32(nil), ids...), Targets: append([]string(nil), targets...),
		})
	}
	return out, nil
}

// buildRulesBodyLimit validates Site.rules_body_limit (rules-body-v1): 0
// (the default, 65536) or 1024-1048576.
func buildRulesBodyLimit(s *nodev1.Site) (uint32, error) {
	limit := s.GetRulesBodyLimit()
	if limit != 0 && (limit < minRulesBodyLimit || limit > maxRulesBodyLimit) {
		return 0, fmt.Errorf("%w: rules body limit %d out of range (%d-%d)", ErrRejected, limit, minRulesBodyLimit, maxRulesBodyLimit)
	}
	return limit, nil
}
