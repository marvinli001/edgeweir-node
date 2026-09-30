package configir

import (
	"fmt"
	"slices"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// Challenge types, in rising strength; the level of a type is its index + 1
// (lua/edgeweir/challenge.lua uses the same order).
var ChallengeTypes = []string{"cookie302", "js", "pow", "captcha"}

// Defaults and bounds of SiteProtection and CcPolicy. A zero value takes the
// default; any other value outside its range rejects the configuration.
const (
	DefaultPassTTL         = 1800
	MinPassTTL             = 300
	MaxPassTTL             = 86400
	DefaultPoW             = 16
	MinPoW                 = 8
	MaxPoW                 = 24
	DefaultPoWHigh         = 20
	MaxPoWHigh             = 26
	DefaultCCWindow        = 10
	MinCCWindow            = 5
	MaxCCWindow            = 60
	DefaultIPBan           = 600
	MinIPBan               = 60
	MaxIPBan               = 86400
	DefaultEscalateSeconds = 10
	MaxEscalateSeconds     = 3600
	DefaultCooldownSeconds = 60
	MaxCooldownSeconds     = 86400
	// MaxCCRate bounds the request-per-second thresholds and the minimum
	// origin request count.
	MaxCCRate = 10_000_000
)

// Challenge key roles: nodes sign with current and accept all three.
const (
	KeyRoleNext     = "next"
	KeyRoleCurrent  = "current"
	KeyRolePrevious = "previous"
)

// Protection is a site's challenge and CC mitigation settings with the
// defaults applied (site table field "protection").
type Protection struct {
	UnderAttack bool `json:"under_attack,omitempty"`
	// UnderAttackChallenge is the challenge type of Under Attack.
	UnderAttackChallenge string `json:"under_attack_challenge"`
	// PassTTL is the lifetime of a pass in seconds.
	PassTTL uint32 `json:"pass_ttl"`
	// PoW and PoWHigh are the leading zero bits of the proof of work and
	// of the high-difficulty proof of work (captcha alternative).
	PoW     uint32 `json:"pow"`
	PoWHigh uint32 `json:"pow_high"`
	LogJA4  bool   `json:"log_ja4,omitempty"`
	// CC is set only when the policy is enabled.
	CC *CCPolicy `json:"cc,omitempty"`
}

// CCPolicy is an enabled CC mitigation policy with the defaults applied.
// Thresholds of 0 disable their trigger.
type CCPolicy struct {
	MaxLevel               string `json:"max_level"`
	HighPoW                bool   `json:"high_pow,omitempty"`
	WindowSeconds          uint32 `json:"window"`
	SiteQPS                uint32 `json:"site_qps"`
	URLQPS                 uint32 `json:"url_qps"`
	IPQPS                  uint32 `json:"ip_qps"`
	IPBanSeconds           uint32 `json:"ip_ban"`
	OriginErrorPercent     uint32 `json:"error_percent"`
	OriginErrorMinRequests uint32 `json:"error_min_requests"`
	EscalateSeconds        uint32 `json:"escalate"`
	CooldownSeconds        uint32 `json:"cooldown"`
}

// PlatformProtection is the platform-wide Under Attack (site table field
// "platform_protection").
type PlatformProtection struct {
	UnderAttack bool   `json:"under_attack"`
	Challenge   string `json:"challenge"`
}

// ChallengeKeyRef names one challenge pass key of the cluster and its role.
type ChallengeKeyRef struct {
	ID   string
	Role string
}

// challengeType validates a challenge type; "" takes def.
func challengeType(v, def, what string) (string, error) {
	if v == "" {
		return def, nil
	}
	if !slices.Contains(ChallengeTypes, v) {
		return "", fmt.Errorf("%w: unsupported %s %q", ErrRejected, what, v)
	}
	return v, nil
}

// ranged validates a number: 0 takes def, anything else must be in [lo, hi].
func ranged(v, def, lo, hi uint32, what string) (uint32, error) {
	if v == 0 {
		return def, nil
	}
	if v < lo || v > hi {
		return 0, fmt.Errorf("%w: %s %d out of range (%d-%d)", ErrRejected, what, v, lo, hi)
	}
	return v, nil
}

// buildProtection validates a site's protection; nil stays nil.
func buildProtection(p *nodev1.SiteProtection) (*Protection, error) {
	if p == nil {
		return nil, nil
	}
	out := &Protection{UnderAttack: p.GetUnderAttack(), LogJA4: p.GetLogJa4()}
	var err error
	if out.UnderAttackChallenge, err = challengeType(p.GetUnderAttackChallenge(), "js", "Under Attack challenge"); err != nil {
		return nil, err
	}
	if out.PassTTL, err = ranged(p.GetPassTtlSeconds(), DefaultPassTTL, MinPassTTL, MaxPassTTL, "pass lifetime"); err != nil {
		return nil, err
	}
	if out.PoW, err = ranged(p.GetPowDifficulty(), DefaultPoW, MinPoW, MaxPoW, "proof-of-work difficulty"); err != nil {
		return nil, err
	}
	if out.PoWHigh, err = ranged(p.GetPowHighDifficulty(), max(DefaultPoWHigh, out.PoW), MinPoW, MaxPoWHigh, "high proof-of-work difficulty"); err != nil {
		return nil, err
	}
	if out.PoWHigh < out.PoW {
		return nil, fmt.Errorf("%w: high proof-of-work difficulty %d below the difficulty %d", ErrRejected, out.PoWHigh, out.PoW)
	}
	cc := p.GetCc()
	if cc == nil {
		return out, nil
	}
	policy := &CCPolicy{
		HighPoW:                cc.GetHighPowInsteadOfCaptcha(),
		SiteQPS:                cc.GetSiteQps(),
		URLQPS:                 cc.GetUrlQps(),
		IPQPS:                  cc.GetIpQps(),
		OriginErrorPercent:     cc.GetOriginErrorPercent(),
		OriginErrorMinRequests: cc.GetOriginErrorMinRequests(),
	}
	if policy.MaxLevel, err = challengeType(cc.GetMaxLevel(), "captcha", "CC maximum level"); err != nil {
		return nil, err
	}
	if policy.WindowSeconds, err = ranged(cc.GetWindowSeconds(), DefaultCCWindow, MinCCWindow, MaxCCWindow, "CC window"); err != nil {
		return nil, err
	}
	if policy.IPBanSeconds, err = ranged(cc.GetIpBanSeconds(), DefaultIPBan, MinIPBan, MaxIPBan, "CC ban duration"); err != nil {
		return nil, err
	}
	if policy.EscalateSeconds, err = ranged(cc.GetEscalateAfterSeconds(), DefaultEscalateSeconds, 1, MaxEscalateSeconds, "CC escalation time"); err != nil {
		return nil, err
	}
	if policy.CooldownSeconds, err = ranged(cc.GetCooldownSeconds(), DefaultCooldownSeconds, 1, MaxCooldownSeconds, "CC cooldown"); err != nil {
		return nil, err
	}
	if policy.OriginErrorPercent > 100 {
		return nil, fmt.Errorf("%w: CC origin error rate %d%% out of range (0-100)", ErrRejected, policy.OriginErrorPercent)
	}
	for what, v := range map[string]uint32{"site QPS": policy.SiteQPS, "URL QPS": policy.URLQPS, "IP QPS": policy.IPQPS, "origin error minimum requests": policy.OriginErrorMinRequests} {
		if v > MaxCCRate {
			return nil, fmt.Errorf("%w: CC %s %d out of range (0-%d)", ErrRejected, what, v, MaxCCRate)
		}
	}
	if cc.GetEnabled() {
		out.CC = policy
	}
	return out, nil
}

// buildPlatformProtection validates the platform-wide Under Attack.
func buildPlatformProtection(p *nodev1.PlatformProtection) (*PlatformProtection, error) {
	if p == nil {
		return nil, nil
	}
	challenge, err := challengeType(p.GetUnderAttackChallenge(), "js", "platform Under Attack challenge")
	if err != nil {
		return nil, err
	}
	return &PlatformProtection{UnderAttack: p.GetUnderAttack(), Challenge: challenge}, nil
}

// buildChallengeKeys validates the key references: ids like other ids, at
// most one key per role and exactly one current key.
func buildChallengeKeys(keys []*nodev1.ChallengeKeyRef) ([]ChallengeKeyRef, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	ids, roles := map[string]bool{}, map[string]bool{}
	out := make([]ChallengeKeyRef, 0, len(keys))
	for _, k := range keys {
		role := k.GetRole()
		switch {
		case !idRE.MatchString(k.GetId()) || ids[k.GetId()]:
			return nil, fmt.Errorf("%w: invalid or duplicate challenge key id %q", ErrRejected, k.GetId())
		case role != KeyRoleNext && role != KeyRoleCurrent && role != KeyRolePrevious:
			return nil, fmt.Errorf("%w: unsupported challenge key role %q", ErrRejected, role)
		case roles[role]:
			return nil, fmt.Errorf("%w: more than one %s challenge key", ErrRejected, role)
		}
		ids[k.GetId()], roles[role] = true, true
		out = append(out, ChallengeKeyRef{ID: k.GetId(), Role: role})
	}
	if !roles[KeyRoleCurrent] {
		return nil, fmt.Errorf("%w: challenge keys without a current key", ErrRejected)
	}
	return out, nil
}

// ChallengeKeyIDs returns the ids of the plan's challenge keys.
func (p *Plan) ChallengeKeyIDs() []string {
	out := make([]string, 0, len(p.ChallengeKeys))
	for _, k := range p.ChallengeKeys {
		out = append(out, k.ID)
	}
	return out
}

// CurrentChallengeKey returns the id of the signing key ("" without keys).
func (p *Plan) CurrentChallengeKey() string {
	for _, k := range p.ChallengeKeys {
		if k.Role == KeyRoleCurrent {
			return k.ID
		}
	}
	return ""
}
