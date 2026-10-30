package configir

import (
	"fmt"
	"regexp"
	"strings"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// FeatureSessionDetection (proto vNEXT, ADR-0068): Site.session_detection,
// the session script and cookie under /.edgeweir/session/, the bot score
// fields http.request.bot.score / automated, AccessLog.bot_score and
// MinuteStats.bot_scores.
const FeatureSessionDetection = "session-detection-v1"

// MaxInterstitialRules bounds SessionDetection.interstitial_rules.
const MaxInterstitialRules = 32

// SessionDetection is a site's session detection (site table field
// "session_detection"; lua/edgeweir/session.lua): Mode "monitor" or
// "enforce", the site's Interstitial default and its Rules in order.
type SessionDetection struct {
	Mode         string             `json:"mode"`
	Interstitial bool               `json:"interstitial,omitempty"`
	Rules        []InterstitialRule `json:"rules,omitempty"`
}

// InterstitialRule overrides the interstitial for a host ("" any,
// "*.example.com" one label below) and a path prefix ("" any).
type InterstitialRule struct {
	Host         string `json:"host,omitempty"`
	PathPrefix   string `json:"path_prefix,omitempty"`
	Interstitial bool   `json:"interstitial"`
}

var (
	ldhHostRE  = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	pathPrefix = regexp.MustCompile(`^/[\x21-\x7e]{0,255}$`)
)

// validInterstitialHost mirrors the console's validInterstitialHost.
func validInterstitialHost(h string) bool {
	if h == "" {
		return true
	}
	h = strings.TrimPrefix(h, "*.")
	return len(h) <= 253 && ldhHostRE.MatchString(h)
}

// buildSessionDetection validates Site.session_detection (nil: off).
func buildSessionDetection(s *nodev1.Site) (*SessionDetection, error) {
	d := s.GetSessionDetection()
	if d == nil {
		return nil, nil
	}
	if d.GetMode() != "monitor" && d.GetMode() != "enforce" {
		return nil, fmt.Errorf("%w: unknown session detection mode", ErrRejected)
	}
	if len(d.GetInterstitialRules()) > MaxInterstitialRules {
		return nil, fmt.Errorf("%w: more than %d interstitial rules", ErrRejected, MaxInterstitialRules)
	}
	out := &SessionDetection{Mode: d.GetMode(), Interstitial: d.GetInterstitial()}
	for _, r := range d.GetInterstitialRules() {
		if !validInterstitialHost(r.GetHost()) {
			return nil, fmt.Errorf("%w: invalid interstitial rule host", ErrRejected)
		}
		if p := r.GetPathPrefix(); p != "" && !pathPrefix.MatchString(p) {
			return nil, fmt.Errorf("%w: invalid interstitial rule path prefix", ErrRejected)
		}
		out.Rules = append(out.Rules, InterstitialRule{Host: r.GetHost(), PathPrefix: r.GetPathPrefix(), Interstitial: r.GetInterstitial()})
	}
	return out, nil
}
