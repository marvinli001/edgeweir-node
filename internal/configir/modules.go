package configir

import (
	"fmt"
	"regexp"
	"slices"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// Features of the optional OpenResty modules. They depend on the engine
// binary, not on this agent version: the agent detects them at startup and
// passes them as Options.ExtraFeatures.
const (
	FeatureBrotli      = "brotli-v1"
	FeatureZstd        = "zstd-v1"
	FeatureModSecurity = "modsecurity-v1"
)

// Compression levels (TlsOptions.brotli_level, zstd_level): 0 takes the
// default.
const (
	DefaultBrotliLevel = 6
	MaxBrotliLevel     = 11
	DefaultZstdLevel   = 3
	MaxZstdLevel       = 19
)

// Bounds of SiteWaf (OWASP CRS).
const (
	WAFModeDetect         = "detect"
	WAFModeBlock          = "block"
	MinParanoiaLevel      = 1
	MaxParanoiaLevel      = 4
	MinAnomalyThreshold   = 1
	MaxAnomalyThreshold   = 1000
	MaxWAFBodyLimit       = 128 << 20
	MinWAFRuleID          = 900000
	MaxWAFRuleID          = 999999
	MaxWAFExcludedRuleIDs = 200
)

// mimeTypeRE matches the MIME types of gzip_types, brotli_types and
// zstd_types (rendered into nginx.conf unquoted).
var mimeTypeRE = regexp.MustCompile(`^[a-z0-9.+-]+/[a-z0-9.+-]+$`)

// WAF is a site's OWASP CRS setting (site table field "waf"). The data
// plane sends a site's requests through ModSecurity only when it is set.
type WAF struct {
	// Mode is detect (DetectionOnly: log matches, never block) or block
	// (403 once the inbound anomaly score reaches the threshold).
	Mode             string `json:"mode"`
	ParanoiaLevel    uint32 `json:"paranoia_level"`
	AnomalyThreshold uint32 `json:"anomaly_threshold"`
	// RequestBodyLimit is the number of request body bytes inspected; 0
	// inspects none. Sites with the same limit share a location.
	RequestBodyLimit uint32 `json:"request_body_limit"`
	// ExcludedRuleIDs never run for the site (rendered into the
	// ModSecurity configuration, not the site table).
	ExcludedRuleIDs []uint32 `json:"-"`
	// Exclusions by path or target in the site's order (proto v0.29.0,
	// feature waf-v2).
	Exclusions []WAFExclusion `json:"exclusions,omitempty"`
}

// buildWAF validates a site's SiteWaf; nil means CRS off.
func buildWAF(siteID string, w *nodev1.SiteWaf) (*WAF, error) {
	if w == nil {
		return nil, nil
	}
	out := &WAF{
		Mode:             w.GetMode(),
		ParanoiaLevel:    w.GetParanoiaLevel(),
		AnomalyThreshold: w.GetAnomalyThreshold(),
		RequestBodyLimit: w.GetRequestBodyLimit(),
		ExcludedRuleIDs:  slices.Clone(w.GetExcludedRuleIds()),
	}
	switch {
	case out.Mode != WAFModeDetect && out.Mode != WAFModeBlock:
		return nil, fmt.Errorf("%w: unknown CRS mode %q", ErrRejected, out.Mode)
	case out.ParanoiaLevel < MinParanoiaLevel || out.ParanoiaLevel > MaxParanoiaLevel:
		return nil, fmt.Errorf("%w: CRS paranoia level %d out of range (%d-%d)", ErrRejected, out.ParanoiaLevel, MinParanoiaLevel, MaxParanoiaLevel)
	case out.AnomalyThreshold < MinAnomalyThreshold || out.AnomalyThreshold > MaxAnomalyThreshold:
		return nil, fmt.Errorf("%w: CRS anomaly threshold %d out of range (%d-%d)", ErrRejected, out.AnomalyThreshold, MinAnomalyThreshold, MaxAnomalyThreshold)
	case out.RequestBodyLimit > MaxWAFBodyLimit:
		return nil, fmt.Errorf("%w: CRS request body limit %d exceeds %d", ErrRejected, out.RequestBodyLimit, MaxWAFBodyLimit)
	case len(out.ExcludedRuleIDs) > MaxWAFExcludedRuleIDs:
		return nil, fmt.Errorf("%w: %d excluded CRS rules (at most %d)", ErrRejected, len(out.ExcludedRuleIDs), MaxWAFExcludedRuleIDs)
	}
	for i, id := range out.ExcludedRuleIDs {
		if id < MinWAFRuleID || id > MaxWAFRuleID {
			return nil, fmt.Errorf("%w: excluded CRS rule id %d out of range (%d-%d)", ErrRejected, id, MinWAFRuleID, MaxWAFRuleID)
		}
		if i > 0 && id <= out.ExcludedRuleIDs[i-1] {
			return nil, fmt.Errorf("%w: excluded CRS rule ids must be sorted and unique", ErrRejected)
		}
	}
	var err error
	if out.Exclusions, err = buildWAFExclusions(siteID, w.GetExclusions()); err != nil {
		return nil, err
	}
	return out, nil
}

// buildCompression validates the Brotli and Zstandard settings of tls and
// applies their defaults to out. Levels, minimum lengths and types only
// matter while an algorithm is on.
func buildCompression(tls *nodev1.TlsOptions, out *TLSOptions) error {
	for _, list := range [][]string{tls.GetGzipTypes(), tls.GetBrotliTypes(), tls.GetZstdTypes()} {
		for _, mime := range list {
			if !mimeTypeRE.MatchString(mime) {
				return fmt.Errorf("%w: invalid compression type", ErrRejected)
			}
		}
	}
	if tls.GetBrotliLevel() > MaxBrotliLevel {
		return fmt.Errorf("%w: Brotli level %d out of range (0-%d)", ErrRejected, tls.GetBrotliLevel(), MaxBrotliLevel)
	}
	if tls.GetZstdLevel() > MaxZstdLevel {
		return fmt.Errorf("%w: Zstandard level %d out of range (0-%d)", ErrRejected, tls.GetZstdLevel(), MaxZstdLevel)
	}
	if tls.GetBrotli() {
		out.Brotli = true
		out.BrotliLevel = orDefault(tls.GetBrotliLevel(), DefaultBrotliLevel)
		out.BrotliMinLength = tls.GetBrotliMinLength()
		out.BrotliTypes = slices.Clone(tls.GetBrotliTypes())
	}
	if tls.GetZstd() {
		out.Zstd = true
		out.ZstdLevel = orDefault(tls.GetZstdLevel(), DefaultZstdLevel)
		out.ZstdMinLength = tls.GetZstdMinLength()
		out.ZstdTypes = slices.Clone(tls.GetZstdTypes())
	}
	return nil
}

// requireModules rejects a site that uses a module this node's engine
// lacks. The console requires the matching feature anyway; this names the
// site.
func requireModules(site *Site, extra []string) error {
	need := func(feature, what string) error {
		if slices.Contains(extra, feature) {
			return nil
		}
		return fmt.Errorf("%w: site %q uses %s, but this node's OpenResty has no %s", ErrRejected, site.ID, what, feature)
	}
	if site.TLS != nil && site.TLS.Brotli {
		if err := need(FeatureBrotli, "Brotli"); err != nil {
			return err
		}
	}
	if site.TLS != nil && site.TLS.Zstd {
		if err := need(FeatureZstd, "Zstandard"); err != nil {
			return err
		}
	}
	if site.WAF != nil {
		return need(FeatureModSecurity, "OWASP CRS")
	}
	return nil
}

// UsesWAF reports whether a site of the plan runs the OWASP CRS.
func (p *Plan) UsesWAF() bool {
	return slices.ContainsFunc(p.Sites, func(s Site) bool { return s.WAF != nil })
}

// WAFBodyLimits returns the distinct CRS request body limits of the plan's
// sites in ascending order: the edge layer has one ModSecurity location per
// limit.
func (p *Plan) WAFBodyLimits() []uint32 {
	var limits []uint32
	for _, s := range p.Sites {
		if s.WAF != nil && !slices.Contains(limits, s.WAF.RequestBodyLimit) {
			limits = append(limits, s.WAF.RequestBodyLimit)
		}
	}
	slices.Sort(limits)
	return limits
}
