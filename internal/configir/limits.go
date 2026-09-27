package configir

import (
	"encoding/hex"
	"fmt"
)

const (
	RateLimitDictPrefix = "edgeweir_rate_"
	RateLimitSiteKB     = 256
	MaxPublishedSites   = 512
	RateLimitBudgetKB   = RateLimitSiteKB * MaxPublishedSites
)

// RateLimitDictName is also implemented by edgeweir.ratelimit.dict_name.
// Hex is reversible, so distinct validated IDs cannot share a dictionary.
func RateLimitDictName(siteID string) (string, error) {
	if !idRE.MatchString(siteID) {
		return "", fmt.Errorf("%w: invalid rate-limit site ID", ErrRejected)
	}
	return RateLimitDictPrefix + hex.EncodeToString([]byte(siteID)), nil
}
