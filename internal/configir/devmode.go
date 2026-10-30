package configir

import (
	"fmt"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// FeatureDevelopmentMode (proto/v1.9.0): Site.development_mode,
// the edge cache of the site bypassed until a deadline on the node's clock
// (edgeweir.router). Required while a site has it.
const FeatureDevelopmentMode = "development-mode-v1"

// buildDevelopmentMode returns the Unix second at which a site's
// development mode ends, 0 without one; development mode without an end
// rejects the configuration.
func buildDevelopmentMode(s *nodev1.Site) (int64, error) {
	d := s.GetDevelopmentMode()
	if d == nil {
		return 0, nil
	}
	end := d.GetExpiresAt()
	if end == nil || !end.IsValid() || end.GetSeconds() <= 0 {
		return 0, fmt.Errorf("%w: development mode without a valid end", ErrRejected)
	}
	return end.GetSeconds(), nil
}
