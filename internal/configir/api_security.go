package configir

import (
	"fmt"

	"github.com/marvinli001/edgeweir-node/internal/apisecurity"
)

const FeatureAPISecurity = apisecurity.Feature

func buildAPISecurity(raw string) (*apisecurity.Settings, string, error) {
	s, version, err := apisecurity.Parse(raw)
	if err != nil {
		return nil, "", fmt.Errorf("%w: API security: %v", ErrRejected, err)
	}
	if s == nil {
		return nil, "", nil
	}
	scope := s.JWT.Scope
	if len(scope.Domains) > maxAuthDomains || len(scope.Extensions) > maxAuthExtensions {
		return nil, "", fmt.Errorf("%w: API JWT scope too large", ErrRejected)
	}
	for _, d := range scope.Domains {
		if !validScopeDomain(d) {
			return nil, "", fmt.Errorf("%w: invalid API JWT domain", ErrRejected)
		}
	}
	for _, e := range scope.Extensions {
		if !authExtensionRE.MatchString(e) {
			return nil, "", fmt.Errorf("%w: invalid API JWT extension", ErrRejected)
		}
	}
	if _, err := authPrefixes(scope.PathPrefixes); err != nil {
		return nil, "", err
	}
	if _, err := authPrefixes(scope.ExcludePathPrefixes); err != nil {
		return nil, "", err
	}
	return s, version, nil
}
