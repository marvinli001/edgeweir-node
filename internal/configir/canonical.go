// Package configir handles the engine-agnostic NodeConfig IR on the node:
// canonical ordering, content hashing, diff application and validation into
// a Plan that the data plane renderers consume.
//
// The canonical form and hash are defined in edgeweir/proto
// (edgeweir/node/v1/config.proto) and implemented identically by the
// console (protobuf-es) and the node (protobuf-go):
//
//   - listeners sorted by port, cache_zones by name, sites by id,
//     certificates by id; origin_allowed_cidrs sorted ascending (byte
//     order) with duplicates removed (proto v0.2.1);
//   - inside a site: domains by name, origins by id, cache_rules by
//     (priority, id);
//   - challenge_keys by id (proto v0.10.0);
//   - inside a site: tls.gzip_types ascending without duplicates, and
//     likewise tls.brotli_types, tls.zstd_types and waf.excluded_rule_ids
//     (proto v0.11.0);
//   - offline_hosts by (name, wildcard), inside a site error_pages.pages
//     by status (proto v0.12.0);
//   - inside a site bulk_redirects by source; inside the action of every
//     platform and site rule set_query by name and remove_query ascending
//     (proto v0.13.0);
//   - l4_apps by id, inside an application origins by id and
//     allow_list_ids / block_list_ids ascending without duplicates (proto
//     v0.15.0; the console sorts the list ids as sets too);
//   - inside a site ports and tls.redirect_excluded_domains ascending,
//     client_address.trusted_cidrs ascending without duplicates (proto
//     v0.23.0);
//   - inside a cache zone node_sizes by node_id, inside a site's
//     maintenance allowed_cidrs and allowed_path_prefixes ascending without
//     duplicates (proto v0.24.0);
//   - content_hash = lowercase hex SHA-256 of the deterministic binary
//     encoding with revision and content_hash cleared.
//
// Both protobuf runtimes emit known fields in field-number order and omit
// proto3 default values, and NodeConfig contains no map fields, so the
// encodings are byte-identical. Cross-language vectors live in
// testdata/content_hash_vector*.json.
package configir

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// ErrHashMismatch is returned when a computed content hash differs from the
// hash announced by the console.
var ErrHashMismatch = errors.New("content hash mismatch")

// Canonicalize sorts every repeated field of c in place into canonical
// order. Sorting is stable so that ties keep the console's order.
func Canonicalize(c *nodev1.NodeConfig) {
	if c == nil {
		return
	}
	slices.SortStableFunc(c.Listeners, func(a, b *nodev1.Listener) int {
		return cmp.Compare(a.GetPort(), b.GetPort())
	})
	slices.SortStableFunc(c.CacheZones, func(a, b *nodev1.CacheZone) int {
		return cmp.Compare(a.GetName(), b.GetName())
	})
	for _, z := range c.CacheZones {
		slices.SortStableFunc(z.NodeSizes, func(a, b *nodev1.CacheZoneNodeSize) int {
			return cmp.Compare(a.GetNodeId(), b.GetNodeId())
		})
	}
	slices.SortStableFunc(c.Certificates, func(a, b *nodev1.CertificateRef) int {
		return cmp.Compare(a.GetId(), b.GetId())
	})
	slices.SortStableFunc(c.Sites, func(a, b *nodev1.Site) int {
		return cmp.Compare(a.GetId(), b.GetId())
	})
	// Go compares strings byte by byte, which is the canonical order.
	slices.Sort(c.OriginAllowedCidrs)
	c.OriginAllowedCidrs = slices.Compact(c.OriginAllowedCidrs)
	slices.Sort(c.RequiredFeatures)
	c.RequiredFeatures = slices.Compact(c.RequiredFeatures)
	slices.SortStableFunc(c.HttpChallenges, func(a, b *nodev1.HttpChallenge) int {
		return cmp.Compare(a.GetDomain()+"/"+a.GetToken(), b.GetDomain()+"/"+b.GetToken())
	})
	slices.SortStableFunc(c.IpLists, func(a, b *nodev1.IpList) int { return cmp.Compare(a.GetId(), b.GetId()) })
	slices.SortStableFunc(c.ChallengeKeys, func(a, b *nodev1.ChallengeKeyRef) int { return cmp.Compare(a.GetId(), b.GetId()) })
	// The console sorts by `${name}\0${wildcard ? 1 : 0}\0${match}`: name
	// first, then exact before wildcard, then the match (v0.25.0).
	slices.SortStableFunc(c.OfflineHosts, func(a, b *nodev1.OfflineHost) int {
		return cmp.Or(cmp.Compare(a.GetName(), b.GetName()), compareBool(a.GetWildcard(), b.GetWildcard()),
			cmp.Compare(a.GetMatch(), b.GetMatch()))
	})
	for _, l := range c.IpLists {
		slices.Sort(l.Entries)
		l.Entries = slices.Compact(l.Entries)
	}
	if ca := c.ClientAddress; ca != nil {
		slices.Sort(ca.TrustedCidrs)
		ca.TrustedCidrs = slices.Compact(ca.TrustedCidrs)
	}
	slices.SortStableFunc(c.L4Apps, func(a, b *nodev1.L4App) int { return cmp.Compare(a.GetId(), b.GetId()) })
	for _, a := range c.L4Apps {
		slices.SortStableFunc(a.Origins, func(x, y *nodev1.L4Origin) int { return cmp.Compare(x.GetId(), y.GetId()) })
		slices.Sort(a.AllowListIds)
		a.AllowListIds = slices.Compact(a.AllowListIds)
		slices.Sort(a.BlockListIds)
		a.BlockListIds = slices.Compact(a.BlockListIds)
	}
	canonicalizeRules(c.PlatformRules)
	for _, s := range c.Sites {
		CanonicalizeSite(s)
	}
}

// CanonicalizeSite sorts the repeated fields inside a site.
func CanonicalizeSite(s *nodev1.Site) {
	if s == nil {
		return
	}
	slices.Sort(s.Ports)
	s.Ports = slices.Compact(s.Ports)
	if s.Tls != nil {
		slices.Sort(s.Tls.RedirectExcludedDomains)
		s.Tls.RedirectExcludedDomains = slices.Compact(s.Tls.RedirectExcludedDomains)
		slices.Sort(s.Tls.GzipTypes)
		s.Tls.GzipTypes = slices.Compact(s.Tls.GzipTypes)
		slices.Sort(s.Tls.BrotliTypes)
		s.Tls.BrotliTypes = slices.Compact(s.Tls.BrotliTypes)
		slices.Sort(s.Tls.ZstdTypes)
		s.Tls.ZstdTypes = slices.Compact(s.Tls.ZstdTypes)
	}
	if s.Waf != nil {
		slices.Sort(s.Waf.ExcludedRuleIds)
		s.Waf.ExcludedRuleIds = slices.Compact(s.Waf.ExcludedRuleIds)
	}
	if s.ErrorPages != nil {
		slices.SortStableFunc(s.ErrorPages.Pages, func(a, b *nodev1.ErrorPage) int {
			return cmp.Compare(a.GetStatus(), b.GetStatus())
		})
	}
	if m := s.Maintenance; m != nil {
		slices.Sort(m.AllowedCidrs)
		m.AllowedCidrs = slices.Compact(m.AllowedCidrs)
		slices.Sort(m.AllowedPathPrefixes)
		m.AllowedPathPrefixes = slices.Compact(m.AllowedPathPrefixes)
	}
	// By (name, wildcard, match) like offline hosts (v0.25.0).
	slices.SortStableFunc(s.Domains, func(a, b *nodev1.Domain) int {
		return cmp.Or(cmp.Compare(a.GetName(), b.GetName()), compareBool(a.GetWildcard(), b.GetWildcard()),
			cmp.Compare(a.GetMatch(), b.GetMatch()))
	})
	if p := s.GetOriginPool(); p != nil {
		slices.SortStableFunc(p.Origins, func(a, b *nodev1.Origin) int {
			return cmp.Compare(a.GetId(), b.GetId())
		})
	}
	slices.SortStableFunc(s.CacheRules, func(a, b *nodev1.CacheRule) int {
		return cmp.Or(
			cmp.Compare(a.GetPriority(), b.GetPriority()),
			cmp.Compare(a.GetId(), b.GetId()),
		)
	})
	slices.SortStableFunc(s.BulkRedirects, func(a, b *nodev1.BulkRedirect) int {
		return cmp.Compare(a.GetSource(), b.GetSource())
	})
	canonicalizeRules(s.Rules)
}

// canonicalizeRules sorts the query edits of the rules' actions. The rules
// themselves keep their order (execution order inside a phase).
func canonicalizeRules(rules []*nodev1.EdgeRule) {
	for _, r := range rules {
		if a := r.GetAction(); a != nil {
			slices.SortStableFunc(a.SetQuery, func(x, y *nodev1.QueryParam) int {
				return cmp.Compare(x.GetName(), y.GetName())
			})
			slices.Sort(a.RemoveQuery)
		}
	}
}

// compareBool orders false before true.
func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	}
	return 1
}

// CanonicalBytes returns the deterministic binary encoding of the canonical
// form of c with revision and content_hash cleared. c is not modified.
func CanonicalBytes(c *nodev1.NodeConfig) ([]byte, error) {
	if c == nil {
		c = &nodev1.NodeConfig{}
	}
	clone := proto.CloneOf(c)
	clone.Revision = 0
	clone.ContentHash = ""
	Canonicalize(clone)
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	return b, nil
}

// ContentHash computes the content hash of c (see package docs).
func ContentHash(c *nodev1.NodeConfig) (string, error) {
	b, err := CanonicalBytes(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// VerifyHash checks that c.content_hash matches its content.
func VerifyHash(c *nodev1.NodeConfig) error {
	got, err := ContentHash(c)
	if err != nil {
		return err
	}
	if c.GetContentHash() == "" {
		return fmt.Errorf("%w: revision %d has no content_hash (computed %s)", ErrHashMismatch, c.GetRevision(), got)
	}
	if got != c.GetContentHash() {
		return fmt.Errorf("%w: revision %d announces %s, computed %s", ErrHashMismatch, c.GetRevision(), c.GetContentHash(), got)
	}
	return nil
}
