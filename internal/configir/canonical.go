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
	for _, l := range c.IpLists {
		slices.Sort(l.Entries)
		l.Entries = slices.Compact(l.Entries)
	}
	for _, s := range c.Sites {
		CanonicalizeSite(s)
	}
}

// CanonicalizeSite sorts the repeated fields inside a site.
func CanonicalizeSite(s *nodev1.Site) {
	if s != nil && s.Tls != nil {
		slices.Sort(s.Tls.GzipTypes)
		s.Tls.GzipTypes = slices.Compact(s.Tls.GzipTypes)
	}
	if s == nil {
		return
	}
	slices.SortStableFunc(s.Domains, func(a, b *nodev1.Domain) int {
		return cmp.Compare(a.GetName(), b.GetName())
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
