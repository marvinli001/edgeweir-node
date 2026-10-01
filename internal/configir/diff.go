package configir

import (
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// ErrBaseMismatch is returned when a diff does not apply to the local base.
var ErrBaseMismatch = errors.New("diff base revision mismatch")

// ApplyDiff transforms base (the locally applied config) into the target
// revision described by d:
//
//   - listeners, cache zones, certificates, the origin allow list, the
//     platform protection, the challenge keys, the platform error pages,
//     the offline hosts and the layer-4 applications are replaced
//     wholesale;
//   - sites listed in removed_site_ids are dropped;
//   - upserted sites replace sites with the same id or are added;
//   - the result is canonicalized and its content hash must equal
//     d.content_hash.
//
// base is not modified. On any error the caller must fall back to a full
// snapshot.
func ApplyDiff(base *nodev1.NodeConfig, d *nodev1.NodeConfigDiff) (*nodev1.NodeConfig, error) {
	if base == nil {
		return nil, fmt.Errorf("%w: no local base config", ErrBaseMismatch)
	}
	if d == nil {
		return nil, errors.New("nil diff")
	}
	if d.GetBaseRevision() != base.GetRevision() {
		return nil, fmt.Errorf("%w: diff is against revision %d, local revision is %d",
			ErrBaseMismatch, d.GetBaseRevision(), base.GetRevision())
	}
	if base.GetClusterId() != "" && d.GetClusterId() != "" && base.GetClusterId() != d.GetClusterId() {
		return nil, fmt.Errorf("%w: diff is for cluster %q, local config for %q",
			ErrBaseMismatch, d.GetClusterId(), base.GetClusterId())
	}

	out := &nodev1.NodeConfig{
		Revision:     d.GetRevision(),
		ContentHash:  d.GetContentHash(),
		ClusterId:    d.GetClusterId(),
		Listeners:    cloneAll(d.GetListeners()),
		CacheZones:   cloneAll(d.GetCacheZones()),
		Certificates: cloneAll(d.GetCertificates()),
		// A v0.2.0 console never sends the allow list: the target has none.
		OriginAllowedCidrs: slices.Clone(d.GetOriginAllowedCidrs()),
		RequiredFeatures:   slices.Clone(d.GetRequiredFeatures()),
		HttpChallenges:     cloneAll(d.GetHttpChallenges()),
		IpLists:            cloneAll(d.GetIpLists()),
		PlatformRules:      cloneAll(d.GetPlatformRules()),
		ChallengeKeys:      cloneAll(d.GetChallengeKeys()),
		OfflineHosts:       cloneAll(d.GetOfflineHosts()),
		L4Apps:             cloneAll(d.GetL4Apps()),
	}
	if p := d.GetPlatformProtection(); p != nil {
		out.PlatformProtection = proto.CloneOf(p)
	}
	if p := d.GetPlatformErrorPages(); p != nil {
		out.PlatformErrorPages = proto.CloneOf(p)
	}
	removed := make(map[string]bool, len(d.GetRemovedSiteIds()))
	for _, id := range d.GetRemovedSiteIds() {
		removed[id] = true
	}
	index := make(map[string]int, len(base.GetSites()))
	for _, s := range base.GetSites() {
		if removed[s.GetId()] {
			continue
		}
		index[s.GetId()] = len(out.Sites)
		out.Sites = append(out.Sites, proto.CloneOf(s))
	}
	for _, s := range d.GetUpsertedSites() {
		c := proto.CloneOf(s)
		if i, ok := index[s.GetId()]; ok {
			out.Sites[i] = c
			continue
		}
		index[s.GetId()] = len(out.Sites)
		out.Sites = append(out.Sites, c)
	}
	Canonicalize(out)

	got, err := ContentHash(out)
	if err != nil {
		return nil, err
	}
	if got != d.GetContentHash() {
		return nil, fmt.Errorf("%w: diff %d->%d announces %s, computed %s",
			ErrHashMismatch, d.GetBaseRevision(), d.GetRevision(), d.GetContentHash(), got)
	}
	return out, nil
}

// Diff computes the diff that transforms base into target. The node never
// needs it at runtime; it exists for tests and the fake console, and
// documents the exact semantics ApplyDiff expects.
func Diff(base, target *nodev1.NodeConfig) *nodev1.NodeConfigDiff {
	d := &nodev1.NodeConfigDiff{
		BaseRevision:       base.GetRevision(),
		Revision:           target.GetRevision(),
		ContentHash:        target.GetContentHash(),
		ClusterId:          target.GetClusterId(),
		Listeners:          cloneAll(target.GetListeners()),
		CacheZones:         cloneAll(target.GetCacheZones()),
		Certificates:       cloneAll(target.GetCertificates()),
		OriginAllowedCidrs: slices.Clone(target.GetOriginAllowedCidrs()),
		RequiredFeatures:   slices.Clone(target.GetRequiredFeatures()),
		HttpChallenges:     cloneAll(target.GetHttpChallenges()),
		IpLists:            cloneAll(target.GetIpLists()),
		PlatformRules:      cloneAll(target.GetPlatformRules()),
		ChallengeKeys:      cloneAll(target.GetChallengeKeys()),
		OfflineHosts:       cloneAll(target.GetOfflineHosts()),
		L4Apps:             cloneAll(target.GetL4Apps()),
	}
	if p := target.GetPlatformProtection(); p != nil {
		d.PlatformProtection = proto.CloneOf(p)
	}
	if p := target.GetPlatformErrorPages(); p != nil {
		d.PlatformErrorPages = proto.CloneOf(p)
	}
	old := make(map[string]*nodev1.Site, len(base.GetSites()))
	for _, s := range base.GetSites() {
		old[s.GetId()] = s
	}
	seen := make(map[string]bool, len(target.GetSites()))
	for _, s := range target.GetSites() {
		seen[s.GetId()] = true
		if prev, ok := old[s.GetId()]; !ok || !proto.Equal(prev, s) {
			d.UpsertedSites = append(d.UpsertedSites, proto.CloneOf(s))
		}
	}
	for _, s := range base.GetSites() {
		if !seen[s.GetId()] {
			d.RemovedSiteIds = append(d.RemovedSiteIds, s.GetId())
		}
	}
	slices.Sort(d.RemovedSiteIds)
	return d
}

func cloneAll[M proto.Message](in []M) []M {
	if len(in) == 0 {
		return nil
	}
	out := make([]M, len(in))
	for i, m := range in {
		out[i] = proto.CloneOf(m)
	}
	return out
}
