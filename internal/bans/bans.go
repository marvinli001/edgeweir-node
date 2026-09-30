// Package bans holds the dynamic IP bans the console distributes outside
// configuration revisions (GetBans).
//
// The agent keeps the console's bans and the sequence it has applied in
// memory and in <state-dir>/bans.json (0600), applies GetBans pages to them
// (a reset page drops every ban first) and pushes the result to the data
// plane (lua/edgeweir/bans.lua) and, for platform bans, to nftables.
// Bans the node creates itself (automatic mitigation) live only in the
// data plane until they are reported with ReportBans.
package bans

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// File is the name of the persisted state inside the state directory.
const File = "bans.json"

// Minimum prefix lengths: shorter prefixes are refused (the console
// enforces the same bounds).
const (
	MinBitsIPv4 = 16
	MinBitsIPv6 = 48
)

// MaxLifetime bounds how far in the future a ban may expire (the console
// allows 1 minute to 7 days).
const MaxLifetime = 7 * 24 * time.Hour

// Scope is where a ban applies.
type Scope string

// Scopes.
const (
	ScopePlatform Scope = "platform" // every site; also enforced by nftables
	ScopeSite     Scope = "site"     // one site, at the edge layer only
)

// Source tells who created a ban.
type Source string

// Sources.
const (
	SourceManual Source = "manual" // an operator or a tenant
	SourceAuto   Source = "auto"   // a node's automatic mitigation
)

// Ban is one console ban.
type Ban struct {
	ID string `json:"id"`
	// Prefix is canonical: host bits zero, IPv4-mapped addresses unmapped.
	Prefix    netip.Prefix `json:"cidr"`
	Scope     Scope        `json:"scope"`
	SiteID    string       `json:"site_id,omitempty"`
	Source    Source       `json:"source"`
	Reason    string       `json:"reason,omitempty"`
	CreatedAt time.Time    `json:"created_at"`
	ExpiresAt time.Time    `json:"expires_at"`
}

// Manual reports whether the ban was created by a person (manual bans are
// never dropped for capacity).
func (b Ban) Manual() bool { return b.Source != SourceAuto }

// idRE matches ban and site ids: they are part of data plane keys.
var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// ValidID reports whether id can be used as a ban or site id.
func ValidID(id string) bool { return idRE.MatchString(id) }

// ParsePrefix parses a ban CIDR and returns it in canonical form. It
// refuses prefixes shorter than MinBitsIPv4 / MinBitsIPv6.
func ParsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return Canonical(p)
}

// Canonical masks p, unmaps IPv4-mapped IPv6 prefixes and checks the
// minimum prefix length.
func Canonical(p netip.Prefix) (netip.Prefix, error) {
	if !p.IsValid() {
		return netip.Prefix{}, errors.New("invalid prefix")
	}
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	p = p.Masked()
	minBits := MinBitsIPv6
	if p.Addr().Is4() {
		minBits = MinBitsIPv4
	}
	if p.Bits() < minBits {
		return netip.Prefix{}, fmt.Errorf("prefix %s is shorter than /%d", p, minBits)
	}
	return p, nil
}

// FromProto validates a console ban.
func FromProto(pb *nodev1.Ban) (Ban, error) {
	b := Ban{ID: pb.GetId(), SiteID: pb.GetSiteId(), Reason: pb.GetReason()}
	if !ValidID(b.ID) {
		return Ban{}, fmt.Errorf("invalid ban id %q", truncate(b.ID))
	}
	p, err := ParsePrefix(pb.GetCidr())
	if err != nil {
		return Ban{}, fmt.Errorf("ban %s: invalid cidr %q: %w", b.ID, truncate(pb.GetCidr()), err)
	}
	b.Prefix = p
	switch pb.GetScope() {
	case nodev1.BanScope_BAN_SCOPE_PLATFORM:
		b.Scope, b.SiteID = ScopePlatform, ""
	case nodev1.BanScope_BAN_SCOPE_SITE:
		b.Scope = ScopeSite
		if !ValidID(b.SiteID) {
			return Ban{}, fmt.Errorf("ban %s: invalid site id %q", b.ID, truncate(b.SiteID))
		}
	default:
		return Ban{}, fmt.Errorf("ban %s: unsupported scope %v", b.ID, pb.GetScope())
	}
	// Unknown sources are treated like manual bans: they are never dropped
	// to make room.
	b.Source = SourceManual
	if pb.GetSource() == nodev1.BanSource_BAN_SOURCE_AUTO {
		b.Source = SourceAuto
	}
	if pb.GetExpiresAt() == nil || !pb.GetExpiresAt().IsValid() {
		return Ban{}, fmt.Errorf("ban %s: no expiry", b.ID)
	}
	b.ExpiresAt = pb.GetExpiresAt().AsTime().UTC()
	if c := pb.GetCreatedAt(); c != nil && c.IsValid() {
		b.CreatedAt = c.AsTime().UTC()
	}
	if len(b.Reason) > 64 {
		b.Reason = b.Reason[:64]
	}
	return b, nil
}

func (b Ban) validate() error {
	if !ValidID(b.ID) {
		return fmt.Errorf("invalid ban id %q", truncate(b.ID))
	}
	if p, err := Canonical(b.Prefix); err != nil || p != b.Prefix {
		return fmt.Errorf("ban %s: invalid cidr %s", b.ID, b.Prefix)
	}
	switch b.Scope {
	case ScopePlatform:
		if b.SiteID != "" {
			return fmt.Errorf("ban %s: platform ban with a site", b.ID)
		}
	case ScopeSite:
		if !ValidID(b.SiteID) {
			return fmt.Errorf("ban %s: invalid site id", b.ID)
		}
	default:
		return fmt.Errorf("ban %s: invalid scope %q", b.ID, b.Scope)
	}
	if b.Source != SourceManual && b.Source != SourceAuto {
		return fmt.Errorf("ban %s: invalid source %q", b.ID, b.Source)
	}
	if b.ExpiresAt.IsZero() {
		return fmt.Errorf("ban %s: no expiry", b.ID)
	}
	return nil
}

func truncate(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

// State is the console's ban set as far as the node has applied it.
type State struct {
	// ClusterID is the cluster the bans belong to (a node enrolled into
	// another cluster starts over).
	ClusterID string
	// Sequence is the console sequence the bans are complete up to.
	Sequence uint64
	Bans     map[string]Ban
}

// New returns an empty state.
func New() *State { return &State{Bans: map[string]Ban{}} }

// Clone returns a copy of s.
func (s *State) Clone() *State {
	c := &State{ClusterID: s.ClusterID, Sequence: s.Sequence, Bans: make(map[string]Ban, len(s.Bans))}
	for id, b := range s.Bans {
		c.Bans[id] = b
	}
	return c
}

type fileFormat struct {
	Version   int    `json:"version"`
	ClusterID string `json:"cluster_id,omitempty"`
	Sequence  uint64 `json:"sequence,string"`
	Bans      []Ban  `json:"bans"`
}

const fileVersion = 1

// Load reads the persisted state. A missing file is an empty state.
// Entries that fail validation are dropped (and reported in the error
// joined to a usable state).
func Load(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return New(), nil
	}
	if err != nil {
		return nil, err
	}
	var f fileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if f.Version != fileVersion {
		return nil, fmt.Errorf("%s: unsupported version %d", path, f.Version)
	}
	s := &State{ClusterID: f.ClusterID, Sequence: f.Sequence, Bans: make(map[string]Ban, len(f.Bans))}
	var errs []error
	for _, b := range f.Bans {
		if err := b.validate(); err != nil {
			errs = append(errs, err)
			continue
		}
		s.Bans[b.ID] = b
	}
	return s, errors.Join(errs...)
}

// Save writes the state atomically (0600).
func (s *State) Save(path string) error {
	f := fileFormat{Version: fileVersion, ClusterID: s.ClusterID, Sequence: s.Sequence, Bans: s.sorted()}
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(path, raw, 0o600)
}

func (s *State) sorted() []Ban {
	out := make([]Ban, 0, len(s.Bans))
	for _, b := range s.Bans {
		out = append(out, b)
	}
	slices.SortFunc(out, func(a, b Ban) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Apply applies one GetBans page: a reset page drops every ban first,
// then bans are upserted by id and removed ids deleted. Bans that fail
// validation are skipped (returned as errors); bans already expired are
// dropped. The state then continues from the page's sequence.
func (s *State) Apply(page *nodev1.GetBansResponse, now time.Time) []error {
	if page.GetReset_() {
		s.Bans = map[string]Ban{}
	}
	var errs []error
	for _, pb := range page.GetBans() {
		b, err := FromProto(pb)
		if err != nil {
			errs = append(errs, err)
			// An invalid update must not leave an older version of the
			// same ban in force.
			delete(s.Bans, pb.GetId())
			continue
		}
		if !b.ExpiresAt.After(now) {
			delete(s.Bans, b.ID)
			continue
		}
		// Bans last at most 7 days; a later expiry (a clock or data
		// error) is shortened rather than kept for years.
		if limit := now.Add(MaxLifetime); b.ExpiresAt.After(limit) {
			b.ExpiresAt = limit.UTC().Truncate(time.Second)
		}
		s.Bans[b.ID] = b
	}
	for _, id := range page.GetRemovedIds() {
		delete(s.Bans, id)
	}
	s.Sequence = page.GetSequence()
	return errs
}

// Prune drops expired bans and returns how many were dropped.
func (s *State) Prune(now time.Time) int {
	n := 0
	for id, b := range s.Bans {
		if !b.ExpiresAt.After(now) {
			delete(s.Bans, id)
			n++
		}
	}
	return n
}

// Ordered returns the unexpired bans in the order the data plane must
// hold them: manual bans first (oldest first), then automatic bans from
// the newest to the oldest. Automatic bans beyond capacity are dropped
// and counted; manual bans are never dropped (the data plane reports those
// it cannot hold).
func (s *State) Ordered(now time.Time, capacity int) (bans []Ban, dropped int) {
	var manual, auto []Ban
	for _, b := range s.Bans {
		if !b.ExpiresAt.After(now) {
			continue
		}
		if b.Manual() {
			manual = append(manual, b)
		} else {
			auto = append(auto, b)
		}
	}
	slices.SortFunc(manual, func(a, b Ban) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), strings.Compare(a.ID, b.ID))
	})
	slices.SortFunc(auto, func(a, b Ban) int {
		return cmp.Or(b.CreatedAt.Compare(a.CreatedAt), strings.Compare(a.ID, b.ID))
	})
	room := max(capacity-len(manual), 0)
	if len(auto) > room {
		dropped = len(auto) - room
		auto = auto[:room]
	}
	return append(manual, auto...), dropped
}

// Platform returns the unexpired platform bans.
func (s *State) Platform(now time.Time) []Ban {
	var out []Ban
	for _, b := range s.Bans {
		if b.Scope == ScopePlatform && b.ExpiresAt.After(now) {
			out = append(out, b)
		}
	}
	slices.SortFunc(out, func(a, b Ban) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func (b Ban) equal(o Ban) bool {
	return b.ID == o.ID && b.Prefix == o.Prefix && b.Scope == o.Scope && b.SiteID == o.SiteID &&
		b.Source == o.Source && b.Reason == o.Reason && b.CreatedAt.Equal(o.CreatedAt) && b.ExpiresAt.Equal(o.ExpiresAt)
}

// Delta is the difference between two states: bans to write and bans to
// delete (their previous version, so the data plane can find them).
type Delta struct {
	Upsert []Ban
	Remove []Ban
}

// Len returns the number of operations.
func (d Delta) Len() int { return len(d.Upsert) + len(d.Remove) }

// Diff returns what turns from into to. A ban whose address, scope or
// site changed is removed under its old key and written under the new one.
func Diff(from, to *State) Delta {
	var d Delta
	for id, nb := range to.Bans {
		ob, ok := from.Bans[id]
		switch {
		case !ok:
			d.Upsert = append(d.Upsert, nb)
		case !ob.equal(nb):
			if ob.Prefix != nb.Prefix || ob.Scope != nb.Scope || ob.SiteID != nb.SiteID {
				d.Remove = append(d.Remove, ob)
			}
			d.Upsert = append(d.Upsert, nb)
		}
	}
	for id, ob := range from.Bans {
		if _, ok := to.Bans[id]; !ok {
			d.Remove = append(d.Remove, ob)
		}
	}
	byID := func(a, b Ban) int { return strings.Compare(a.ID, b.ID) }
	slices.SortFunc(d.Upsert, byID)
	slices.SortFunc(d.Remove, byID)
	return d
}
