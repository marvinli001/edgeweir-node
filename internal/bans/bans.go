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

// SlotKey is where a ban lives in the data plane: bans of the same scope,
// site and prefix share one entry.
type SlotKey struct {
	Scope  Scope
	SiteID string
	Prefix netip.Prefix
}

// Slot is the data plane entry of one or more bans with the same key
// (several nodes can report an automatic ban for the same address, next
// to a manual one).
type Slot struct {
	SlotKey
	// ID is the ban the entry is reported under: the manual ban if there is
	// one, otherwise the automatic ban that expires last.
	ID     string
	Manual bool
	// CreatedAt is the creation time of the ban with ID.
	CreatedAt time.Time
	// ExpiresAt is the latest expiry of the bans in the slot.
	ExpiresAt time.Time
}

// Key returns the slot key of a ban.
func (b Ban) Key() SlotKey { return SlotKey{Scope: b.Scope, SiteID: b.SiteID, Prefix: b.Prefix} }

// Slots groups the unexpired bans by data plane key.
func (s *State) Slots(now time.Time) map[SlotKey]Slot {
	out := make(map[SlotKey]Slot, len(s.Bans))
	for _, b := range s.Bans {
		if !b.ExpiresAt.After(now) {
			continue
		}
		k := b.Key()
		cur, ok := out[k]
		if !ok {
			out[k] = Slot{SlotKey: k, ID: b.ID, Manual: b.Manual(), CreatedAt: b.CreatedAt, ExpiresAt: b.ExpiresAt}
			continue
		}
		expires := cur.ExpiresAt
		if b.ExpiresAt.After(expires) {
			expires = b.ExpiresAt
		}
		// The representative: manual before automatic, then the later
		// expiry, then the smaller id, whatever the map order.
		var replace bool
		switch {
		case b.Manual() != cur.Manual:
			replace = b.Manual()
		case !b.ExpiresAt.Equal(cur.ExpiresAt):
			replace = b.ExpiresAt.After(cur.ExpiresAt)
		default:
			replace = b.ID < cur.ID
		}
		if replace {
			cur = Slot{SlotKey: k, ID: b.ID, Manual: b.Manual(), CreatedAt: b.CreatedAt}
		}
		cur.ExpiresAt = expires
		out[k] = cur
	}
	return out
}

func compareSlots(a, b Slot) int {
	return cmp.Or(strings.Compare(string(a.Scope), string(b.Scope)), strings.Compare(a.SiteID, b.SiteID),
		a.Prefix.Addr().Compare(b.Prefix.Addr()), cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()))
}

// Ordered returns the slots in the order the data plane must hold them:
// manual bans first (oldest first), then automatic bans from the newest to
// the oldest. Automatic bans beyond capacity are dropped and counted;
// manual bans are never dropped (the data plane reports those it cannot
// hold).
func Ordered(slots map[SlotKey]Slot, capacity int) (ordered []Slot, dropped int) {
	var manual, auto []Slot
	for _, s := range slots {
		if s.Manual {
			manual = append(manual, s)
		} else {
			auto = append(auto, s)
		}
	}
	slices.SortFunc(manual, func(a, b Slot) int {
		return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), strings.Compare(a.ID, b.ID), compareSlots(a, b))
	})
	slices.SortFunc(auto, func(a, b Slot) int {
		return cmp.Or(b.CreatedAt.Compare(a.CreatedAt), strings.Compare(a.ID, b.ID), compareSlots(a, b))
	})
	room := max(capacity-len(manual), 0)
	if len(auto) > room {
		dropped = len(auto) - room
		auto = auto[:room]
	}
	return append(manual, auto...), dropped
}

// Diff returns the slots to write and the slots to delete (with the id
// the data plane holds them under) to turn from into to.
func Diff(from, to map[SlotKey]Slot) (upsert, remove []Slot) {
	for k, n := range to {
		if o, ok := from[k]; !ok || o.ID != n.ID || o.Manual != n.Manual || !o.ExpiresAt.Equal(n.ExpiresAt) {
			upsert = append(upsert, n)
		}
	}
	for k, o := range from {
		if _, ok := to[k]; !ok {
			remove = append(remove, o)
		}
	}
	slices.SortFunc(upsert, compareSlots)
	slices.SortFunc(remove, compareSlots)
	return upsert, remove
}
