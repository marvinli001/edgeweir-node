// Package bans holds the dynamic IP bans the console distributes outside
// configuration revisions (GetBans).
//
// The agent keeps the console's bans and the sequence it has applied in
// memory and in <state-dir>/bans.json (0600), applies GetBans pages to them
// (a reset page drops every ban first) and pushes the result to the data
// plane (lua/edgeweir/bans.lua) and, for platform bans, to nftables.
// Bans the node creates itself (automatic mitigation) live only in the
// data plane until they are reported with ReportBans.
//
// Greylist entries (proto v1.6.0, Ban.action) travel the same way: the
// edge layer challenges or rate-limits their addresses instead of refusing
// them, and the kernel never drops them. They are stored apart from the
// bans in bans.json ("greylist"), so an older agent reading the file
// never mistakes one for a ban.
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

// Action is what an entry does: "" refuses (a ban), the others make it a
// greylist entry.
type Action string

// Actions.
const (
	ActionBlock     Action = ""
	ActionChallenge Action = "challenge"
	ActionRateLimit Action = "rate_limit"
)

// Challenges a greylist entry may ask for.
var challenges = map[string]bool{"cookie302": true, "js": true, "pow": true, "captcha": true}

// Bounds of a greylist rate limit.
const (
	MaxRateRequests = 100000
	MaxRateWindow   = 3600
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
	// Greylist entries only.
	Action       Action `json:"action,omitempty"`
	Challenge    string `json:"challenge,omitempty"`
	RateRequests uint32 `json:"rate_requests,omitempty"`
	RateWindow   uint32 `json:"rate_window,omitempty"`
}

// Grey reports whether b is a greylist entry.
func (b Ban) Grey() bool { return b.Action != ActionBlock }

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
	switch pb.GetAction() {
	case nodev1.BanAction_BAN_ACTION_UNSPECIFIED:
	case nodev1.BanAction_BAN_ACTION_CHALLENGE:
		b.Action, b.Challenge = ActionChallenge, pb.GetChallenge()
	case nodev1.BanAction_BAN_ACTION_RATE_LIMIT:
		b.Action, b.RateRequests, b.RateWindow = ActionRateLimit, pb.GetRateLimitRequests(), pb.GetRateLimitWindowSeconds()
	default:
		return Ban{}, fmt.Errorf("ban %s: unsupported action %v", b.ID, pb.GetAction())
	}
	if err := b.validateAction(); err != nil {
		return Ban{}, err
	}
	return b, nil
}

// validateAction checks a greylist entry's parameters: only console
// (manual) entries are greylist entries.
func (b Ban) validateAction() error {
	switch b.Action {
	case ActionBlock:
		if b.Challenge != "" || b.RateRequests != 0 || b.RateWindow != 0 {
			return fmt.Errorf("ban %s: greylist parameters without a greylist action", b.ID)
		}
		return nil
	case ActionChallenge:
		if !challenges[b.Challenge] || b.RateRequests != 0 || b.RateWindow != 0 {
			return fmt.Errorf("ban %s: invalid challenge %q", b.ID, truncate(b.Challenge))
		}
	case ActionRateLimit:
		if b.Challenge != "" || b.RateRequests < 1 || b.RateRequests > MaxRateRequests || b.RateWindow < 1 || b.RateWindow > MaxRateWindow {
			return fmt.Errorf("ban %s: invalid rate limit %d per %d s", b.ID, b.RateRequests, b.RateWindow)
		}
	default:
		return fmt.Errorf("ban %s: invalid action %q", b.ID, truncate(string(b.Action)))
	}
	if b.Source != SourceManual {
		return fmt.Errorf("ban %s: an automatic greylist entry", b.ID)
	}
	return nil
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
	return b.validateAction()
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
	// Greylist: the bans were fetched with greylist entries
	// (GetBansRequest.greylist). A state written without them (by an
	// older agent) is fetched again from the start.
	Greylist bool
	// Bans holds the bans and the greylist entries by id.
	Bans map[string]Ban
}

// New returns an empty state.
func New() *State { return &State{Bans: map[string]Ban{}} }

// Clone returns a copy of s.
func (s *State) Clone() *State {
	c := &State{ClusterID: s.ClusterID, Sequence: s.Sequence, Greylist: s.Greylist, Bans: make(map[string]Ban, len(s.Bans))}
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
	// Greylist entries, apart from the bans: older agents ignore both
	// fields and keep only the bans.
	Greylist     []Ban `json:"greylist,omitempty"`
	GreylistSync bool  `json:"greylist_sync,omitempty"`
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
	s := &State{ClusterID: f.ClusterID, Sequence: f.Sequence, Greylist: f.GreylistSync, Bans: make(map[string]Ban, len(f.Bans)+len(f.Greylist))}
	var errs []error
	for _, b := range f.Bans {
		if err := b.validate(); err == nil && b.Grey() {
			errs = append(errs, fmt.Errorf("ban %s: greylist entry among the bans", b.ID))
		} else if err != nil {
			errs = append(errs, err)
		} else {
			s.Bans[b.ID] = b
		}
	}
	for _, b := range f.Greylist {
		if err := b.validate(); err == nil && !b.Grey() {
			errs = append(errs, fmt.Errorf("ban %s: ban among the greylist entries", b.ID))
		} else if err != nil {
			errs = append(errs, err)
		} else {
			s.Bans[b.ID] = b
		}
	}
	return s, errors.Join(errs...)
}

// Save writes the state atomically (0600).
func (s *State) Save(path string) error {
	f := fileFormat{Version: fileVersion, ClusterID: s.ClusterID, Sequence: s.Sequence, Bans: []Ban{}, GreylistSync: s.Greylist}
	for _, b := range s.sorted() {
		if b.Grey() {
			f.Greylist = append(f.Greylist, b)
		} else {
			f.Bans = append(f.Bans, b)
		}
	}
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

// Platform returns the unexpired platform bans (greylist entries are not
// bans: the kernel never drops them).
func (s *State) Platform(now time.Time) []Ban {
	var out []Ban
	for _, b := range s.Bans {
		if b.Scope == ScopePlatform && !b.Grey() && b.ExpiresAt.After(now) {
			out = append(out, b)
		}
	}
	slices.SortFunc(out, func(a, b Ban) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// SlotKey is where a ban lives in the data plane: bans of the same scope,
// site and prefix share one entry, greylist entries one of their own.
type SlotKey struct {
	Scope  Scope
	SiteID string
	Prefix netip.Prefix
	Grey   bool
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
	// The greylist entry's action and parameters (of the entry with ID).
	Action       Action
	Challenge    string
	RateRequests uint32
	RateWindow   uint32
}

// Key returns the slot key of a ban.
func (b Ban) Key() SlotKey {
	return SlotKey{Scope: b.Scope, SiteID: b.SiteID, Prefix: b.Prefix, Grey: b.Grey()}
}

func (b Ban) slot() Slot {
	return Slot{SlotKey: b.Key(), ID: b.ID, Manual: b.Manual(), CreatedAt: b.CreatedAt, Action: b.Action,
		Challenge: b.Challenge, RateRequests: b.RateRequests, RateWindow: b.RateWindow}
}

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
			cur = b.slot()
			cur.ExpiresAt = b.ExpiresAt
			out[k] = cur
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
			cur = b.slot()
		}
		cur.ExpiresAt = expires
		out[k] = cur
	}
	return out
}

func compareSlots(a, b Slot) int {
	grey := func(s Slot) int {
		if s.Grey {
			return 1
		}
		return 0
	}
	return cmp.Or(strings.Compare(string(a.Scope), string(b.Scope)), strings.Compare(a.SiteID, b.SiteID),
		a.Prefix.Addr().Compare(b.Prefix.Addr()), cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()), cmp.Compare(grey(a), grey(b)))
}

// Ordered returns the slots in the order the data plane must hold them:
// manual bans first (oldest first), then automatic bans from the newest to
// the oldest. Automatic bans beyond capacity are dropped and counted;
// manual bans are never dropped (the data plane reports those it cannot
// hold).
func Ordered(slots map[SlotKey]Slot, capacity int) (ordered, dropped []Slot) {
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
		dropped = auto[room:]
		auto = auto[:room]
	}
	return append(manual, auto...), dropped
}

// Diff returns the slots to write and the slots to delete (with the id
// the data plane holds them under) to turn from into to.
func Diff(from, to map[SlotKey]Slot) (upsert, remove []Slot) {
	for k, n := range to {
		if o, ok := from[k]; !ok || o.ID != n.ID || o.Manual != n.Manual || !o.ExpiresAt.Equal(n.ExpiresAt) ||
			o.Action != n.Action || o.Challenge != n.Challenge || o.RateRequests != n.RateRequests || o.RateWindow != n.RateWindow {
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
