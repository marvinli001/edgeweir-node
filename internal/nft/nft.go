// Package nft enforces platform bans in the kernel with nftables.
//
// The agent owns exactly one table, `table inet edgeweir`:
//
//	set ban4 / ban6      flags interval, timeout: banned prefixes, each
//	                     element with the seconds left until it expires
//	set allow4 / allow6  flags interval: addresses that are never dropped
//	                     (console, the node's own addresses, loopback,
//	                     platform allow lists)
//	chain input          type filter hook input priority -10; policy accept;
//	                     allow sets accept, ban sets drop
//
// Every change is one `nft -f -` transaction (flush the sets, add the
// elements), so the kernel never sees a half-written set. Interval sets
// refuse overlapping elements: a prefix covered by a larger banned prefix
// that expires no earlier is left out, and one that outlives its cover is
// written once the cover has expired (Sync returns when to sync again).
//
// Scripts are built only from netip values formatted by the standard
// library; no string from the console reaches nft unparsed.
package nft

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/netip"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Table is the family and name of the agent's table.
const Table = "inet edgeweir"

// Executor runs an nft script as one transaction.
type Executor interface {
	Run(ctx context.Context, script string) error
}

// Command runs `<Bin> -f -` with the script on standard input.
type Command struct {
	Bin string // default "nft"
}

// Run implements Executor.
func (c Command) Run(ctx context.Context, script string) error {
	bin := c.Bin
	if bin == "" {
		bin = "nft"
	}
	cmd := exec.CommandContext(ctx, bin, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if len(msg) > 2000 {
			msg = msg[:2000] + "…"
		}
		if msg != "" {
			return fmt.Errorf("%s -f -: %w: %s", bin, err, msg)
		}
		return fmt.Errorf("%s -f -: %w", bin, err)
	}
	return nil
}

// Ban is a banned prefix until Expires.
type Ban struct {
	Prefix  netip.Prefix
	Expires time.Time
}

// SetupScript (re)creates the table: `add table` followed by `delete
// table` removes whatever an earlier run left behind without failing when
// there is nothing (nft 1.0.6 has no `destroy`), then the table is
// defined from scratch.
const SetupScript = `add table inet edgeweir
delete table inet edgeweir
table inet edgeweir {
	set ban4 {
		type ipv4_addr
		flags interval, timeout
	}
	set ban6 {
		type ipv6_addr
		flags interval, timeout
	}
	set allow4 {
		type ipv4_addr
		flags interval
	}
	set allow6 {
		type ipv6_addr
		flags interval
	}
	chain input {
		type filter hook input priority -10; policy accept;
		ip saddr @allow4 accept
		ip6 saddr @allow6 accept
		ip saddr @ban4 drop
		ip6 saddr @ban6 drop
	}
}
`

// StopScript removes the table.
const StopScript = "delete table inet edgeweir\n"

// chunk bounds the elements of one `add element` statement (the whole
// script is still one transaction).
const chunk = 500

type element struct {
	prefix  netip.Prefix
	timeout int64 // seconds; 0 for allow elements
	expires time.Time
}

// plan is what one Sync writes.
type plan struct {
	Ban4, Ban6     []element
	Allow4, Allow6 []netip.Prefix
	// Resync is when a ban left out because a shorter-lived larger ban
	// covers it has to be written (zero: never).
	Resync time.Time
}

// entries returns the number of ban elements.
func (p plan) entries() int { return len(p.Ban4) + len(p.Ban6) }

// buildPlan computes the set elements for bans and protected prefixes at
// time now: expired bans are skipped, each element's timeout is the
// remaining lifetime rounded up to a second, and overlapping elements are
// removed (see the package comment).
func buildPlan(bans []Ban, protected []netip.Prefix, now time.Time) plan {
	var p plan
	var v4, v6 []element
	for _, b := range bans {
		if !b.Prefix.IsValid() {
			continue
		}
		left := b.Expires.Sub(now)
		if left <= 0 {
			continue
		}
		e := element{prefix: canonical(b.Prefix), timeout: int64(math.Ceil(left.Seconds())), expires: b.Expires}
		if e.prefix.Addr().Is4() {
			v4 = append(v4, e)
		} else {
			v6 = append(v6, e)
		}
	}
	var r4, r6 time.Time
	p.Ban4, r4 = deoverlap(v4)
	p.Ban6, r6 = deoverlap(v6)
	for _, r := range []time.Time{r4, r6} {
		if !r.IsZero() && (p.Resync.IsZero() || r.Before(p.Resync)) {
			p.Resync = r
		}
	}
	var a4, a6 []netip.Prefix
	for _, pr := range protected {
		if !pr.IsValid() {
			continue
		}
		pr = canonical(pr)
		if pr.Addr().Is4() {
			a4 = append(a4, pr)
		} else {
			a6 = append(a6, pr)
		}
	}
	p.Allow4, p.Allow6 = uncovered(a4), uncovered(a6)
	return p
}

// canonical masks p and unmaps IPv4-mapped IPv6 prefixes.
func canonical(p netip.Prefix) netip.Prefix {
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p.Masked()
}

func comparePrefix(a, b netip.Prefix) int {
	return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
}

// deoverlap keeps elements that no kept larger prefix covers. Larger
// prefixes are kept first; a covered element is dropped when its cover
// expires no earlier, otherwise it waits for a resync at the cover's
// expiry.
func deoverlap(in []element) ([]element, time.Time) {
	// Identical prefixes: the latest expiry wins.
	latest := map[netip.Prefix]element{}
	for _, e := range in {
		if cur, ok := latest[e.prefix]; !ok || e.expires.After(cur.expires) {
			latest[e.prefix] = e
		}
	}
	list := make([]element, 0, len(latest))
	for _, e := range latest {
		list = append(list, e)
	}
	slices.SortFunc(list, func(a, b element) int {
		return cmp.Or(cmp.Compare(a.prefix.Bits(), b.prefix.Bits()), comparePrefix(a.prefix, b.prefix))
	})
	kept := map[netip.Prefix]element{}
	var lengths []int // prefix lengths present in kept, ascending
	var out []element
	var resync time.Time
	for _, e := range list {
		covered := false
		for _, bits := range lengths {
			if bits >= e.prefix.Bits() {
				break
			}
			cover, ok := kept[netip.PrefixFrom(e.prefix.Addr(), bits).Masked()]
			if !ok {
				continue
			}
			covered = true
			if e.expires.After(cover.expires) && (resync.IsZero() || cover.expires.Before(resync)) {
				resync = cover.expires
			}
			break // kept prefixes never overlap: there is at most one cover
		}
		if covered {
			continue
		}
		kept[e.prefix] = e
		if n := len(lengths); n == 0 || lengths[n-1] != e.prefix.Bits() {
			lengths = append(lengths, e.prefix.Bits())
		}
		out = append(out, e)
	}
	slices.SortFunc(out, func(a, b element) int { return comparePrefix(a.prefix, b.prefix) })
	return out, resync
}

// uncovered drops duplicates and prefixes inside another one.
func uncovered(in []netip.Prefix) []netip.Prefix {
	list := slices.Clone(in)
	slices.SortFunc(list, func(a, b netip.Prefix) int {
		return cmp.Or(cmp.Compare(a.Bits(), b.Bits()), comparePrefix(a, b))
	})
	list = slices.Compact(list)
	kept := map[netip.Prefix]bool{}
	var lengths []int
	var out []netip.Prefix
	for _, p := range list {
		covered := false
		for _, bits := range lengths {
			if bits >= p.Bits() {
				break
			}
			if kept[netip.PrefixFrom(p.Addr(), bits).Masked()] {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		kept[p] = true
		if n := len(lengths); n == 0 || lengths[n-1] != p.Bits() {
			lengths = append(lengths, p.Bits())
		}
		out = append(out, p)
	}
	slices.SortFunc(out, comparePrefix)
	return out
}

// elementRE is the only shape an element may have in a script.
var elementRE = regexp.MustCompile(`^[0-9a-f:.]+(/[0-9]{1,3})?$`)

// format writes a prefix as an nft element: a single address without its
// length, any other prefix in CIDR notation.
func format(p netip.Prefix) (string, error) {
	var s string
	if p.IsSingleIP() {
		s = p.Addr().String()
	} else {
		s = p.String()
	}
	if p.Addr().Zone() != "" || !elementRE.MatchString(s) {
		return "", fmt.Errorf("refusing nft element %q", s)
	}
	return s, nil
}

// syncScript returns the transaction that replaces the contents of all
// four sets with plan.
func syncScript(p plan) (string, error) {
	var b strings.Builder
	for _, set := range []string{"allow4", "allow6", "ban4", "ban6"} {
		fmt.Fprintf(&b, "flush set %s %s\n", Table, set)
	}
	writeSet := func(set string, items []string) {
		for len(items) > 0 {
			n := min(chunk, len(items))
			fmt.Fprintf(&b, "add element %s %s { %s }\n", Table, set, strings.Join(items[:n], ", "))
			items = items[n:]
		}
	}
	allow := func(list []netip.Prefix) ([]string, error) {
		out := make([]string, 0, len(list))
		for _, p := range list {
			s, err := format(p)
			if err != nil {
				return nil, err
			}
			out = append(out, s)
		}
		return out, nil
	}
	ban := func(list []element) ([]string, error) {
		out := make([]string, 0, len(list))
		for _, e := range list {
			s, err := format(e.prefix)
			if err != nil {
				return nil, err
			}
			if e.timeout < 1 {
				return nil, fmt.Errorf("refusing nft element %s without a timeout", s)
			}
			out = append(out, fmt.Sprintf("%s timeout %ds", s, e.timeout))
		}
		return out, nil
	}
	a4, err := allow(p.Allow4)
	if err != nil {
		return "", err
	}
	a6, err := allow(p.Allow6)
	if err != nil {
		return "", err
	}
	b4, err := ban(p.Ban4)
	if err != nil {
		return "", err
	}
	b6, err := ban(p.Ban6)
	if err != nil {
		return "", err
	}
	writeSet("allow4", a4)
	writeSet("allow6", a6)
	writeSet("ban4", b4)
	writeSet("ban6", b6)
	return b.String(), nil
}

// Manager owns the table. It is safe for concurrent use.
type Manager struct {
	exec Executor
	log  *slog.Logger

	mu      sync.Mutex
	active  bool
	expires []time.Time // expiry of each ban element written
}

// NewManager returns an inactive manager.
func NewManager(exec Executor, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{exec: exec, log: log}
}

// Start creates the table. An error means nftables cannot be used (no
// nft binary, no CAP_NET_ADMIN, no nf_tables in the kernel): the manager
// stays inactive and bans are enforced at the edge layer only.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.exec.Run(ctx, SetupScript); err != nil {
		m.active = false
		return err
	}
	m.active = true
	m.expires = nil
	return nil
}

// Active reports whether the table is managed.
func (m *Manager) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

// ErrInactive is returned by Sync when the table is not managed.
var ErrInactive = errors.New("kernel bans are not active")

// Sync replaces the sets with bans and protected prefixes. When the sets
// cannot be written (for example the table was deleted by someone else)
// the table is created again once and the sync retried. It returns when a
// ban left out because of an overlap must be written (zero: never).
func (m *Manager) Sync(ctx context.Context, bans []Ban, protected []netip.Prefix, now time.Time) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return time.Time{}, ErrInactive
	}
	plan := buildPlan(bans, protected, now)
	script, err := syncScript(plan)
	if err != nil {
		return time.Time{}, err
	}
	if err := m.exec.Run(ctx, script); err != nil {
		m.log.Warn("cannot update the nftables sets; creating the table again", "err", err)
		if serr := m.exec.Run(ctx, SetupScript); serr != nil {
			return time.Time{}, errors.Join(err, serr)
		}
		m.expires = nil
		if err := m.exec.Run(ctx, script); err != nil {
			return time.Time{}, err
		}
	}
	m.expires = m.expires[:0]
	for _, set := range [][]element{plan.Ban4, plan.Ban6} {
		for _, e := range set {
			m.expires = append(m.expires, now.Add(time.Duration(e.timeout)*time.Second))
		}
	}
	return plan.Resync, nil
}

// Entries returns the number of ban elements the kernel still holds at now.
func (m *Manager) Entries(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, e := range m.expires {
		if e.After(now) {
			n++
		}
	}
	return n
}

// Stop deletes the table (on agent shutdown).
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.active {
		return nil
	}
	m.active = false
	m.expires = nil
	return m.exec.Run(ctx, StopScript)
}
