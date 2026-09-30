package agent

import (
	"context"
	"errors"
	"math"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marvinli001/edgeweir-node/internal/bans"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/nft"
)

// Dynamic bans (ADR-0022 in the console's development records): the
// console's bans arrive outside configuration revisions through GetBans,
// are kept in bans.json, pushed to the data plane (lua/edgeweir/bans.lua)
// and, for platform bans, to nftables (internal/nft). The node's own bans
// are drained from the data plane and reported with ReportBans.

const (
	// banPageSize is the GetBans page size asked for.
	banPageSize = 2000
	// maxBanPages bounds one fetch (a console that never finishes).
	maxBanPages = 1000
	// maxBanDelta: bigger changes replace the whole set instead.
	maxBanDelta = 10000
	// autoBanBatch and maxAutoBansPending bound ReportBans calls and the
	// own bans kept in memory while the console is unreachable.
	autoBanBatch       = 1000
	maxAutoBansPending = 10000
	// protectedRefresh is how often the console's addresses are resolved
	// again and the local addresses read again.
	protectedRefresh = 5 * time.Minute
)

func (a *Agent) bansPath() string { return filepath.Join(a.cfg.StateDir, bans.File) }

func (a *Agent) triggerBans() {
	select {
	case a.banCh <- struct{}{}:
	default:
	}
}

func (a *Agent) triggerKernel() {
	select {
	case a.kernelCh <- struct{}{}:
	default:
	}
}

// startBans loads bans.json, probes nftables and installs the bans before
// the console is contacted.
func (a *Agent) startBans(ctx context.Context) {
	st, err := bans.Load(a.bansPath())
	if st == nil {
		a.log.Error("cannot read the stored bans; starting without them until the console sends them again", "err", err)
		st = bans.New()
	} else if err != nil {
		a.log.Warn("dropped invalid stored bans", "err", err)
	}
	st.Prune(time.Now())
	a.banMu.Lock()
	a.bans = st
	a.banMu.Unlock()
	if a.nft != nil {
		if err := a.nft.Start(ctx); err != nil {
			a.log.Warn("kernel bans unavailable (nft with CAP_NET_ADMIN is required); bans are enforced at the edge layer only", "err", err)
		} else {
			a.log.Info("kernel bans active: nftables table inet edgeweir")
		}
	}
	if len(st.Bans) > 0 {
		a.log.Info("restored stored bans", "bans", len(st.Bans), "sequence", st.Sequence)
	}
	a.pushBansWithRetry(ctx)
}

// stopKernel removes the nftables table (agent shutdown).
func (a *Agent) stopKernel() {
	if a.nft == nil || !a.nft.Active() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.nft.Stop(ctx); err != nil {
		a.log.Warn("cannot remove the nftables table inet edgeweir", "err", err)
		return
	}
	a.log.Info("kernel bans removed: nftables table inet edgeweir deleted")
}

func (a *Agent) kernelActive() bool { return a.nft != nil && a.nft.Active() }

// appliedBanSequence is the console ban sequence the agent has applied.
func (a *Agent) appliedBanSequence() uint64 {
	a.banMu.Lock()
	defer a.banMu.Unlock()
	return a.bans.Sequence
}

// bansLoop fetches bans whenever they are announced, polled or requested.
func (a *Agent) bansLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.banCh:
		}
		a.syncBans(ctx)
	}
}

// syncBans pages through GetBans from the applied sequence, then persists,
// pushes and reports the result. A page error keeps what was applied so
// far (every page leaves a consistent state).
func (a *Agent) syncBans(ctx context.Context) {
	id := a.channel.Identity()
	a.banMu.Lock()
	next := a.bans.Clone()
	a.banMu.Unlock()
	after := next.Sequence
	if next.ClusterID != id.ClusterID {
		after = 0 // enrolled into another cluster: start over
	}
	reset, pages := false, 0
	for pages < maxBanPages {
		cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
		resp, err := a.channel.Client().GetBans(cctx, connect.NewRequest(&nodev1.GetBansRequest{AfterSequence: after, Limit: banPageSize}))
		cancel()
		if err != nil {
			if connect.CodeOf(err) == connect.CodeUnimplemented {
				a.banUnsupported.Do(func() {
					a.log.Info("the console does not distribute dynamic bans (GetBans unimplemented)")
				})
			} else if ctx.Err() == nil {
				a.logRPCError("GetBans failed", err)
			}
			break
		}
		a.markConnected()
		pages++
		msg := resp.Msg
		if msg.GetReset_() {
			reset = true
			next.ClusterID = id.ClusterID
		}
		for _, err := range next.Apply(msg, time.Now()) {
			a.log.Warn("ignoring an invalid ban from the console", "err", err)
		}
		if !msg.GetMore() {
			break
		}
		if msg.GetSequence() <= after && !msg.GetReset_() {
			a.log.Warn("console announced more bans without advancing the sequence; continuing later", "sequence", msg.GetSequence())
			break
		}
		after = msg.GetSequence()
	}
	if pages == 0 {
		return
	}
	a.installBans(ctx, next, reset)
}

// installBans makes next the applied state: persist, push to the data
// plane and the kernel, report.
func (a *Agent) installBans(ctx context.Context, next *bans.State, reset bool) {
	a.banMu.Lock()
	prev := a.bans
	now := time.Now()
	next.Prune(now)
	from, to := prev.Slots(now), next.Slots(now)
	up, rm := bans.Diff(from, to)
	// A console without any ban answers every request with an empty
	// snapshot (sequence 0): nothing to do then.
	unchanged := prev.Sequence == next.Sequence && prev.ClusterID == next.ClusterID && len(up)+len(rm) == 0
	if unchanged {
		a.banMu.Unlock()
		return
	}
	if err := next.Save(a.bansPath()); err != nil {
		a.log.Error("cannot persist bans; applying them anyway", "err", err)
	}
	a.bans = next
	kernel := !slices.EqualFunc(prev.Platform(now), next.Platform(now), func(x, y bans.Ban) bool {
		return x.ID == y.ID && x.Prefix == y.Prefix && x.ExpiresAt.Equal(y.ExpiresAt)
	})
	if reset {
		a.banForcePut = true // the console dropped everything: replace the set
	}
	err := a.pushBansLocked(ctx)
	a.banMu.Unlock()
	if err != nil {
		a.log.Warn("cannot push bans to the data plane; retrying", "err", err)
	} else {
		a.log.Info("bans applied", "sequence", next.Sequence, "bans", len(next.Bans), "reset", reset, "upserted", len(up), "removed", len(rm))
	}
	if kernel {
		a.triggerKernel()
	}
	a.triggerReport()
}

func toDataPlane(s bans.Slot) dataplane.Ban {
	b := dataplane.Ban{ID: s.ID, CIDR: s.Prefix.String(), Scope: string(s.Scope), SiteID: s.SiteID, Kind: "c",
		ExpiresAt: float64(s.ExpiresAt.UnixMilli()) / 1000}
	if s.Manual {
		b.Kind = "m"
	}
	return b
}

func slotsToDataPlane(list []bans.Slot) []dataplane.Ban {
	out := make([]dataplane.Ban, len(list))
	for i, s := range list {
		out[i] = toDataPlane(s)
	}
	return out
}

// pushBansLocked brings the data plane to a.bans: the slots are ordered
// for the capacity (manual first, automatic newest first, the oldest
// automatic ones left out) and sent as a delta against what the data plane
// was last given when it still holds that sequence; otherwise (forced,
// unknown data plane, too many changes, 409) the whole ordered set
// replaces it. banMu is held.
func (a *Agent) pushBansLocked(ctx context.Context) error {
	now := time.Now()
	ordered, dropped := bans.Ordered(a.bans.Slots(now), a.cfg.BanCapacity)
	a.countDroppedLocked(dropped, now)
	want := make(map[bans.SlotKey]bans.Slot, len(ordered))
	for _, s := range ordered {
		want[s.SlotKey] = s
	}
	for k, s := range a.banSent {
		if !s.ExpiresAt.After(now) {
			delete(a.banSent, k) // expired in the data plane as well
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if !a.banForcePut && a.banSent != nil {
		st, err := a.dp.BanStatus(cctx)
		if err != nil {
			a.banForcePut = true
			return err
		}
		if st.Sequence == a.banSentSeq {
			up, rm := bans.Diff(a.banSent, want)
			if a.banSentSeq == a.bans.Sequence && len(up)+len(rm) == 0 {
				a.setBanStatus(st)
				return nil
			}
			if len(up)+len(rm) <= maxBanDelta {
				st, err = a.dp.AddBans(cctx, &dataplane.BanDelta{Base: a.banSentSeq, Sequence: a.bans.Sequence,
					Upsert: slotsToDataPlane(up), Remove: slotsToDataPlane(rm)})
				if err == nil {
					a.banSent, a.banSentSeq = want, a.bans.Sequence
					a.setBanStatus(st)
					a.logDropped(dropped)
					return nil
				}
				var apiErr *dataplane.APIError
				if !errors.As(err, &apiErr) || apiErr.Status != 409 {
					a.banForcePut = true
					return err
				}
			}
		}
	}
	st, err := a.dp.PutBans(cctx, &dataplane.BanTable{Sequence: a.bans.Sequence, Bans: slotsToDataPlane(ordered)})
	if err != nil {
		a.banForcePut = true
		return err
	}
	a.banForcePut = false
	a.banSent, a.banSentSeq = want, a.bans.Sequence
	a.setBanStatus(st)
	a.logDropped(dropped)
	return nil
}

func (a *Agent) logDropped(dropped []bans.Slot) {
	if len(dropped) > 0 {
		a.log.Warn("automatic bans beyond the ban capacity were left out", "dropped", len(dropped), "capacity", a.cfg.BanCapacity)
	}
}

// countDroppedLocked counts automatic bans left out for capacity, each
// once while it lasts.
func (a *Agent) countDroppedLocked(dropped []bans.Slot, now time.Time) {
	for id, until := range a.banDroppedSeen {
		if !until.After(now) {
			delete(a.banDroppedSeen, id)
		}
	}
	for _, s := range dropped {
		if _, ok := a.banDroppedSeen[s.ID]; !ok {
			a.banDroppedSeen[s.ID] = s.ExpiresAt
			a.banDropped++
		}
	}
}

func (a *Agent) setBanStatus(st *dataplane.BanStatus) {
	a.mu.Lock()
	a.banStatus = st
	a.mu.Unlock()
}

// pushBansWithRetry installs the stored bans at startup (nginx may still
// be starting); the data plane loop keeps trying afterwards.
func (a *Agent) pushBansWithRetry(ctx context.Context) {
	deadline := time.Now().Add(a.cfg.PushTimeout)
	delay := 100 * time.Millisecond
	for {
		a.banMu.Lock()
		// The data plane's content is unknown (banSent is nil): the whole
		// set goes in.
		err := a.pushBansLocked(ctx)
		a.banMu.Unlock()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			a.log.Warn("cannot install the stored bans yet; retrying in the background", "err", err)
			return
		}
		if !sleepCtx(ctx, delay) {
			return
		}
		delay = min(delay*2, 2*time.Second)
	}
}

// reconcileBans runs with the data plane checks: it replaces the set when
// the data plane lost it (nginx restarted) or a write failed, and retries
// manual bans that did not fit once a minute.
func (a *Agent) reconcileBans(ctx context.Context) {
	a.banMu.Lock()
	defer a.banMu.Unlock()
	if a.bans == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	st, err := a.dp.BanStatus(cctx)
	if err != nil {
		return
	}
	a.setBanStatus(st)
	if a.banForcePut || st.Sequence != a.bans.Sequence {
		a.log.Info("data plane bans out of sync (nginx restarted?); installing them again",
			"data_plane_sequence", st.Sequence, "sequence", a.bans.Sequence)
		a.banForcePut = true
		if err := a.pushBansLocked(ctx); err != nil {
			a.log.Warn("cannot install bans", "err", err)
		}
		return
	}
	now := time.Now()
	if st.Unapplied == 0 || now.Before(a.banRetryAt) {
		return
	}
	a.banRetryAt = now.Add(a.cfg.BanRetryInterval)
	if st.Unapplied > len(st.UnappliedIDs) {
		a.banForcePut = true
		if err := a.pushBansLocked(ctx); err != nil {
			a.log.Warn("cannot retry the manual bans that did not fit", "err", err)
		}
		return
	}
	var retry []bans.Slot
	for _, s := range a.bans.Slots(now) {
		if slices.Contains(st.UnappliedIDs, s.ID) {
			retry = append(retry, s)
		}
	}
	if len(retry) == 0 {
		return
	}
	res, err := a.dp.AddBans(cctx, &dataplane.BanDelta{Base: a.bans.Sequence, Sequence: a.bans.Sequence, Upsert: slotsToDataPlane(retry)})
	if err != nil {
		a.log.Warn("cannot retry the manual bans that did not fit", "err", err)
		return
	}
	a.setBanStatus(res)
	if res.Unapplied > 0 {
		a.log.Warn("manual bans do not fit into the data plane (raise --ban-capacity or --ban-dict-mb)",
			"unapplied", res.Unapplied, "capacity", res.Capacity)
	}
}

// kernelLoop writes the nftables sets when it starts (before the console
// is contacted) and keeps them in step: after ban and configuration
// changes, when a ban hidden by a larger shorter-lived one has to be
// written, and every protectedRefresh for changed protected addresses.
func (a *Agent) kernelLoop(ctx context.Context) {
	if a.nft == nil {
		return
	}
	refresh := time.NewTicker(protectedRefresh)
	defer refresh.Stop()
	resync := time.NewTimer(time.Hour)
	resync.Stop()
	defer resync.Stop()
	for first := true; ; first = false {
		if !first {
			select {
			case <-ctx.Done():
				return
			case <-a.kernelCh:
			case <-resync.C:
			case <-refresh.C:
				a.addrMu.Lock()
				a.consoleAddrsAt = time.Time{}
				a.addrMu.Unlock()
			}
		}
		at := a.syncKernel(ctx)
		resync.Stop()
		if !at.IsZero() {
			// One second late, so the cover has certainly expired.
			resync.Reset(max(time.Until(at)+time.Second, time.Second))
		}
	}
}

// syncKernel writes the platform bans and protected addresses into the
// nftables sets and returns when to write them again (zero: no need).
func (a *Agent) syncKernel(ctx context.Context) time.Time {
	if !a.kernelActive() {
		return time.Time{}
	}
	protected := a.protectedPrefixes(ctx)
	now := time.Now()
	a.banMu.Lock()
	var list []nft.Ban
	if a.bans != nil {
		for _, b := range a.bans.Platform(now) {
			list = append(list, nft.Ban{Prefix: b.Prefix, Expires: b.ExpiresAt})
		}
	}
	a.banMu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	at, err := a.nft.Sync(cctx, list, protected, now)
	if err != nil {
		if !errors.Is(err, nft.ErrInactive) {
			a.log.Warn("cannot update the nftables sets; retrying in a minute", "err", err)
			return now.Add(time.Minute)
		}
		return time.Time{}
	}
	a.log.Debug("kernel bans synced", "bans", a.nft.Entries(now), "protected", len(protected))
	return at
}

// protectedPrefixes are the addresses nftables never drops: loopback,
// every local interface address, the console's addresses and the
// platform allow lists of the applied configuration.
func (a *Agent) protectedPrefixes(ctx context.Context) []netip.Prefix {
	out := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipn, ok := addr.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(ipn.IP); ok {
					ip = ip.Unmap()
					out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
				}
			}
		}
	}
	out = append(out, a.consoleAddrs(ctx)...)
	for _, list := range a.appliedConfig().GetIpLists() {
		if !list.GetPlatform() || list.GetKind() != "allow" {
			continue
		}
		for _, entry := range list.GetEntries() {
			if p, err := netip.ParsePrefix(entry); err == nil {
				out = append(out, p)
			}
		}
	}
	return out
}

// consoleAddrs resolves the host of the console URL the agent connects to
// (cached for protectedRefresh; the last answer is kept when a lookup
// fails).
func (a *Agent) consoleAddrs(ctx context.Context) []netip.Prefix {
	a.addrMu.Lock()
	defer a.addrMu.Unlock()
	if time.Since(a.consoleAddrsAt) < protectedRefresh && a.consoleAddrsCache != nil {
		return a.consoleAddrsCache
	}
	server := ""
	if id, err := a.ids.ReadIdentity(); err == nil && id != nil {
		server = id.ServerURL
	}
	u, err := url.Parse(server)
	if server == "" || err != nil || u.Hostname() == "" {
		return a.consoleAddrsCache
	}
	host := u.Hostname()
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		addrs, err = net.DefaultResolver.LookupNetIP(lctx, "ip", host)
		cancel()
		if err != nil || len(addrs) == 0 {
			a.log.Warn("cannot resolve the console host for the nftables allow list; keeping the previous addresses", "host", host, "err", err)
			a.consoleAddrsAt = time.Now()
			return a.consoleAddrsCache
		}
	}
	out := make([]netip.Prefix, 0, len(addrs))
	for _, ip := range addrs {
		ip = ip.Unmap().WithZone("")
		out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
	}
	a.consoleAddrsCache, a.consoleAddrsAt = out, time.Now()
	return out
}

// autoBansLoop drains the node's own bans from the data plane every
// AutoBanInterval and reports them. Bans the console did not take stay in
// memory (at most maxAutoBansPending, oldest dropped) for the next round.
func (a *Agent) autoBansLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.AutoBanInterval)
	defer t.Stop()
	var pending []*nodev1.AutoBan
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for range maxAutoBansPending / autoBanBatch {
			dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			items, err := a.dp.DrainAutoBans(dctx)
			cancel()
			if err != nil {
				a.log.Debug("cannot drain automatic bans", "err", err)
				break
			}
			for _, item := range items {
				if b, ok := convertAutoBan(item); ok {
					pending = append(pending, b)
				}
			}
			if len(items) < autoBanBatch {
				break
			}
		}
		if over := len(pending) - maxAutoBansPending; over > 0 {
			a.log.Warn("dropping the oldest unreported automatic bans", "dropped", over)
			pending = slices.Clone(pending[over:])
		}
		for len(pending) > 0 {
			n := min(autoBanBatch, len(pending))
			cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
			_, err := a.channel.Client().ReportBans(cctx, connect.NewRequest(&nodev1.ReportBansRequest{Bans: pending[:n]}))
			cancel()
			if err != nil {
				if connect.CodeOf(err) == connect.CodeUnimplemented {
					a.banUnsupported.Do(func() {
						a.log.Info("the console does not take automatic bans (ReportBans unimplemented)")
					})
				} else if ctx.Err() == nil {
					a.logRPCError("ReportBans failed; will retry", err)
				}
				break
			}
			a.markConnected()
			pending = pending[n:]
		}
	}
}

func unixTime(s float64) time.Time {
	sec, frac := math.Modf(s)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC()
}

// convertAutoBan turns a drained own ban into its report; the address is
// written as a canonical single-address CIDR.
func convertAutoBan(b dataplane.AutoBan) (*nodev1.AutoBan, bool) {
	ip, err := netip.ParseAddr(b.IP)
	if err != nil || !bans.ValidID(b.SiteID) || b.ExpiresAt <= 0 {
		return nil, false
	}
	ip = ip.Unmap().WithZone("")
	reason := b.Reason
	if reason == "" {
		reason = "cc_ip_rate"
	}
	return &nodev1.AutoBan{
		SiteId:        b.SiteID,
		Cidr:          netip.PrefixFrom(ip, ip.BitLen()).String(),
		CreatedAt:     timestamppb.New(unixTime(b.CreatedAt)),
		ExpiresAt:     timestamppb.New(unixTime(b.ExpiresAt)),
		Reason:        reason,
		Metric:        b.Metric,
		Observed:      b.Observed,
		Threshold:     b.Threshold,
		WindowSeconds: b.WindowSeconds,
	}, true
}

// banReport is ReportStatusRequest.bans.
func (a *Agent) banReport(ctx context.Context) *nodev1.BanStatus {
	st, err := a.dp.BanStatus(ctx)
	if err == nil {
		a.setBanStatus(st)
	}
	a.mu.Lock()
	last := a.banStatus
	a.mu.Unlock()
	a.banMu.Lock()
	out := &nodev1.BanStatus{Capacity: uint32(min(a.cfg.BanCapacity, math.MaxUint32)), AutoEvicted: a.banDropped}
	a.banMu.Unlock()
	if last != nil {
		out.AppliedSequence = last.Sequence
		out.Entries = uint32(max(last.Entries, 0))
		out.Unapplied = uint32(max(last.Unapplied, 0))
		out.UnappliedIds = slices.Clone(last.UnappliedIDs[:min(len(last.UnappliedIDs), 100)])
		out.AutoEvicted += last.AutoEvicted
	}
	if a.kernelActive() {
		out.KernelEntries = uint32(a.nft.Entries(time.Now()))
	}
	return out
}
