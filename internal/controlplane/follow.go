package controlplane

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/nodelog"
)

// Follow timing defaults (Follower).
const (
	DefaultFailoverAfter = 3 * time.Minute
	DefaultRetryPrimary  = 5 * time.Minute
	DefaultCheckTimeout  = 20 * time.Second
)

// DefaultFollowBackoff is the wait before the console's address is checked
// again after a failed check (the last step repeats).
var DefaultFollowBackoff = []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour}

// Follower moves a Channel to the address the console gives out:
//
//   - the console's address (SetDesired, from every heartbeat) is checked
//     with Check before anything changes; a passing check persists it in
//     the identity file atomically, keeps the address in use as the
//     fallback and reloads the channel. A failing one is reported
//     (Status) and retried after DefaultFollowBackoff; a new address is
//     checked at once. Only the latest address counts.
//   - while no call succeeded on the persisted address for FailoverAfter,
//     the fallback is checked and, when it passes, used until the
//     persisted address passes a check again (every RetryPrimary). The
//     fallback is never persisted: after a restart the agent connects to
//     the persisted address first.
type Follower struct {
	Channel *Channel
	Store   identity.Store
	Log     *slog.Logger
	// BeforeCheck runs before a check connects to an address (the node
	// agent adds its host to the nftables allow list); Hosts includes it
	// meanwhile.
	BeforeCheck func(ctx context.Context)
	// Switched runs after the address in use changed (or a check failed),
	// so the status is reported at once.
	Switched func()

	FailoverAfter time.Duration
	RetryPrimary  time.Duration
	Backoff       []time.Duration
	CheckTimeout  time.Duration
	Now           func() time.Time

	mu           sync.Mutex
	desired      Address
	attempts     int
	nextAttempt  time.Time
	failed       *followFailure
	lastOK       time.Time
	lastErr      error
	nextPrimary  time.Time
	nextFailover time.Time
	candidate    Address
	wake         chan struct{}
}

type followFailure struct {
	addr Address
	code string
	err  string
	at   time.Time
}

func (f *Follower) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Follower) log() *slog.Logger {
	if f.Log == nil {
		return slog.Default()
	}
	return f.Log
}

func (f *Follower) failoverAfter() time.Duration {
	return cmpOr(f.FailoverAfter, DefaultFailoverAfter)
}

func (f *Follower) retryPrimary() time.Duration { return cmpOr(f.RetryPrimary, DefaultRetryPrimary) }

func cmpOr(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

func (f *Follower) backoff(attempt int) time.Duration {
	steps := f.Backoff
	if len(steps) == 0 {
		steps = DefaultFollowBackoff
	}
	return steps[min(attempt, len(steps)-1)]
}

func (f *Follower) poke() {
	f.mu.Lock()
	if f.wake == nil {
		f.wake = make(chan struct{}, 1)
	}
	w := f.wake
	f.mu.Unlock()
	select {
	case w <- struct{}{}:
	default:
	}
}

// SetDesired takes the address the console gives out (nil: the console
// does not say, e.g. an older console: the address in use stays). An
// address the agent refuses is reported as invalid_address and never
// connected to.
func (f *Follower) SetDesired(a *nodev1.ChannelAddress) {
	if a.GetUrl() == "" {
		f.mu.Lock()
		f.desired = Address{}
		f.mu.Unlock()
		return
	}
	addr, err := ParseAddress(a.GetUrl(), a.GetServerName())
	now := f.now()
	f.mu.Lock()
	if err != nil {
		bad := Address{URL: a.GetUrl(), ServerName: a.GetServerName()}
		if f.failed == nil || f.failed.addr != bad {
			f.log().Warn("the console gave out a node channel address this agent refuses", "url", a.GetUrl(), "err", err)
			f.failed = &followFailure{addr: bad, code: CheckInvalidAddress, err: err.Error(), at: now}
		}
		f.desired = Address{}
		f.mu.Unlock()
		return
	}
	changed := !addr.Equal(f.desired)
	if changed {
		f.desired, f.attempts, f.nextAttempt = addr, 0, now
	}
	f.mu.Unlock()
	if changed {
		f.poke()
	}
}

// NoteOK records a successful call on the address in use; NoteFailure a
// failed one.
func (f *Follower) NoteOK() {
	f.mu.Lock()
	f.lastOK, f.lastErr = f.now(), nil
	f.mu.Unlock()
}

func (f *Follower) NoteFailure(err error) {
	f.mu.Lock()
	f.lastErr = err
	f.mu.Unlock()
	f.poke()
}

// Hosts returns the hosts the agent may connect to as the console: the
// persisted and fallback addresses, the one in use and the one being
// checked.
func (f *Follower) Hosts() []string {
	var hosts []string
	add := func(a Address) {
		if h := a.Host(); h != "" && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	if id := f.Channel.Identity(); id != nil {
		add(CurrentAddress(id.Identity))
		add(FallbackAddress(id.Identity))
	}
	inUse, _ := f.Channel.InUse()
	add(inUse)
	f.mu.Lock()
	add(f.candidate)
	f.mu.Unlock()
	return hosts
}

// Run checks and switches addresses until ctx is done.
func (f *Follower) Run(ctx context.Context) {
	f.mu.Lock()
	if f.wake == nil {
		f.wake = make(chan struct{}, 1)
	}
	wake := f.wake
	if f.lastOK.IsZero() {
		// The failover clock starts with the agent.
		f.lastOK = f.now()
	}
	f.mu.Unlock()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		f.Step(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-wake:
		}
	}
}

// Step does what is due now: switch to the console's address, fall back,
// or return from the fallback. At most one check per step.
func (f *Follower) Step(ctx context.Context) {
	f.reloadIfChanged()
	id := f.Channel.Identity()
	if id == nil {
		return
	}
	current, fallback := CurrentAddress(id.Identity), FallbackAddress(id.Identity)
	inUse, onFallback := f.Channel.InUse()
	now := f.now()

	f.mu.Lock()
	desired := f.desired
	follow := !desired.Empty() && !desired.Equal(current) && !now.Before(f.nextAttempt)
	// On the console's address: whatever failed before is over.
	if !desired.Empty() && desired.Equal(current) && !onFallback {
		f.failed = nil
	}
	failover := !onFallback && !fallback.Empty() && !fallback.Equal(current) &&
		now.Sub(f.lastOK) >= f.failoverAfter() && !now.Before(f.nextFailover)
	back := onFallback && !now.Before(f.nextPrimary)
	lastErr := f.lastErr
	f.mu.Unlock()

	switch {
	case follow:
		f.follow(ctx, id, desired, current, inUse)
	case failover:
		f.failover(ctx, id, current, fallback, lastErr)
	case back:
		f.back(ctx, id, current)
	}
}

// reloadIfChanged reloads the channel when the identity file names other
// console addresses than the channel loaded (`set-server` while the agent
// runs). Another identity is the agent's business (it restarts).
func (f *Follower) reloadIfChanged() {
	loaded := f.Channel.Identity()
	if loaded == nil {
		return
	}
	disk, err := f.Store.ReadIdentity()
	if err != nil || !identity.SameIdentity(*disk, loaded.Identity) || identity.SameServer(*disk, loaded.Identity) {
		return
	}
	if err := f.Channel.Reload(); err != nil {
		f.log().Error("cannot load the changed node channel address", "err", err)
		return
	}
	f.mu.Lock()
	f.failed, f.lastOK, f.lastErr, f.nextFailover = nil, f.now(), nil, time.Time{}
	f.mu.Unlock()
	f.log().Info("node channel address changed on disk; reconnecting", "server", disk.ServerURL, "fallback_server", disk.FallbackServerURL,
		nodelog.EventKey, nodelog.EventChannelSwitched)
	f.switched()
}

func (f *Follower) check(ctx context.Context, id *identity.Loaded, addr Address) (CheckResult, error) {
	f.mu.Lock()
	f.candidate = addr
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.candidate = Address{}
		f.mu.Unlock()
	}()
	if f.BeforeCheck != nil {
		f.BeforeCheck(ctx)
	}
	cctx, cancel := context.WithTimeout(ctx, cmpOr(f.CheckTimeout, DefaultCheckTimeout))
	defer cancel()
	cert := id.TLS
	return Check(cctx, id, func() *tls.Certificate { return &cert }, addr)
}

func (f *Follower) recordFailure(addr Address, err error) {
	f.mu.Lock()
	f.failed = &followFailure{addr: addr, code: CheckCode(err), err: truncateError(err.Error()), at: f.now()}
	f.mu.Unlock()
}

func (f *Follower) switched() {
	if f.Switched != nil {
		f.Switched()
	}
}

// follow checks the console's address and persists it when the check
// passes. The address in use becomes the fallback (the persisted one when
// the console's address is the fallback in use).
func (f *Follower) follow(ctx context.Context, id *identity.Loaded, desired, current, inUse Address) {
	_, err := f.check(ctx, id, desired)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		f.mu.Lock()
		wait := f.backoff(f.attempts)
		f.attempts++
		f.nextAttempt = f.now().Add(wait)
		f.mu.Unlock()
		f.recordFailure(desired, err)
		f.log().Warn("the node channel address the console gives out failed its check; staying on the address in use",
			"address", desired.String(), "in_use", inUse.String(), "code", CheckCode(err), "err", err, "retry_in", wait.String())
		f.switched()
		return
	}
	now := f.now()
	keep := inUse
	if keep.Equal(desired) {
		keep = current
	}
	_, err = f.Store.UpdateServer(id.Identity, func(next *identity.Identity) {
		if !keep.Equal(desired) {
			next.FallbackServerURL, next.FallbackServerName = keep.URL, keep.ServerName
		}
		next.ServerURL, next.ServerName = desired.URL, desired.ServerName
		next.ServerSource, next.ServerChangedAt = identity.ServerSourceConsole, now.UTC().Truncate(time.Second)
	})
	if err == nil {
		err = f.Channel.Reload()
	}
	if err != nil {
		if errors.Is(err, identity.ErrIdentityReplaced) {
			return // the agent restarts with the new identity
		}
		f.recordFailure(desired, err)
		f.log().Error("cannot save the node channel address", "address", desired.String(), "err", err)
		f.switched()
		return
	}
	f.mu.Lock()
	f.failed, f.attempts, f.lastOK, f.lastErr = nil, 0, now, nil
	f.mu.Unlock()
	f.log().Info("switched to the node channel address the console gives out", "address", desired.String(), "fallback", keep.String(),
		nodelog.EventKey, nodelog.EventChannelSwitched)
	f.switched()
}

// failover moves to the fallback while the persisted address fails.
func (f *Follower) failover(ctx context.Context, id *identity.Loaded, current, fallback Address, lastErr error) {
	_, err := f.check(ctx, id, fallback)
	if ctx.Err() != nil {
		return
	}
	now := f.now()
	if err == nil {
		err = f.Channel.Use(fallback)
	}
	if err != nil {
		f.mu.Lock()
		f.nextFailover = now.Add(f.retryPrimary())
		f.mu.Unlock()
		f.log().Warn("the node channel address fails and so does the fallback", "address", current.String(),
			"fallback", fallback.String(), "err", err)
		return
	}
	if lastErr == nil {
		lastErr = errors.New("no successful call for " + f.failoverAfter().String())
	}
	f.recordFailure(current, lastErr)
	f.mu.Lock()
	f.nextPrimary, f.lastOK = now.Add(f.retryPrimary()), now
	f.mu.Unlock()
	f.log().Warn("the node channel address fails; using the fallback until it works again", "address", current.String(),
		"fallback", fallback.String(), "err", lastErr)
	f.switched()
}

// back returns from the fallback once the persisted address passes a check.
func (f *Follower) back(ctx context.Context, id *identity.Loaded, current Address) {
	_, err := f.check(ctx, id, current)
	if ctx.Err() != nil {
		return
	}
	now := f.now()
	if err == nil {
		err = f.Channel.Reload()
	}
	if err != nil {
		f.recordFailure(current, err)
		f.mu.Lock()
		f.nextPrimary = now.Add(f.retryPrimary())
		f.mu.Unlock()
		return
	}
	f.mu.Lock()
	f.failed, f.lastOK, f.lastErr, f.nextFailover = nil, now, nil, time.Time{}
	f.mu.Unlock()
	f.log().Info("the node channel address works again; leaving the fallback", "address", current.String())
	f.switched()
}

// Status is the ChannelStatus of heartbeats.
func (f *Follower) Status() *nodev1.ChannelStatus {
	id := f.Channel.Identity()
	if id == nil {
		return nil
	}
	_, onFallback := f.Channel.InUse()
	st := &nodev1.ChannelStatus{
		Current:    CurrentAddress(id.Identity).Proto(),
		Fallback:   FallbackAddress(id.Identity).Proto(),
		OnFallback: onFallback,
		Source:     nodev1.ChannelSource_CHANNEL_SOURCE_ENROLL,
	}
	switch id.ServerSource {
	case identity.ServerSourceConsole:
		st.Source = nodev1.ChannelSource_CHANNEL_SOURCE_CONSOLE
	case identity.ServerSourceCommand:
		st.Source = nodev1.ChannelSource_CHANNEL_SOURCE_COMMAND
	}
	switch {
	case !id.ServerChangedAt.IsZero():
		st.SwitchedAt = timestamppb.New(id.ServerChangedAt)
	case !id.EnrolledAt.IsZero():
		st.SwitchedAt = timestamppb.New(id.EnrolledAt)
	}
	f.mu.Lock()
	if fl := f.failed; fl != nil {
		st.Failed = &nodev1.ChannelAddress{Url: fl.addr.URL, ServerName: fl.addr.ServerName}
		st.ErrorCode, st.Error, st.FailedAt = fl.code, fl.err, timestamppb.New(fl.at)
	}
	f.mu.Unlock()
	return st
}

func truncateError(s string) string {
	const limit = 512
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "…"
}
