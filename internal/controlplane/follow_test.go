package controlplane_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/marvinli001/edgeweir-node/internal/controlplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

func TestParseAddress(t *testing.T) {
	for raw, want := range map[string]string{
		"https://Console.Example.com:8443/": "https://console.example.com:8443",
		"https://console.example.com:443":   "https://console.example.com",
		"wss://console.example.com:443":     "wss://console.example.com",
		"ws://10.0.0.1:80":                  "ws://10.0.0.1",
		"ws://10.0.0.1:3000":                "ws://10.0.0.1:3000",
		"https://[::1]:8443":                "https://[::1]:8443",
		"https://node_channel.internal":     "https://node_channel.internal",
	} {
		got, err := controlplane.ParseAddress(raw, "")
		if err != nil || got.URL != want {
			t.Errorf("ParseAddress(%q) = %q, %v; want %q", raw, got.URL, err, want)
		}
	}
	for raw, why := range map[string]string{
		"http://console:8443":                  "scheme must be https",
		"https://user@console:8443":            "credentials",
		"https://console:8443/prefix":          "has no path",
		"https://console:8443/?x=1":            "query",
		"https://console:0":                    "port out of range",
		"https://console:70000":                "port out of range",
		"https://-console.test":                "hyphen",
		"https://" + strings.Repeat("a", 2050): "longer than 2048",
	} {
		if _, err := controlplane.ParseAddress(raw, ""); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("ParseAddress(%q): err = %v, want %q", raw, err, why)
		}
	}
	for _, name := range []string{"*.console.test", "a b", "console.test/x", strings.Repeat("a", 64) + ".test"} {
		if _, err := controlplane.ParseAddress("https://console.test", name); err == nil {
			t.Errorf("server name %q accepted", name)
		}
	}
	a, err := controlplane.ParseAddress("https://10.0.0.1:8443", "Console.Test")
	if err != nil || a.ServerName != "console.test" || a.Name() != "console.test" {
		t.Fatalf("server name: %+v, %v", a, err)
	}
}

func TestAddressEqual(t *testing.T) {
	eq := [][2]controlplane.Address{
		{{URL: "https://console.test:443"}, {URL: "https://CONSOLE.test"}},
		{{URL: "https://console.test", ServerName: "console.test"}, {URL: "https://console.test"}},
		{{URL: "ws://console.test:80"}, {URL: "ws://console.test"}},
		{{}, {}},
	}
	for _, p := range eq {
		if !p[0].Equal(p[1]) {
			t.Errorf("%+v != %+v", p[0], p[1])
		}
	}
	ne := [][2]controlplane.Address{
		{{URL: "https://console.test"}, {URL: "wss://console.test"}},
		{{URL: "https://console.test:8443"}, {URL: "https://console.test"}},
		{{URL: "https://10.0.0.1", ServerName: "a.test"}, {URL: "https://10.0.0.1"}},
		{{URL: "https://console.test"}, {}},
	}
	for _, p := range ne {
		if p[0].Equal(p[1]) {
			t.Errorf("%+v == %+v", p[0], p[1])
		}
	}
}

// relay forwards TCP connections to target while it is up: a second
// address of the same console that can go away.
type relay struct {
	ln     net.Listener
	target string
	up     atomic.Bool
	mu     sync.Mutex
	conns  []net.Conn
}

func startRelay(t *testing.T, target string) *relay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{ln: ln, target: target}
	r.up.Store(true)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if !r.up.Load() {
				_ = c.Close()
				continue
			}
			u, err := net.Dial("tcp", target)
			if err != nil {
				_ = c.Close()
				continue
			}
			r.mu.Lock()
			r.conns = append(r.conns, c, u)
			r.mu.Unlock()
			go func() { _, _ = io.Copy(u, c); _ = u.Close() }()
			go func() { _, _ = io.Copy(c, u); _ = c.Close() }()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); r.setUp(false) })
	return r
}

// setUp lets connections through, or refuses new ones and cuts the open ones.
func (r *relay) setUp(on bool) {
	r.up.Store(on)
	if on {
		return
	}
	r.mu.Lock()
	for _, c := range r.conns {
		_ = c.Close()
	}
	r.conns = nil
	r.mu.Unlock()
}

func (r *relay) port() string {
	_, port, _ := net.SplitHostPort(r.ln.Addr().String())
	return port
}

type followEnv struct {
	console *fakeconsole.Console
	srv     *httptest.Server
	store   identity.Store
	// direct: https://127.0.0.1:<port>; viaRelay: https://localhost:<relay>.
	direct, viaRelay controlplane.Address
	relay            *relay
}

// newFollowEnv enrolls a node with the console at enrollAt (direct or
// relay, chosen by the callback).
func newFollowEnv(t *testing.T, enrollAt func(e *followEnv) controlplane.Address) *followEnv {
	t.Helper()
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-follow", ClusterID: "cl-follow"})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	e := &followEnv{console: console, srv: srv, store: identity.Store{Dir: filepath.Join(t.TempDir(), "state")}}
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	e.direct = controlplane.Address{URL: "https://127.0.0.1:" + port}
	e.relay = startRelay(t, srv.Listener.Addr().String())
	e.viaRelay = controlplane.Address{URL: "https://localhost:" + e.relay.port()}
	console.AddToken("follow-token")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	at := enrollAt(e)
	if _, err := enroll.Run(ctx, enroll.Options{ServerURL: at.URL, Token: "follow-token", CASHA256: console.CA.Pin(), StateDir: e.store.Dir}); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *followEnv) loaded(t *testing.T) *identity.Loaded {
	t.Helper()
	id, err := e.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func certOf(id *identity.Loaded) func() *tls.Certificate {
	return func() *tls.Certificate { return &id.TLS }
}

func TestCheck(t *testing.T) {
	e := newFollowEnv(t, func(e *followEnv) controlplane.Address { return e.direct })
	id := e.loaded(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	e.console.SetChannel(&nodev1.ChannelAddress{Url: e.viaRelay.URL})
	res, err := controlplane.Check(ctx, id, certOf(id), e.viaRelay)
	if err != nil || res.Legacy || !res.Advertised.Equal(e.viaRelay) {
		t.Fatalf("check through the second address: %+v, %v", res, err)
	}
	if got := e.console.ChannelChecks(); len(got) != 1 || got[0] != "node-follow" {
		t.Fatalf("checks = %v", got)
	}

	codeOf := func(addr controlplane.Address) string {
		t.Helper()
		_, err := controlplane.Check(ctx, id, certOf(id), addr)
		var ce *controlplane.CheckError
		if !errors.As(err, &ce) {
			t.Fatalf("%s: err = %v, want a CheckError", addr, err)
		}
		return ce.Code
	}
	// A name the console's certificate does not carry.
	if code := codeOf(controlplane.Address{URL: e.direct.URL, ServerName: "elsewhere.test"}); code != controlplane.CheckTLSUntrusted {
		t.Errorf("foreign server name: %s", code)
	}
	// Another console (another CA) at the address.
	other, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-follow"})
	if err != nil {
		t.Fatal(err)
	}
	otherSrv := other.StartTLS(t)
	if code := codeOf(controlplane.Address{URL: otherSrv.URL}); code != controlplane.CheckTLSUntrusted {
		t.Errorf("another CA: %s", code)
	}
	// Nothing listens.
	e.relay.setUp(false)
	if code := codeOf(e.viaRelay); code != controlplane.CheckUnreachable {
		t.Errorf("unreachable: %s", code)
	}
	e.relay.setUp(true)
	// No WebSocket entry at a ws:// URL.
	plain := httptest.NewServer(http.NotFoundHandler())
	defer plain.Close()
	if code := codeOf(controlplane.Address{URL: "ws://" + plain.Listener.Addr().String()}); code != controlplane.CheckWebSocketRefused {
		t.Errorf("no entry: %s", code)
	}
	// The address is not one the agent takes.
	if code := codeOf(controlplane.Address{URL: "http://" + plain.Listener.Addr().String()}); code != controlplane.CheckInvalidAddress {
		t.Errorf("http://: %s", code)
	}
	// Without a pinned CA nothing is trusted (never the system roots).
	noCA := *id
	noCA.CAPool = nil
	if _, err := controlplane.Check(ctx, &noCA, certOf(id), e.direct); controlplane.CheckCode(err) != controlplane.CheckTLSUntrusted {
		t.Errorf("no CA: %v", err)
	}
	// The console answers for another node than the identity's.
	stranger := *id
	stranger.NodeID = "node-other"
	if _, err := controlplane.Check(ctx, &stranger, certOf(id), e.direct); controlplane.CheckCode(err) != controlplane.CheckWrongIdentity {
		t.Errorf("another node: %v", err)
	}
	// The console refuses the certificate (a deleted node).
	e.console.RejectNode(true)
	if code := codeOf(e.direct); code != controlplane.CheckRejected {
		t.Errorf("refused certificate: %s", code)
	}
	e.console.RejectNode(false)
	// A console without CheckChannel: an authenticated call without side effects stands in.
	e.console.DisableCheck(true)
	res, err = controlplane.Check(ctx, id, certOf(id), e.direct)
	if err != nil || !res.Legacy || !res.Advertised.Empty() {
		t.Fatalf("older console: %+v, %v", res, err)
	}
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func newFollower(t *testing.T, e *followEnv, c *clock) (*controlplane.Follower, *controlplane.Channel) {
	t.Helper()
	ch, err := controlplane.NewChannel(e.store)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ch.Close)
	f := &controlplane.Follower{
		Channel: ch, Store: e.store, Now: c.Now,
		FailoverAfter: time.Minute, RetryPrimary: 2 * time.Minute,
		Backoff: []time.Duration{time.Minute, 10 * time.Minute}, CheckTimeout: 10 * time.Second,
	}
	f.NoteOK()
	return f, ch
}

func reportStatus(ctx context.Context, ch *controlplane.Channel) error {
	_, err := ch.Client().ReportStatus(ctx, connect.NewRequest(&nodev1.ReportStatusRequest{}))
	return err
}

// TestFollowerSwitchesToTheConsolesAddress: a passing check persists the
// console's address with the previous one as the fallback; a failing one
// changes nothing, is reported and retried after the backoff; only the
// latest address counts.
func TestFollowerSwitchesToTheConsolesAddress(t *testing.T) {
	e := newFollowEnv(t, func(e *followEnv) controlplane.Address { return e.direct })
	c := &clock{now: time.Now()}
	f, ch := newFollower(t, e, c)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// An address that does not answer: no switch, the reason is reported.
	e.relay.setUp(false)
	f.SetDesired(e.viaRelay.Proto())
	f.Step(ctx)
	if got := controlplane.CurrentAddress(e.loaded(t).Identity); !got.Equal(e.direct) {
		t.Fatalf("switched to an unreachable address: %s", got)
	}
	st := f.Status()
	if st.GetErrorCode() != controlplane.CheckUnreachable || st.GetFailed().GetUrl() != e.viaRelay.URL || !e.direct.Equal(controlplane.Address{URL: st.GetCurrent().GetUrl()}) {
		t.Fatalf("status after a failed check: %v", st)
	}
	if err := reportStatus(ctx, ch); err != nil {
		t.Fatalf("the address in use stopped working: %v", err)
	}
	// Retried only after the backoff.
	e.relay.setUp(true)
	f.Step(ctx)
	if got := controlplane.CurrentAddress(e.loaded(t).Identity); !got.Equal(e.direct) {
		t.Fatal("checked again before the backoff")
	}
	c.advance(time.Minute)
	f.Step(ctx)
	id := e.loaded(t)
	if !controlplane.CurrentAddress(id.Identity).Equal(e.viaRelay) || !controlplane.FallbackAddress(id.Identity).Equal(e.direct) ||
		id.ServerSource != identity.ServerSourceConsole || id.ServerChangedAt.IsZero() {
		t.Fatalf("identity after the switch: %+v", id.Identity)
	}
	if inUse, fb := ch.InUse(); !inUse.Equal(e.viaRelay) || fb {
		t.Fatalf("in use: %s %v", inUse, fb)
	}
	if err := reportStatus(ctx, ch); err != nil {
		t.Fatalf("call at the new address: %v", err)
	}
	st = f.Status()
	if st.GetFailed() != nil || st.GetSource() != nodev1.ChannelSource_CHANNEL_SOURCE_CONSOLE || st.GetFallback().GetUrl() != e.direct.URL {
		t.Fatalf("status after the switch: %v", st)
	}
	// The key and certificate stay.
	if !bytes.Equal(id.Certificate.Raw, ch.Identity().Certificate.Raw) {
		t.Fatal("certificate changed")
	}

	// A new address is checked at once, whatever the backoff.
	e.relay.setUp(false)
	f.SetDesired(&nodev1.ChannelAddress{Url: "https://localhost:1"})
	f.Step(ctx)
	f.SetDesired(e.direct.Proto())
	f.Step(ctx)
	if got := controlplane.CurrentAddress(e.loaded(t).Identity); !got.Equal(e.direct) {
		t.Fatalf("the latest address was not taken: %s", got)
	}
	if got := controlplane.FallbackAddress(e.loaded(t).Identity); !got.Equal(e.viaRelay) {
		t.Fatalf("fallback = %s", got)
	}

	// An address the agent refuses is reported and never connected to.
	checks := len(e.console.ChannelChecks())
	f.SetDesired(&nodev1.ChannelAddress{Url: "https://user:pw@console.test"})
	f.Step(ctx)
	if f.Status().GetErrorCode() != controlplane.CheckInvalidAddress || len(e.console.ChannelChecks()) != checks {
		t.Fatalf("invalid address: %v", f.Status())
	}
}

// TestFollowerFallsBack: while the persisted address fails the fallback is
// used (not persisted), and the persisted one again once it answers; a
// restart connects to the persisted address.
func TestFollowerFallsBack(t *testing.T) {
	e := newFollowEnv(t, func(e *followEnv) controlplane.Address { return e.direct })
	c := &clock{now: time.Now()}
	f, ch := newFollower(t, e, c)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f.SetDesired(e.viaRelay.Proto())
	f.Step(ctx)
	if inUse, _ := ch.InUse(); !inUse.Equal(e.viaRelay) {
		t.Fatalf("not switched: %s", inUse)
	}

	e.relay.setUp(false)
	err := reportStatus(ctx, ch)
	if err == nil {
		t.Fatal("call through the closed relay succeeded")
	}
	f.NoteFailure(err)
	f.Step(ctx)
	if _, fb := ch.InUse(); fb {
		t.Fatal("fell back before FailoverAfter")
	}
	c.advance(time.Minute)
	f.Step(ctx)
	inUse, fb := ch.InUse()
	if !inUse.Equal(e.direct) || !fb {
		t.Fatalf("in use after the failover: %s %v", inUse, fb)
	}
	if err := reportStatus(ctx, ch); err != nil {
		t.Fatalf("call on the fallback: %v", err)
	}
	st := f.Status()
	if !st.GetOnFallback() || st.GetFailed().GetUrl() != e.viaRelay.URL || st.GetErrorCode() == "" {
		t.Fatalf("status on the fallback: %v", st)
	}
	if got := controlplane.CurrentAddress(e.loaded(t).Identity); !got.Equal(e.viaRelay) {
		t.Fatalf("the fallback was persisted: %s", got)
	}

	// A restart connects to the persisted address first.
	restarted, err := controlplane.NewChannel(e.store)
	if err != nil {
		t.Fatal(err)
	}
	if inUse, fb := restarted.InUse(); !inUse.Equal(e.viaRelay) || fb {
		t.Fatalf("after a restart: %s %v", inUse, fb)
	}
	restarted.Close()

	// The persisted address is tried again every RetryPrimary.
	c.advance(2 * time.Minute)
	f.Step(ctx)
	if _, fb := ch.InUse(); !fb {
		t.Fatal("left the fallback for an address that still fails")
	}
	e.relay.setUp(true)
	f.Step(ctx)
	if _, fb := ch.InUse(); !fb {
		t.Fatal("tried the persisted address before RetryPrimary")
	}
	c.advance(2 * time.Minute)
	f.Step(ctx)
	if inUse, fb := ch.InUse(); !inUse.Equal(e.viaRelay) || fb {
		t.Fatalf("after the persisted address answers again: %s %v", inUse, fb)
	}
	if st := f.Status(); st.GetOnFallback() || st.GetFailed() != nil {
		t.Fatalf("status back on the persisted address: %v", st)
	}
}

// TestFollowerTakesTheFallbackTheConsoleGivesOut: on the fallback, the
// console giving out that address makes it the persisted one, with the
// failing address as the fallback.
func TestFollowerTakesTheFallbackTheConsoleGivesOut(t *testing.T) {
	e := newFollowEnv(t, func(e *followEnv) controlplane.Address { return e.direct })
	c := &clock{now: time.Now()}
	f, ch := newFollower(t, e, c)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	f.SetDesired(e.viaRelay.Proto())
	f.Step(ctx)
	e.relay.setUp(false)
	f.NoteFailure(errors.New("down"))
	c.advance(time.Minute)
	f.Step(ctx)
	if _, fb := ch.InUse(); !fb {
		t.Fatal("no failover")
	}
	f.SetDesired(e.direct.Proto())
	f.Step(ctx)
	id := e.loaded(t)
	if !controlplane.CurrentAddress(id.Identity).Equal(e.direct) || !controlplane.FallbackAddress(id.Identity).Equal(e.viaRelay) {
		t.Fatalf("identity: %+v", id.Identity)
	}
	if inUse, fb := ch.InUse(); !inUse.Equal(e.direct) || fb {
		t.Fatalf("in use: %s %v", inUse, fb)
	}
}

// TestFollowerWebSocket: https:// and ws:// / wss:// replace each other; the
// TLS inside the WebSocket is the same pinned mTLS.
func TestFollowerWebSocket(t *testing.T) {
	e := newFollowEnv(t, func(e *followEnv) controlplane.Address { return e.direct })
	entry := e.console.StartWebSocketEntry(t, e.srv, false)
	ws := controlplane.Address{URL: "ws://" + entry.Listener.Addr().String(), ServerName: "localhost"}
	c := &clock{now: time.Now()}
	f, ch := newFollower(t, e, c)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, to := range []controlplane.Address{ws, e.direct} {
		f.SetDesired(to.Proto())
		f.Step(ctx)
		if inUse, _ := ch.InUse(); !inUse.Equal(to) {
			t.Fatalf("not switched to %s: %v", to, f.Status())
		}
		if err := reportStatus(ctx, ch); err != nil {
			t.Fatalf("call at %s: %v", to, err)
		}
	}
}

// TestFollowerPicksUpSetServer: a changed address on disk (set-server while
// the agent runs) reconnects the channel.
func TestFollowerPicksUpSetServer(t *testing.T) {
	e := newFollowEnv(t, func(e *followEnv) controlplane.Address { return e.direct })
	c := &clock{now: time.Now()}
	f, ch := newFollower(t, e, c)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if _, err := controlplane.SetServer(ctx, e.store, e.viaRelay); err != nil {
		t.Fatal(err)
	}
	changed := ch.Changed()
	f.Step(ctx)
	select {
	case <-changed:
	default:
		t.Fatal("channel not reloaded")
	}
	if inUse, _ := ch.InUse(); !inUse.Equal(e.viaRelay) {
		t.Fatalf("in use: %s", inUse)
	}
	if st := f.Status(); st.GetSource() != nodev1.ChannelSource_CHANNEL_SOURCE_COMMAND {
		t.Fatalf("source: %v", st)
	}
}

// TestSetServerRecoversALostNode: a node whose address went away gets a new
// one after a passing check, keeping its identity; a failing check changes
// nothing.
func TestSetServerRecoversALostNode(t *testing.T) {
	e := newFollowEnv(t, func(e *followEnv) controlplane.Address { return e.viaRelay })
	e.relay.setUp(false)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	idFile := e.store.Path(identity.IdentityFile)
	keyFile := e.store.Path(identity.KeyFile)
	before, _ := os.ReadFile(idFile)
	key, _ := os.ReadFile(keyFile)

	_, err := controlplane.SetServer(ctx, e.store, controlplane.Address{URL: "https://127.0.0.1:1"})
	if controlplane.CheckCode(err) != controlplane.CheckUnreachable {
		t.Fatalf("unreachable: %v", err)
	}
	_, err = controlplane.SetServer(ctx, e.store, controlplane.Address{URL: e.direct.URL, ServerName: "elsewhere.test"})
	if controlplane.CheckCode(err) != controlplane.CheckTLSUntrusted {
		t.Fatalf("foreign name: %v", err)
	}
	if after, _ := os.ReadFile(idFile); !bytes.Equal(before, after) {
		t.Fatal("a failed check changed the identity file")
	}

	e.console.SetChannel(e.direct.Proto())
	res, err := controlplane.SetServer(ctx, e.store, e.direct)
	if err != nil || res.Unchanged || !res.Advertised.Equal(e.direct) || !res.Previous.Equal(e.viaRelay) {
		t.Fatalf("set-server: %+v, %v", res, err)
	}
	id := e.loaded(t)
	if id.NodeID != "node-follow" || !controlplane.CurrentAddress(id.Identity).Equal(e.direct) ||
		!controlplane.FallbackAddress(id.Identity).Equal(e.viaRelay) || id.ServerSource != identity.ServerSourceCommand {
		t.Fatalf("identity: %+v", id.Identity)
	}
	if after, _ := os.ReadFile(keyFile); !bytes.Equal(key, after) {
		t.Fatal("the key changed")
	}
	ch, err := controlplane.NewChannel(e.store)
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	if err := reportStatus(ctx, ch); err != nil {
		t.Fatalf("the node is back: %v", err)
	}
	res, err = controlplane.SetServer(ctx, e.store, e.direct)
	if err != nil || !res.Unchanged {
		t.Fatalf("same address again: %+v, %v", res, err)
	}
}
