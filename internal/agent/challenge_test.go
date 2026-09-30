package agent_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/agent"
	"github.com/marvinli001/edgeweir-node/internal/captcha"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

func secret(id string) []byte { return bytes.Repeat([]byte(id[len(id)-1:]), 32) }

func keyRefs(next, current, previous string) []*nodev1.ChallengeKeyRef {
	var out []*nodev1.ChallengeKeyRef
	for _, k := range []struct{ id, role string }{{next, "next"}, {current, "current"}, {previous, "previous"}} {
		if k.id != "" {
			out = append(out, &nodev1.ChallengeKeyRef{Id: k.id, Role: k.role})
		}
	}
	return out
}

func underAttackConfig(keys []*nodev1.ChallengeKeyRef) *nodev1.NodeConfig {
	s := demoSite("site-ua", "ua.test")
	s.Protection = &nodev1.SiteProtection{UnderAttack: true, UnderAttackChallenge: "js"}
	c := baseConfig(s)
	c.ChallengeKeys = keys
	c.RequiredFeatures = []string{"challenge-v1"}
	return c
}

func dpKeys(dp *fakedataplane.Server) (current string, ids []string) {
	k := dp.ChallengeKeys()
	if k == nil {
		return "", nil
	}
	for _, key := range k.Keys {
		ids = append(ids, key.ID)
	}
	return k.Current, ids
}

func storedKeyIDs(t *testing.T, stateDir string) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(stateDir, "challenge-keys.json"))
	if err != nil {
		return nil
	}
	var list []struct {
		ID     string `json:"id"`
		Secret []byte `json:"secret"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, k := range list {
		if !bytes.Equal(k.Secret, secret(k.ID)) {
			t.Fatalf("stored secret of %s differs", k.ID)
		}
		ids = append(ids, k.ID)
	}
	return ids
}

// TestChallengeKeysAndCaptchas follows the cluster's keys from
// GetChallengeKeys to disk and the data plane through two rotations,
// installs captcha pools and reinstalls both after an nginx restart.
func TestChallengeKeysAndCaptchas(t *testing.T) {
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-k", ClusterID: "cl-k", ReportInterval: 1, KeepaliveInterval: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	root := t.TempDir()
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}
	for _, id := range []string{"key-1", "key-2", "key-3", "key-4", "key-5"} {
		console.SetChallengeKey(id, secret(id))
	}
	rev := console.Publish(underAttackConfig(keyRefs("key-3", "key-2", "key-1")))
	dp := fakedataplane.Start(t)
	cfg := h.agentConfig(dp.Socket)
	cfg.CaptchaPoolSize = 8
	cfg.ChallengeKeyRetry = 100 * time.Millisecond
	stop := startAgent(t, cfg, newFakeEngine(), dataplane.NewClient(dp.Socket))
	console.AddToken("k-token")
	if _, err := enroll.Run(context.Background(), enroll.Options{
		ServerURL: srv.URL, Token: "k-token", CASHA256: console.CA.Pin(), StateDir: h.stateDir, Logger: testLogger(t),
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	// Keys go in before the site table but never hold up the apply; a
	// push that fails is left to the data plane check.
	eventually(t, "keys installed", func() bool {
		current, ids := dpKeys(dp)
		return current == "key-2" && slices.Equal(ids, []string{"key-1", "key-2", "key-3"})
	})
	for _, k := range dp.ChallengeKeys().Keys {
		if got, _ := base64.StdEncoding.DecodeString(k.Secret); !bytes.Equal(got, secret(k.ID)) {
			t.Fatalf("secret of %s", k.ID)
		}
	}
	if reqs := console.ChallengeKeyRequests(); len(reqs) != 1 || !slices.Equal(reqs[0], []string{"key-1", "key-2", "key-3"}) {
		t.Fatalf("GetChallengeKeys calls: %v", reqs)
	}
	if st, err := os.Stat(filepath.Join(h.stateDir, "challenge-keys.json")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("challenge-keys.json: %v", err)
	}
	if got := storedKeyIDs(t, h.stateDir); !slices.Equal(got, []string{"key-1", "key-2", "key-3"}) {
		t.Fatalf("stored keys %v", got)
	}
	eventually(t, "captcha pool installed", func() bool {
		pool, _ := dp.Captchas()
		return pool != nil && len(pool.Images) == 8
	})
	pool, _ := dp.Captchas()
	for _, img := range pool.Images {
		raw, err := base64.StdEncoding.DecodeString(img.PNG)
		if err != nil || len(img.Answer) != captcha.Length || strings.Trim(img.Answer, captcha.Alphabet) != "" {
			t.Fatalf("captcha %q: %v", img.Answer, err)
		}
		if _, err := png.Decode(bytes.NewReader(raw)); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "features reported", func() bool {
		st := console.LastStatus()
		return hasFeature(st, "challenge-v1") && hasFeature(st, "ja4-v1")
	})

	// Rotation: only the new key is fetched; the dropped key stays while
	// the previous configuration names it.
	rev = console.Publish(underAttackConfig(keyRefs("key-4", "key-3", "key-2")))
	eventually(t, "rotated", func() bool {
		current, ids := dpKeys(dp)
		return current == "key-3" && slices.Equal(ids, []string{"key-2", "key-3", "key-4"})
	})
	eventually(t, "applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	if reqs := console.ChallengeKeyRequests(); len(reqs) != 2 || !slices.Equal(reqs[1], []string{"key-4"}) {
		t.Fatalf("GetChallengeKeys calls: %v", reqs)
	}
	if got := storedKeyIDs(t, h.stateDir); !slices.Equal(got, []string{"key-1", "key-2", "key-3", "key-4"}) {
		t.Fatalf("stored keys after one rotation %v", got)
	}
	rev = console.Publish(underAttackConfig(keyRefs("key-5", "key-4", "key-3")))
	eventually(t, "applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	if got := storedKeyIDs(t, h.stateDir); !slices.Equal(got, []string{"key-2", "key-3", "key-4", "key-5"}) {
		t.Fatalf("stored keys after two rotations %v", got)
	}

	// nginx restarted: keys and a captcha pool go in again.
	_, puts := dp.Captchas()
	dp.Restart()
	eventually(t, "keys and captchas reinstalled", func() bool {
		current, _ := dpKeys(dp)
		pool, n := dp.Captchas()
		return current == "key-4" && pool != nil && n > puts
	})

	// A key the console does not hand out yet is asked for again.
	rev = console.Publish(underAttackConfig(keyRefs("key-6", "key-5", "key-4")))
	eventually(t, "applied without key-6", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	console.SetChallengeKey("key-6", secret("key-6"))
	eventually(t, "key-6 fetched later", func() bool {
		_, ids := dpKeys(dp)
		return slices.Contains(ids, "key-6")
	})
	// The data plane check never replaces the keys of an apply with the
	// set of an older configuration.
	var currents []string
	for _, k := range dp.KeySets() {
		currents = append(currents, k.Current)
	}
	if !slices.IsSorted(currents) || slices.Contains(currents, "") {
		t.Fatalf("current key of each key set put: %q", currents)
	}

	// Offline restart: the stored keys go back into a fresh data plane.
	stop()
	console.Close()
	srv.Close()
	dp2 := fakedataplane.Start(t)
	cfg2 := h.agentConfig(dp2.Socket)
	cfg2.CaptchaPoolSize = 8
	startAgent(t, cfg2, newFakeEngine(), dataplane.NewClient(dp2.Socket))
	eventually(t, "stored keys served offline", func() bool {
		current, ids := dpKeys(dp2)
		return current == "key-5" && slices.Equal(ids, []string{"key-4", "key-5", "key-6"})
	})
}

// A configuration without challenges leaves the data plane without keys
// and captchas.
func TestNoChallengesNoKeys(t *testing.T) {
	e := startEnrolled(t, "nokeys", func(c *agent.Config) { c.CaptchaInterval = 100 * time.Millisecond }, demoSite("site-a", "a.test"))
	time.Sleep(500 * time.Millisecond)
	if k := e.dp.ChallengeKeys(); k != nil {
		t.Fatalf("keys pushed without challenges: %+v", k)
	}
	if pool, _ := e.dp.Captchas(); pool != nil {
		t.Fatal("captchas pushed without challenges")
	}
	if len(e.console.ChallengeKeyRequests()) != 0 {
		t.Fatal("GetChallengeKeys called without challenge keys")
	}
}

// TestSecurityEvents reports CC events in batches of at most 500 with
// their ids, retries failed batches and reports the sites above normal.
func TestSecurityEvents(t *testing.T) {
	e := startEnrolled(t, "sec", func(c *agent.Config) { c.SecurityInterval = 100 * time.Millisecond }, demoSite("site-a", "a.test"))
	e.console.FailReportSecurityEvents(1)
	var events []dataplane.SecurityEvent
	for i := range 1200 {
		events = append(events, dataplane.SecurityEvent{
			ID: fmt.Sprintf("b00t-%d", i), SiteID: "site-a", Time: 1790000000.5 + float64(i), Kind: "site_level",
			Level: "js", PreviousLevel: "cookie302", Metric: "site_qps", Observed: 1200, Threshold: 1000,
			TopIPs:   dataplane.List[dataplane.TopCount]{{Value: "198.51.100.23", Count: 812.4}},
			TopPaths: dataplane.List[dataplane.TopCount]{{Value: "/login", Count: 900}},
		})
	}
	events = append(events,
		dataplane.SecurityEvent{ID: "b00t-x", SiteID: "site-a", Time: 1790000000, Kind: "unknown"},
		dataplane.SecurityEvent{ID: "bad id", SiteID: "site-a", Time: 1790000000, Kind: "ip_banned"},
		dataplane.SecurityEvent{ID: "b00t-ip", SiteID: "site-a", Time: 1790000001, Kind: "ip_banned", Address: "198.51.100.23",
			Metric: "ip_qps", Observed: 61, Threshold: 50},
	)
	e.dp.AddSecurityEvents(events...)
	eventually(t, "events reported", func() bool {
		got, _ := e.console.SecurityEvents()
		return len(got) == 1201
	})
	got, calls := e.console.SecurityEvents()
	for _, n := range calls {
		if n > 500 {
			t.Fatalf("a call with %d events", n)
		}
	}
	first := got[0]
	if first.GetId() != "b00t-0" || first.GetKind() != nodev1.SecurityEventKind_SECURITY_EVENT_KIND_SITE_LEVEL ||
		first.GetLevel() != "js" || first.GetPreviousLevel() != "cookie302" || first.GetOccurredAt().AsTime().UnixMilli() != 1790000000500 ||
		first.GetTopIps()[0].GetCount() != 812 || first.GetTopPaths()[0].GetValue() != "/login" {
		t.Fatalf("first event = %v", first)
	}
	last := got[len(got)-1]
	if last.GetKind() != nodev1.SecurityEventKind_SECURITY_EVENT_KIND_IP_BANNED || last.GetAddress() != "198.51.100.23" {
		t.Fatalf("ban event = %v", last)
	}

	// Sites at normal count only while some of their paths are escalated.
	e.dp.SetSecurity(
		dataplane.SecuritySite{SiteID: "site-a", Level: "pow", EscalatedPaths: 2},
		dataplane.SecuritySite{SiteID: "site-b", Level: "normal", EscalatedPaths: 1},
		dataplane.SecuritySite{SiteID: "site-c", Level: "normal"},
	)
	eventually(t, "security state reported", func() bool {
		s := e.console.LastStatus().GetSecurity()
		return len(s) == 2 && s[0].GetSiteId() == "site-a" && s[0].GetLevel() == "pow" && s[0].GetEscalatedPaths() == 2 &&
			s[1].GetSiteId() == "site-b" && s[1].GetLevel() == "normal" && s[1].GetEscalatedPaths() == 1
	})
}
