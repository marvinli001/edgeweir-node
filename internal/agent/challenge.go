package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marvinli001/edgeweir-node/internal/captcha"
	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// challengeKeysFile keeps the challenge pass keys of the current and the
// previous configuration (secrets, 0600) so that passes stay valid across
// restarts while the console is unreachable.
const challengeKeysFile = "challenge-keys.json"

// Bounds of a key secret (the console issues 32 random bytes).
const (
	minKeySecret = 16
	maxKeySecret = 256
)

type storedKey struct {
	ID     string `json:"id"`
	Secret []byte `json:"secret"`
}

func (a *Agent) challengeKeysPath() string { return filepath.Join(a.cfg.StateDir, challengeKeysFile) }

// loadChallengeKeys reads the persisted keys (missing file: none).
func (a *Agent) loadChallengeKeys() {
	raw, err := os.ReadFile(a.challengeKeysPath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			a.log.Warn("cannot read stored challenge keys", "err", err)
		}
		return
	}
	var list []storedKey
	if err := json.Unmarshal(raw, &list); err != nil {
		a.log.Warn("ignoring unreadable challenge keys file", "err", err)
		return
	}
	a.challengeMu.Lock()
	defer a.challengeMu.Unlock()
	for _, k := range list {
		if validKey(k.ID, k.Secret) {
			a.challengeKeys[k.ID] = k.Secret
		}
	}
}

func validKey(id string, secret []byte) bool {
	return id != "" && len(id) <= 128 && configir.ValidID(id) && len(secret) >= minKeySecret && len(secret) <= maxKeySecret
}

// saveChallengeKeysLocked persists the keys; challengeMu must be held.
func (a *Agent) saveChallengeKeysLocked() error {
	list := make([]storedKey, 0, len(a.challengeKeys))
	for id, secret := range a.challengeKeys {
		list = append(list, storedKey{ID: id, Secret: secret})
	}
	slices.SortFunc(list, func(x, y storedKey) int {
		switch {
		case x.ID < y.ID:
			return -1
		case x.ID > y.ID:
			return 1
		}
		return 0
	})
	raw, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(a.challengeKeysPath(), raw, 0o600)
}

// missingChallengeKeys returns the key ids plan names that the node does
// not hold.
func (a *Agent) missingChallengeKeys(plan *configir.Plan) []string {
	a.challengeMu.Lock()
	defer a.challengeMu.Unlock()
	var missing []string
	for _, id := range plan.ChallengeKeyIDs() {
		if _, ok := a.challengeKeys[id]; !ok {
			missing = append(missing, id)
		}
	}
	slices.Sort(missing)
	return missing
}

// ensureChallengeKeys fetches the keys plan names that the node does not
// hold (GetChallengeKeys over mTLS) and persists them. Transport errors
// are returned (the apply is retried); keys the console does not hand out
// stay missing.
func (a *Agent) ensureChallengeKeys(ctx context.Context, plan *configir.Plan) error {
	missing := a.missingChallengeKeys(plan)
	ch := a.connectedCh.Load()
	if len(missing) == 0 || ch == nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	resp, err := ch.Client().GetChallengeKeys(cctx, connect.NewRequest(&nodev1.GetChallengeKeysRequest{Ids: missing}))
	cancel()
	if err != nil {
		return fmt.Errorf("fetch challenge keys: %w", err)
	}
	a.challengeMu.Lock()
	defer a.challengeMu.Unlock()
	received := 0
	for _, k := range resp.Msg.GetKeys() {
		if !slices.Contains(missing, k.GetId()) || !validKey(k.GetId(), k.GetSecret()) {
			a.log.Warn("ignoring a challenge key the node did not ask for or with an invalid secret", "id", k.GetId())
			continue
		}
		a.challengeKeys[k.GetId()] = slices.Clone(k.GetSecret())
		received++
	}
	a.log.Info("challenge keys fetched", "requested", len(missing), "received", received)
	if received > 0 {
		if err := a.saveChallengeKeysLocked(); err != nil {
			return fmt.Errorf("persist challenge keys: %w", err)
		}
	}
	return nil
}

// pruneChallengeKeys forgets keys that neither the current nor the
// previous configuration (of the same cluster) names.
func (a *Agent) pruneChallengeKeys(current, previous *nodev1.NodeConfig) {
	keep := map[string]bool{}
	for _, config := range []*nodev1.NodeConfig{current, previous} {
		if config == nil || config.GetClusterId() != current.GetClusterId() {
			continue
		}
		for _, k := range config.GetChallengeKeys() {
			keep[k.GetId()] = true
		}
	}
	a.challengeMu.Lock()
	defer a.challengeMu.Unlock()
	changed := false
	for id := range a.challengeKeys {
		if !keep[id] {
			delete(a.challengeKeys, id)
			changed = true
		}
	}
	if changed {
		if err := a.saveChallengeKeysLocked(); err != nil {
			a.log.Warn("challenge key cleanup will retry", "err", err)
		}
	}
}

// desiredChallengeKeys is the key set the data plane must hold for plan:
// every named key the node has, the current one signing. Its id changes
// with the keys and their secrets.
func (a *Agent) desiredChallengeKeys(plan *configir.Plan) *dataplane.ChallengeKeys {
	out := &dataplane.ChallengeKeys{Keys: []dataplane.ChallengeKey{}}
	if plan == nil {
		out.ID = "none"
		return out
	}
	h := sha256.New()
	a.challengeMu.Lock()
	for _, id := range plan.ChallengeKeyIDs() {
		secret, ok := a.challengeKeys[id]
		if !ok {
			continue
		}
		out.Keys = append(out.Keys, dataplane.ChallengeKey{ID: id, Secret: base64.StdEncoding.EncodeToString(secret)})
		fmt.Fprintf(h, "%s\x00%x\x00", id, secret)
	}
	a.challengeMu.Unlock()
	slices.SortFunc(out.Keys, func(x, y dataplane.ChallengeKey) int {
		switch {
		case x.ID < y.ID:
			return -1
		case x.ID > y.ID:
			return 1
		}
		return 0
	})
	if current := plan.CurrentChallengeKey(); slices.ContainsFunc(out.Keys, func(k dataplane.ChallengeKey) bool { return k.ID == current }) {
		out.Current = current
	}
	fmt.Fprintf(h, "current\x00%s", out.Current)
	out.ID = hex.EncodeToString(h.Sum(nil))[:16]
	if len(out.Keys) == 0 {
		out.ID = "none"
	}
	return out
}

// pushChallengeKeys installs the key set of plan in the data plane when it
// differs from the one the data plane reports.
func (a *Agent) pushChallengeKeys(ctx context.Context, plan *configir.Plan) error {
	want := a.desiredChallengeKeys(plan)
	a.challengePushMu.Lock()
	defer a.challengePushMu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	st, err := a.dp.ChallengeStatus(cctx)
	cancel()
	if err != nil {
		return err
	}
	if st.KeysID == want.ID || (want.ID == "none" && st.KeysID == "" && len(st.Keys) == 0) {
		return nil
	}
	cctx, cancel = context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := a.dp.PutChallengeKeys(cctx, want); err != nil {
		return fmt.Errorf("push challenge keys: %w", err)
	}
	a.log.Info("challenge keys pushed to data plane", "keys", len(want.Keys), "current", want.Current)
	return nil
}

func (a *Agent) triggerCaptchas() {
	select {
	case a.captchaCh <- struct{}{}:
	default:
	}
}

// usesChallenges reports whether the plan in effect may challenge: the
// console sends challenge keys only then.
func (a *Agent) usesChallenges() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.plan != nil && len(a.plan.ChallengeKeys) > 0
}

// captchaLoop generates a fresh captcha pool every CaptchaInterval (and
// whenever the data plane lost it) while the configuration uses
// challenges, and installs it.
func (a *Agent) captchaLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.CaptchaInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.captchaCh:
		}
		if !a.usesChallenges() {
			continue
		}
		if err := a.pushCaptchas(ctx); err != nil && ctx.Err() == nil {
			a.log.Warn("cannot install the captcha pool; retrying", "err", err)
		}
	}
}

func (a *Agent) pushCaptchas(ctx context.Context) error {
	body := &dataplane.CaptchaPool{ID: strconv.FormatInt(time.Now().UnixNano(), 36), Images: make([]dataplane.Captcha, 0, a.cfg.CaptchaPoolSize)}
	seen := make(map[string]bool, a.cfg.CaptchaPoolSize)
	for len(body.Images) < a.cfg.CaptchaPoolSize {
		if err := ctx.Err(); err != nil {
			return err
		}
		img, err := captcha.New(nil)
		if err != nil {
			return err
		}
		if seen[img.Answer] {
			continue
		}
		seen[img.Answer] = true
		body.Images = append(body.Images, dataplane.Captcha{Answer: img.Answer, PNG: base64.StdEncoding.EncodeToString(img.PNG)})
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := a.dp.PutCaptchas(cctx, body); err != nil {
		return err
	}
	a.challengePushMu.Lock()
	a.captchaID = body.ID
	a.challengePushMu.Unlock()
	a.log.Debug("captcha pool installed", "images", len(body.Images))
	return nil
}

// pushChallengeKeysWithRetry installs the keys of a plan that uses
// challenges before its site table, retrying while nginx starts; a
// failure only delays them to the next data plane check.
func (a *Agent) pushChallengeKeysWithRetry(ctx context.Context, plan *configir.Plan) {
	if len(plan.ChallengeKeys) == 0 {
		return
	}
	deadline := time.Now().Add(a.cfg.PushTimeout)
	delay := 100 * time.Millisecond
	for {
		err := a.pushChallengeKeys(ctx, plan)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			a.log.Warn("cannot install challenge keys before the site table; retrying in the background", "err", err)
			return
		}
		if !sleepCtx(ctx, delay) {
			return
		}
		delay = min(delay*2, 2*time.Second)
	}
}

// reconcileChallenge runs with the data plane check: it fetches keys the
// applied configuration names but the node lacks (at most every
// ChallengeKeyRetry),
// reinstalls the key set after an nginx restart and asks for a new
// captcha pool when the data plane has none.
func (a *Agent) reconcileChallenge(ctx context.Context) {
	a.mu.Lock()
	plan := a.plan
	a.mu.Unlock()
	if plan == nil {
		return
	}
	if a.connectedCh.Load() != nil && len(a.missingChallengeKeys(plan)) > 0 && time.Since(a.keysFetchedAt) >= a.cfg.ChallengeKeyRetry {
		a.keysFetchedAt = time.Now()
		if err := a.ensureChallengeKeys(ctx, plan); err != nil {
			a.logRPCError("GetChallengeKeys failed; will retry", err)
		}
	}
	if err := a.pushChallengeKeys(ctx, plan); err != nil {
		a.log.Debug("cannot sync challenge keys", "err", err)
		return
	}
	if len(plan.ChallengeKeys) == 0 {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	st, err := a.dp.ChallengeStatus(cctx)
	cancel()
	a.challengePushMu.Lock()
	lost := err == nil && (st.Captchas == 0 || st.CaptchasID != a.captchaID)
	a.challengePushMu.Unlock()
	if lost {
		a.triggerCaptchas()
	}
}

// securityLoop drains CC events every SecurityInterval and reports them
// (ReportSecurityEvents, at most 500 per call, idempotent by event id).
// Unsent events stay in memory, at most 10000 (the oldest go first).
func (a *Agent) securityLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.SecurityInterval)
	defer t.Stop()
	var pending []*nodev1.SecurityEvent
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pending = a.reportSecurityEvents(ctx, pending)
	}
}

// Limits of the security event report.
const (
	securityBatch      = 500
	maxSecurityPending = 10000
)

func (a *Agent) reportSecurityEvents(ctx context.Context, pending []*nodev1.SecurityEvent) []*nodev1.SecurityEvent {
	for range maxSecurityPending / 1000 {
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		items, err := a.dp.DrainSecurity(dctx)
		cancel()
		if err != nil {
			a.log.Debug("cannot drain security events", "err", err)
			break
		}
		for _, item := range items {
			if e, ok := convertSecurityEvent(item); ok {
				pending = append(pending, e)
			}
		}
		if len(items) < 1000 {
			break
		}
	}
	if over := len(pending) - maxSecurityPending; over > 0 {
		a.log.Warn("dropping the oldest unreported security events", "dropped", over)
		pending = slices.Clone(pending[over:])
	}
	for len(pending) > 0 {
		n := min(securityBatch, len(pending))
		cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
		_, err := a.channel.Client().ReportSecurityEvents(cctx, connect.NewRequest(&nodev1.ReportSecurityEventsRequest{Events: pending[:n]}))
		cancel()
		if err != nil {
			if connect.CodeOf(err) == connect.CodeUnimplemented {
				a.securityUnsupported.Do(func() {
					a.log.Info("the console does not take security events (ReportSecurityEvents unimplemented)")
				})
			} else if ctx.Err() == nil {
				a.logRPCError("ReportSecurityEvents failed; will retry", err)
			}
			break
		}
		a.markConnected()
		pending = pending[n:]
	}
	return pending
}

var securityKinds = map[string]nodev1.SecurityEventKind{
	"site_level": nodev1.SecurityEventKind_SECURITY_EVENT_KIND_SITE_LEVEL,
	"path_level": nodev1.SecurityEventKind_SECURITY_EVENT_KIND_PATH_LEVEL,
	"ip_banned":  nodev1.SecurityEventKind_SECURITY_EVENT_KIND_IP_BANNED,
}

// convertSecurityEvent turns a drained CC event into its report.
func convertSecurityEvent(e dataplane.SecurityEvent) (*nodev1.SecurityEvent, bool) {
	kind, ok := securityKinds[e.Kind]
	if !ok || !configir.ValidID(e.ID) || !configir.ValidID(e.SiteID) || e.Time <= 0 {
		return nil, false
	}
	top := func(list []dataplane.TopCount) []*nodev1.TopCounter {
		out := make([]*nodev1.TopCounter, 0, min(len(list), 10))
		for _, t := range list {
			if len(out) == 10 {
				break
			}
			if t.Value == "" || t.Count < 0 {
				continue
			}
			out = append(out, &nodev1.TopCounter{Value: t.Value, Count: uint64(t.Count + 0.5)})
		}
		return out
	}
	return &nodev1.SecurityEvent{
		Id:            e.ID,
		SiteId:        e.SiteID,
		OccurredAt:    timestamppb.New(unixTime(e.Time)),
		Kind:          kind,
		Level:         e.Level,
		PreviousLevel: e.PreviousLevel,
		Path:          e.Path,
		Address:       e.Address,
		Metric:        e.Metric,
		Observed:      e.Observed,
		Threshold:     e.Threshold,
		TopIps:        top(e.TopIPs),
		TopPaths:      top(e.TopPaths),
	}, true
}

// securityReport is ReportStatusRequest.security: every site above normal.
func (a *Agent) securityReport(ctx context.Context) []*nodev1.SiteSecurity {
	st, err := a.dp.SecurityStatus(ctx)
	if err != nil {
		a.log.Debug("cannot read the CC state", "err", err)
		return nil
	}
	var out []*nodev1.SiteSecurity
	for _, s := range st.Sites {
		// A site at normal is left out unless some of its paths are escalated.
		if s.Level == "" || (s.Level == "normal" && s.EscalatedPaths <= 0) || len(out) == 2000 {
			continue
		}
		out = append(out, &nodev1.SiteSecurity{SiteId: s.SiteID, Level: s.Level, EscalatedPaths: uint32(max(s.EscalatedPaths, 0))})
	}
	return out
}
