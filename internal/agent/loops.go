package agent

import (
	"cmp"
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"sort"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/controlplane"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/healthcheck"
	"github.com/marvinli001/edgeweir-node/internal/hostinfo"
	"github.com/marvinli001/edgeweir-node/internal/pki"
	"github.com/marvinli001/edgeweir-node/internal/upgrade"
)

func (a *Agent) logRPCError(msg string, err error) {
	if controlplane.IsAuthError(err) {
		a.log.Error(msg+": the console rejected this node's credentials (node deleted or certificate revoked/expired?); "+
			"still serving the last-known-good configuration; re-enroll with `edgeweir-node enroll --force` if needed", "err", err)
		return
	}
	a.log.Warn(msg, "err", err)
}

// watchLoop keeps a WatchConfig stream open, reconnecting with jittered
// exponential backoff (1s → 30s).
func (a *Agent) watchLoop(ctx context.Context) {
	backoff := a.cfg.WatchBackoffMin
	for {
		gotMessage, err := a.watchOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if gotMessage {
			backoff = a.cfg.WatchBackoffMin
		}
		wait := backoff/2 + rand.N(backoff/2+1)
		if err != nil {
			a.logRPCError("config watch stream ended; reconnecting in "+wait.Round(time.Millisecond).String(), err)
		}
		if !sleepCtx(ctx, wait) {
			return
		}
		backoff = min(backoff*2, a.cfg.WatchBackoffMax)
	}
}

func (a *Agent) watchOnce(ctx context.Context) (gotMessage bool, err error) {
	changed := a.channel.Changed()
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-changed: // credentials renewed: reconnect with the new certificate
			cancel()
		case <-wctx.Done():
		}
	}()

	stream, err := a.channel.Client().WatchConfig(wctx, connect.NewRequest(&nodev1.WatchConfigRequest{
		KnownRevision: a.appliedRevision(),
	}))
	if err != nil {
		return false, err
	}
	defer stream.Close()

	// A dead connection is detected when neither a revision nor a
	// keepalive (every ~15s) arrives within WatchIdleTimeout.
	idle := time.AfterFunc(a.cfg.WatchIdleTimeout, cancel)
	defer idle.Stop()

	for stream.Receive() {
		idle.Reset(a.cfg.WatchIdleTimeout)
		gotMessage = true
		a.markConnected()
		msg := stream.Msg()
		if msg.GetEvent() == nodev1.WatchEvent_WATCH_EVENT_REVISION && msg.GetLatestRevision() > a.appliedRevision() {
			a.log.Info("new configuration revision announced", "revision", msg.GetLatestRevision(), "applied_revision", a.appliedRevision())
			a.triggerSync()
		}
		if msg.GetEvent() == nodev1.WatchEvent_WATCH_EVENT_TASKS {
			a.log.Info("tasks announced")
			a.triggerTasks()
		}
		if msg.GetEvent() == nodev1.WatchEvent_WATCH_EVENT_BANS && msg.GetBanSequence() > a.appliedBanSequence() {
			a.log.Debug("ban changes announced", "sequence", msg.GetBanSequence())
			a.triggerBans()
		}
	}
	if err := stream.Err(); err != nil {
		select {
		case <-changed:
			return gotMessage, nil
		default:
		}
		if wctx.Err() != nil && ctx.Err() == nil {
			return gotMessage, errors.New("no message or keepalive within " + a.cfg.WatchIdleTimeout.String())
		}
		return gotMessage, err
	}
	return gotMessage, errors.New("stream closed by the console")
}

// pollLoop is the fallback when the stream is unavailable or a
// notification was missed: GetConfig (and GetBans) every PollInterval regardless of
// stream health (cheap: an up-to-date node gets an empty diff). Every
// interval is jittered by ±20% so that nodes started together (a cluster
// restart, a console outage) do not poll in lockstep (ADR-0014).
func (a *Agent) pollLoop(ctx context.Context) {
	for sleepCtx(ctx, jittered(a.cfg.PollInterval)) {
		a.triggerSync()
		a.triggerBans()
	}
}

// jittered returns a random duration in [0.8d, 1.2d].
func jittered(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	return d*8/10 + rand.N(d*4/10+1)
}

// reportLoop sends ReportStatus immediately, after every apply attempt and
// every report interval (heartbeat).
func (a *Agent) reportLoop(ctx context.Context) {
	interval := a.cfg.ReportInterval
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-a.reportCh:
		}
		interval = a.reportOnce(ctx, interval)
		t.Reset(interval)
	}
}

func (a *Agent) statusRequest() *nodev1.ReportStatusRequest {
	a.mu.Lock()
	req := &nodev1.ReportStatusRequest{
		AppliedRevision:    a.applied.GetRevision(),
		AppliedContentHash: a.applied.GetContentHash(),
		State:              a.state,
		Message:            a.message,
		DataPlaneHealthy:   a.dpHealthy,
	}
	if !a.appliedAt.IsZero() {
		req.AppliedAt = timestamppb.New(a.appliedAt)
	}
	a.mu.Unlock()
	req.RevisionReceipt = a.receiptFor(req.AppliedRevision, req.AppliedContentHash)
	req.Info = hostinfo.Collect(a.engineVersion)
	req.Info.SupportedFeatures = append(req.Info.SupportedFeatures, a.extraFeatures()...)
	if a.cfg.Metrics.Enabled() {
		req.Info.SupportedFeatures = append(req.Info.SupportedFeatures, configir.FeatureMetrics)
	}

	if id := a.channel.Identity(); id != nil {
		req.CertificateNotAfter = timestamppb.New(id.Certificate.NotAfter)
	}
	return req
}

func (a *Agent) reportOnce(ctx context.Context, interval time.Duration) time.Duration {
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	defer cancel()
	req := a.statusRequest()
	if a.cfg.SupervisorSocket != "" {
		sctx, scancel := context.WithTimeout(ctx, time.Second)
		if upgrade.NewClient(a.cfg.SupervisorSocket).Available(sctx) {
			req.Info.SupportedFeatures = append(req.Info.SupportedFeatures, "self-upgrade-v1")
		}
		scancel()
	}
	req.Metrics = a.nodeMetrics(cctx)
	req.OriginHealth = a.originHealth(cctx)
	req.Bans = a.banReport(cctx)
	req.Security = a.securityReport(cctx)
	if a.kernelActive() {
		req.Info.SupportedFeatures = append(req.Info.SupportedFeatures, "kernel-ban-v1")
	}
	resp, err := a.channel.Client().ReportStatus(cctx, connect.NewRequest(req))
	if err != nil {
		if ctx.Err() == nil {
			a.logRPCError("ReportStatus failed", err)
			// The console refuses a disabled node's heartbeats but still
			// renews its certificate, so the node can come back once enabled.
			if connect.CodeOf(err) == connect.CodePermissionDenied {
				if id := a.channel.Identity(); id != nil && pki.NeedsRenewal(id.Certificate, time.Now()) {
					a.renew(ctx, "less than 1/3 of the certificate lifetime left while disabled")
				}
			}
		}
		return interval
	}
	a.markConnected()
	a.supervisorHealthy(ctx, req.GetState() == nodev1.ApplyState_APPLY_STATE_APPLIED && req.GetDataPlaneHealthy() && resp.Msg.GetLatestRevision() == req.GetAppliedRevision())
	a.log.Debug("status reported", "applied_revision", req.GetAppliedRevision(), "state", req.GetState().String())
	if s := resp.Msg.GetReportIntervalSeconds(); s > 0 {
		interval = min(max(time.Duration(s)*time.Second, time.Second), 5*time.Minute)
	}
	if resp.Msg.GetLatestRevision() > a.appliedRevision() {
		a.triggerSync()
	}
	if resp.Msg.GetTasksPending() {
		a.triggerTasks()
	}
	a.setProbing(ctx, resp.Msg.GetProbe())
	id := a.channel.Identity()
	if resp.Msg.GetRenewCertificate() || pki.NeedsRenewal(id.Certificate, time.Now()) {
		reason := "less than 1/3 of the certificate lifetime left"
		if resp.Msg.GetRenewCertificate() {
			reason = "requested by the console"
		}
		a.renew(ctx, reason)
	}
	return interval
}

// renew obtains a certificate for a freshly generated key and swaps the
// key pair atomically, then rebuilds the TLS client.
func (a *Agent) renew(ctx context.Context, reason string) {
	a.mu.Lock()
	if time.Since(a.lastRenew) < time.Minute {
		a.mu.Unlock()
		return
	}
	a.lastRenew = time.Now()
	a.mu.Unlock()

	if err := a.doRenew(ctx); err != nil {
		a.logRPCError("certificate renewal failed", err)
		return
	}
	id := a.channel.Identity()
	a.log.Info("node certificate renewed", "reason", reason,
		"not_after", id.Certificate.NotAfter.UTC().Format(time.RFC3339))
	a.triggerReport()
}

func (a *Agent) doRenew(ctx context.Context) error {
	id := a.channel.Identity()
	key, err := pki.GenerateKey()
	if err != nil {
		return err
	}
	csr, err := pki.CreateCSR(key, id.NodeID)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	defer cancel()
	resp, err := a.channel.Client().RenewCertificate(cctx, connect.NewRequest(&nodev1.RenewCertificateRequest{CsrPem: string(csr)}))
	if err != nil {
		return err
	}
	cert, err := pki.ParseCertificatePEM([]byte(resp.Msg.GetCertificatePem()))
	if err != nil {
		return err
	}
	// The pinned CA stays authoritative; CA rotation is not supported yet.
	if err := pki.VerifyNodeCertificate(cert, id.CA, key, time.Now()); err != nil {
		return err
	}
	if caPEM := resp.Msg.GetCaCertificatePem(); caPEM != "" {
		if ca, err := pki.ParseCertificatePEM([]byte(caPEM)); err != nil || !ca.Equal(id.CA) {
			a.log.Warn("console returned a different CA certificate; CA rotation is not supported yet, keeping the pinned CA")
		}
	}
	keyPEM, err := pki.MarshalPrivateKeyPEM(key)
	if err != nil {
		return err
	}
	if err := a.ids.SwapCertificate(keyPEM, []byte(resp.Msg.GetCertificatePem())); err != nil {
		return err
	}
	return a.channel.Reload()
}

func convertStats(items []dataplane.MinuteStats) []*nodev1.MinuteStats {
	out := make([]*nodev1.MinuteStats, 0, len(items))
	for _, m := range items {
		codes := make(map[uint32]uint64, len(m.StatusCodes))
		for k, v := range m.StatusCodes {
			if c, err := strconv.ParseUint(k, 10, 32); err == nil {
				codes[uint32(c)] += v
			}
		}
		out = append(out, &nodev1.MinuteStats{
			Minute:        timestamppb.New(time.Unix(m.Minute, 0).UTC()),
			SiteId:        m.SiteID,
			Requests:      m.Requests,
			BytesSent:     m.BytesSent,
			BytesReceived: m.BytesReceived,
			CacheHits:     m.CacheHits,
			CacheMisses:   m.CacheMisses,
			StatusCodes:   codes,
			TopUrls:       topCounters(m.TopURLs),
			TopIps:        topCounters(m.TopIPs),
			WafRules:      wafRules(m.WAFRules),
		})
	}
	return out
}

// nodeMetrics measures the host metrics of a heartbeat (nil where the
// platform has none) with the data plane's active connections.
func (a *Agent) nodeMetrics(ctx context.Context) *nodev1.NodeMetrics {
	m, err := a.cfg.Metrics.Collect()
	if err != nil {
		a.log.Debug("some host metrics are unavailable", "err", err)
	}
	if m == nil {
		return nil
	}
	if st, err := a.dp.Status(ctx); err == nil {
		m.ActiveConnections = st.ConnectionsActive
	}
	return m
}

// maxOriginHealth bounds the origin health entries of one heartbeat.
const maxOriginHealth = 2000

// originHealth converts the data plane's passive health state and the
// active checks' state for ReportStatus.
func (a *Agent) originHealth(ctx context.Context) []*nodev1.OriginHealth {
	list, err := a.dp.OriginHealth(ctx)
	if err != nil {
		a.log.Debug("cannot read origin health", "err", err)
	}
	return mergeOriginHealth(list, a.health.Statuses())
}

// mergeOriginHealth returns one entry per origin and check: the passive
// check's entries (source PASSIVE) and the active check's for origins
// that are unhealthy or have failures (source ACTIVE, no down_until).
// Beyond maxOriginHealth entries the unhealthy ones are kept first.
func mergeOriginHealth(passive []dataplane.OriginHealth, active []healthcheck.Status) []*nodev1.OriginHealth {
	out := make([]*nodev1.OriginHealth, 0, len(passive)+len(active))
	for _, h := range passive {
		e := &nodev1.OriginHealth{
			SiteId:              h.SiteID,
			OriginId:            h.OriginID,
			Healthy:             h.Healthy,
			ConsecutiveFailures: h.Failures,
			LastError:           h.LastError,
			LastErrorCode:       h.LastErrorCode,
			LastErrorParams:     h.LastErrorParams,
			Source:              nodev1.OriginHealthSource_ORIGIN_HEALTH_SOURCE_PASSIVE,
		}
		if h.LastFailureAt > 0 {
			e.LastFailureAt = timestamppb.New(unixFloat(h.LastFailureAt))
		}
		if h.DownUntil > 0 {
			e.DownUntil = timestamppb.New(unixFloat(h.DownUntil))
		}
		out = append(out, e)
	}
	for _, s := range active {
		e := &nodev1.OriginHealth{
			SiteId:              s.SiteID,
			OriginId:            s.OriginID,
			Healthy:             s.Healthy,
			ConsecutiveFailures: s.ConsecutiveFailures,
			LastError:           s.LastError,
			LastErrorCode:       s.LastErrorCode,
			LastErrorParams:     s.LastErrorParams,
			Source:              nodev1.OriginHealthSource_ORIGIN_HEALTH_SOURCE_ACTIVE,
		}
		if !s.LastFailureAt.IsZero() {
			e.LastFailureAt = timestamppb.New(s.LastFailureAt.UTC())
		}
		out = append(out, e)
	}
	if len(out) > maxOriginHealth {
		slices.SortStableFunc(out, func(x, y *nodev1.OriginHealth) int {
			return cmp.Compare(boolRank(x.GetHealthy()), boolRank(y.GetHealthy()))
		})
		out = out[:maxOriginHealth]
	}
	return out
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

func unixFloat(s float64) time.Time {
	return time.UnixMilli(int64(s * 1000)).UTC()
}

// maxWAFRules bounds MinuteStats.waf_rules (the data plane keeps the
// heaviest 20 per site and minute as well).
const maxWAFRules = 20

// wafRules converts matched CRS rule counts; values that are not rule ids
// are dropped.
func wafRules(input map[string]uint64) []*nodev1.TopCounter {
	valid := make(map[string]uint64, len(input))
	for id, count := range input {
		if n, err := strconv.ParseUint(id, 10, 32); err == nil && n > 0 && strconv.FormatUint(n, 10) == id {
			valid[id] = count
		}
	}
	out := topCounters(valid)
	if len(out) > maxWAFRules {
		out = out[:maxWAFRules]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func topCounters(input map[string]uint64) []*nodev1.TopCounter {
	out := make([]*nodev1.TopCounter, 0, len(input))
	for value, count := range input {
		out = append(out, &nodev1.TopCounter{Value: value, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Value < out[j].Value
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}
