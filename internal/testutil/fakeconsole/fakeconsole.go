// Package fakeconsole is a minimal in-memory implementation of the
// console's NodeService and ProbeService (connect-go) used by the
// integration tests and the container smoke test. It enforces the same
// authentication rules as the real console: Enroll and EnrollProbe are
// authorised by single-use tokens, every other RPC requires an mTLS client
// certificate issued by the internal CA whose CN is the node id (NodeService,
// and ProbeService while the node may probe) or the probe id with
// O=Edgeweir Probe (ProbeService only).
package fakeconsole

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1/nodev1connect"
	"github.com/marvinli001/edgeweir-node/internal/pki/pkitest"
)

// Options configure a Console.
type Options struct {
	NodeID            string
	ClusterID         string
	NodeName          string
	CertLifetime      time.Duration
	KeepaliveInterval time.Duration
	ReportInterval    uint32
	// The probe that EnrollProbe registers (defaults probe-1, probe-east,
	// region-1).
	ProbeID   string
	ProbeName string
	RegionID  string
}

// GetConfigCall records one GetConfig exchange.
type GetConfigCall struct {
	Request  *nodev1.GetConfigRequest
	Snapshot bool
	Revision uint64
}

// Console is the fake NodeService.
type Console struct {
	logsSequence    uint64
	logsAckFailures int
	logsSequences   []uint64
	logs            []*nodev1.AccessLog
	nodev1connect.UnimplementedNodeServiceHandler

	CA   *pkitest.CA
	opts Options

	mu                 sync.Mutex
	tokens             map[string]bool
	revisions          []*nodev1.NodeConfig
	watchers           map[chan struct{}]struct{}
	statuses           []*nodev1.ReportStatusRequest
	getConfigs         []GetConfigCall
	stats              []*nodev1.MinuteStats
	l4Stats            []*nodev1.L4MinuteStats
	watermarks         []Watermark
	statsSequence      uint64
	statsQueryFailures int
	statsAckFailures   int
	statsSequences     []uint64
	corruptNextDiff    bool
	pinned             uint64 // serve this revision as the latest (0: the newest)
	renewNext          bool
	refuseReports      bool
	renewals           int
	enrollments        int
	mtlsCalls          map[string]int
	watchStreams       int
	credentials        map[string]*nodev1.OriginCredential
	credRequests       [][]string
	pendingTasks       []*nodev1.NodeTask
	taskPulls          []bool // purge_only of every PullTasks call
	taskResults        []*nodev1.ReportTaskResultRequest
	taskWatchers       map[chan struct{}]struct{}

	// Dynamic bans: the latest state of every ban id with its sequence.
	bans           map[string]*banRow
	banSeq         uint64
	banPageLimit   int
	banWatchers    map[chan struct{}]struct{}
	getBans        []*nodev1.GetBansRequest
	reportedBans   []*nodev1.AutoBan
	reportBansFail int

	// Challenges and CC events.
	challengeKeys      map[string][]byte
	keyRequests        [][]string
	ticketKeys         map[string][]byte
	ticketKeyRequests  [][]string
	certificates       map[string]*nodev1.CertificateMaterial
	securityEvents     []*nodev1.SecurityEvent
	securitySeen       map[string]bool
	securityCalls      []int
	reportSecurityFail int

	probe probeState

	// PURGE requests (SubmitPurge) and the error to answer them with.
	purges   []*nodev1.SubmitPurgeRequest
	purgeErr error

	done      chan struct{}
	closeOnce sync.Once
}

// New creates a console with a fresh internal CA.
func New(opts Options) (*Console, error) {
	if opts.NodeID == "" {
		opts.NodeID = "node-1"
	}
	if opts.ClusterID == "" {
		opts.ClusterID = "cluster-1"
	}
	if opts.NodeName == "" {
		opts.NodeName = "edge-1"
	}
	if opts.CertLifetime == 0 {
		opts.CertLifetime = 24 * time.Hour
	}
	if opts.KeepaliveInterval == 0 {
		opts.KeepaliveInterval = 15 * time.Second
	}
	if opts.ReportInterval == 0 {
		opts.ReportInterval = 15
	}
	if opts.ProbeID == "" {
		opts.ProbeID = "probe-1"
	}
	if opts.ProbeName == "" {
		opts.ProbeName = "probe-east"
	}
	if opts.RegionID == "" {
		opts.RegionID = "region-1"
	}
	ca, err := pkitest.NewCA("Edgeweir Fake Internal CA")
	if err != nil {
		return nil, err
	}
	return &Console{
		CA:            ca,
		opts:          opts,
		tokens:        map[string]bool{},
		watchers:      map[chan struct{}]struct{}{},
		taskWatchers:  map[chan struct{}]struct{}{},
		banWatchers:   map[chan struct{}]struct{}{},
		bans:          map[string]*banRow{},
		credentials:   map[string]*nodev1.OriginCredential{},
		challengeKeys: map[string][]byte{},
		ticketKeys:    map[string][]byte{},
		certificates:  map[string]*nodev1.CertificateMaterial{},
		securitySeen:  map[string]bool{},
		mtlsCalls:     map[string]int{},
		probe:         probeState{tokens: map[string]bool{}},
		done:          make(chan struct{}),
	}, nil
}

// Close ends all open WatchConfig streams.
func (c *Console) Close() {
	c.closeOnce.Do(func() { close(c.done) })
}

// Options returns the effective options.
func (c *Console) Options() Options { return c.opts }

// TLSConfig returns the server TLS configuration (leaf + CA chain, client
// certificates verified when presented).
func (c *Console) TLSConfig(dnsNames []string, ips []net.IP) (*tls.Config, error) {
	cert, err := c.CA.IssueServer(dnsNames, ips)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    c.CA.Pool(),
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

// Handler returns the HTTP handler serving NodeService and ProbeService.
func (c *Console) Handler() http.Handler {
	path, h := nodev1connect.NewNodeServiceHandler(c)
	mux := http.NewServeMux()
	mux.Handle(path, c.authenticate(h))
	path, h = nodev1connect.NewProbeServiceHandler(c)
	mux.Handle(path, c.authenticateProbe(h))
	return mux
}

var errWriter = connect.NewErrorWriter()

func (c *Console) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == nodev1connect.NodeServiceEnrollProcedure {
			next.ServeHTTP(w, r)
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			_ = errWriter.Write(w, r, connect.NewError(connect.CodeUnauthenticated, errors.New("client certificate required")))
			return
		}
		cn := r.TLS.PeerCertificates[0].Subject.CommonName
		if cn != c.opts.NodeID || isProbeCertificate(r.TLS.PeerCertificates[0]) {
			_ = errWriter.Write(w, r, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("unknown node %q", cn)))
			return
		}
		c.mu.Lock()
		c.mtlsCalls[r.URL.Path]++
		c.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

// AddToken registers a single-use enrollment token.
func (c *Console) AddToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tokens[token] = true
}

// Publish stores cfg as the next revision (canonicalized and hashed) and
// notifies watchers. It returns the new revision.
func (c *Console) Publish(cfg *nodev1.NodeConfig) uint64 {
	cfg = proto.CloneOf(cfg)
	c.mu.Lock()
	rev := uint64(len(c.revisions) + 1)
	cfg.Revision = rev
	cfg.ClusterId = c.opts.ClusterID
	configir.Canonicalize(cfg)
	h, err := configir.ContentHash(cfg)
	if err != nil {
		c.mu.Unlock()
		panic(err)
	}
	cfg.ContentHash = h
	c.revisions = append(c.revisions, cfg)
	watchers := make([]chan struct{}, 0, len(c.watchers))
	for w := range c.watchers {
		watchers = append(watchers, w)
	}
	c.mu.Unlock()
	for _, w := range watchers {
		select {
		case w <- struct{}{}:
		default:
		}
	}
	return rev
}

// CorruptNextDiff makes the next diff announce a wrong content hash.
func (c *Console) CorruptNextDiff() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.corruptNextDiff = true
}

// RefuseReports answers ReportStatus with PermissionDenied while on, as the
// console does for a disabled node.
func (c *Console) RefuseReports(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refuseReports = on
}

// RequestRenewal sets renew_certificate in the next ReportStatus response.
func (c *Console) RequestRenewal() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.renewNext = true
}

// Statuses returns all ReportStatus requests received so far.
func (c *Console) Statuses() []*nodev1.ReportStatusRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.statuses)
}

// LastStatus returns the latest ReportStatus request, or nil.
func (c *Console) LastStatus() *nodev1.ReportStatusRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.statuses) == 0 {
		return nil
	}
	return c.statuses[len(c.statuses)-1]
}

// GetConfigCalls returns all GetConfig exchanges.
func (c *Console) GetConfigCalls() []GetConfigCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.getConfigs)
}

// Stats returns all uploaded minute stats.
// Watermark is one complete_until a node reported, with the batch sequence
// of its request and the highest sequence acknowledged at that time.
type Watermark struct {
	CompleteUntil time.Time
	BatchSequence uint64
	Acknowledged  uint64
}

// Watermarks returns the statistics watermarks received, oldest first.
func (c *Console) Watermarks() []Watermark {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Watermark(nil), c.watermarks...)
}

func (c *Console) Stats() []*nodev1.MinuteStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.stats)
}

// L4Stats returns the layer-4 buckets of the accepted statistics batches.
func (c *Console) L4Stats() []*nodev1.L4MinuteStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.l4Stats)
}

// Counters returns enrollments, renewals, watch streams and per-procedure
// mTLS call counts.
func (c *Console) Counters() (enrollments, renewals, watchStreams int, mtls map[string]int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m := make(map[string]int, len(c.mtlsCalls))
	for k, v := range c.mtlsCalls {
		m[k] = v
	}
	return c.enrollments, c.renewals, c.watchStreams, m
}

func (c *Console) latest() *nodev1.NodeConfig {
	if len(c.revisions) == 0 {
		return nil
	}
	if c.pinned != 0 {
		return c.revision(c.pinned)
	}
	return c.revisions[len(c.revisions)-1]
}

// PinLatest makes the console serve revision rev as its latest one (a
// console restored from an older backup); 0 serves the newest again.
func (c *Console) PinLatest(rev uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pinned = rev
}

func (c *Console) revision(r uint64) *nodev1.NodeConfig {
	if r == 0 || r > uint64(len(c.revisions)) {
		return nil
	}
	return c.revisions[r-1]
}

// Enroll implements NodeService.
func (c *Console) Enroll(_ context.Context, req *connect.Request[nodev1.EnrollRequest]) (*connect.Response[nodev1.EnrollResponse], error) {
	c.mu.Lock()
	ok := c.tokens[req.Msg.GetToken()]
	if ok {
		delete(c.tokens, req.Msg.GetToken())
	}
	c.mu.Unlock()
	if !ok {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("invalid or already used enrollment token"))
	}
	certPEM, cert, err := c.CA.SignCSR([]byte(req.Msg.GetCsrPem()), c.opts.NodeID, c.opts.CertLifetime)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	c.mu.Lock()
	c.enrollments++
	c.mu.Unlock()
	return connect.NewResponse(&nodev1.EnrollResponse{
		NodeId:           c.opts.NodeID,
		ClusterId:        c.opts.ClusterID,
		NodeName:         c.opts.NodeName,
		CertificatePem:   string(certPEM),
		CaCertificatePem: string(c.CA.PEM),
		NotAfter:         timestamppb.New(cert.NotAfter),
	}), nil
}

// RenewCertificate implements NodeService.
func (c *Console) RenewCertificate(_ context.Context, req *connect.Request[nodev1.RenewCertificateRequest]) (*connect.Response[nodev1.RenewCertificateResponse], error) {
	certPEM, cert, err := c.CA.SignCSR([]byte(req.Msg.GetCsrPem()), c.opts.NodeID, c.opts.CertLifetime)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	c.mu.Lock()
	c.renewals++
	c.mu.Unlock()
	return connect.NewResponse(&nodev1.RenewCertificateResponse{
		CertificatePem:   string(certPEM),
		CaCertificatePem: string(c.CA.PEM),
		NotAfter:         timestamppb.New(cert.NotAfter),
	}), nil
}

// WatchConfig implements NodeService.
func (c *Console) WatchConfig(ctx context.Context, _ *connect.Request[nodev1.WatchConfigRequest], stream *connect.ServerStream[nodev1.WatchConfigResponse]) error {
	notify := make(chan struct{}, 1)
	tasks := make(chan struct{}, 1)
	bans := make(chan struct{}, 1)
	c.mu.Lock()
	c.watchers[notify] = struct{}{}
	c.taskWatchers[tasks] = struct{}{}
	c.banWatchers[bans] = struct{}{}
	c.watchStreams++
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.watchers, notify)
		delete(c.taskWatchers, tasks)
		delete(c.banWatchers, bans)
		c.mu.Unlock()
	}()
	sendBans := func() error {
		c.mu.Lock()
		seq := c.banSeq
		c.mu.Unlock()
		return stream.Send(&nodev1.WatchConfigResponse{Event: nodev1.WatchEvent_WATCH_EVENT_BANS, BanSequence: seq})
	}

	sendRevision := func() error {
		c.mu.Lock()
		l := c.latest()
		c.mu.Unlock()
		return stream.Send(&nodev1.WatchConfigResponse{
			Event:          nodev1.WatchEvent_WATCH_EVENT_REVISION,
			LatestRevision: l.GetRevision(),
			ContentHash:    l.GetContentHash(),
		})
	}
	if err := sendRevision(); err != nil {
		return err
	}
	if err := sendBans(); err != nil {
		return err
	}
	t := time.NewTicker(c.opts.KeepaliveInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.done:
			return connect.NewError(connect.CodeUnavailable, errors.New("console shutting down"))
		case <-notify:
			if err := sendRevision(); err != nil {
				return err
			}
		case <-tasks:
			if err := stream.Send(&nodev1.WatchConfigResponse{Event: nodev1.WatchEvent_WATCH_EVENT_TASKS}); err != nil {
				return err
			}
		case <-bans:
			if err := sendBans(); err != nil {
				return err
			}
		case <-t.C:
			if err := stream.Send(&nodev1.WatchConfigResponse{Event: nodev1.WatchEvent_WATCH_EVENT_KEEPALIVE}); err != nil {
				return err
			}
		}
	}
}

// GetConfig implements NodeService.
func (c *Console) GetConfig(_ context.Context, req *connect.Request[nodev1.GetConfigRequest]) (*connect.Response[nodev1.GetConfigResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	target := c.latest()
	if req.Msg.GetRevision() != 0 {
		target = c.revision(req.Msg.GetRevision())
	}
	if target == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such revision"))
	}
	resp := &nodev1.GetConfigResponse{GeneratedAt: timestamppb.Now(), RevisionReceipt: fmt.Sprintf("test-receipt/%d", target.GetRevision())}
	call := GetConfigCall{Request: proto.CloneOf(req.Msg), Revision: target.GetRevision()}
	if base := c.revision(req.Msg.GetBaseRevision()); base != nil && base.GetRevision() <= target.GetRevision() {
		d := configir.Diff(base, target)
		if c.corruptNextDiff {
			c.corruptNextDiff = false
			d.ContentHash = "deadbeef" + d.ContentHash[8:]
		}
		resp.Payload = &nodev1.GetConfigResponse_Diff{Diff: d}
	} else {
		call.Snapshot = true
		resp.Payload = &nodev1.GetConfigResponse_Snapshot{Snapshot: proto.CloneOf(target)}
	}
	c.getConfigs = append(c.getConfigs, call)
	return connect.NewResponse(resp), nil
}

// ReportStatus implements NodeService.
func (c *Console) ReportStatus(_ context.Context, req *connect.Request[nodev1.ReportStatusRequest]) (*connect.Response[nodev1.ReportStatusResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refuseReports {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("node is disabled"))
	}
	c.statuses = append(c.statuses, proto.CloneOf(req.Msg))
	renew := c.renewNext
	c.renewNext = false
	return connect.NewResponse(&nodev1.ReportStatusResponse{
		LatestRevision:        c.latest().GetRevision(),
		RenewCertificate:      renew,
		ReportIntervalSeconds: c.opts.ReportInterval,
		TasksPending:          len(c.pendingTasks) > 0,
		Probe:                 c.probe.nodeProbe,
	}), nil
}

// SetCredential makes GetOriginCredentials hand out cred.
func (c *Console) SetCredential(cred *nodev1.OriginCredential) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.credentials[cred.GetId()] = proto.CloneOf(cred)
}

// CredentialRequests returns the ids of every GetOriginCredentials call.
func (c *Console) CredentialRequests() [][]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.credRequests)
}

// AddTask queues a task and announces it on open watch streams (unless
// quiet, which leaves discovery to heartbeats and polling).
func (c *Console) AddTask(task *nodev1.NodeTask, quiet bool) {
	c.AddTasks(quiet, task)
}

// AddTasks queues several tasks at once (one PullTasks sees all of them).
func (c *Console) AddTasks(quiet bool, tasks ...*nodev1.NodeTask) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, task := range tasks {
		c.pendingTasks = append(c.pendingTasks, proto.CloneOf(task))
	}
	if quiet {
		return
	}
	for ch := range c.taskWatchers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// TaskResults returns every reported task result.
func (c *Console) TaskResults() []*nodev1.ReportTaskResultRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.taskResults)
}

// SubmitPurge implements NodeService: records the request and answers
// with task "purge-<n>", or with the error SetPurgeError set.
func (c *Console) SubmitPurge(_ context.Context, req *connect.Request[nodev1.SubmitPurgeRequest]) (*connect.Response[nodev1.SubmitPurgeResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.purgeErr != nil {
		return nil, c.purgeErr
	}
	c.purges = append(c.purges, proto.CloneOf(req.Msg))
	return connect.NewResponse(&nodev1.SubmitPurgeResponse{TaskId: fmt.Sprintf("purge-%d", len(c.purges))}), nil
}

// SetPurgeError makes SubmitPurge fail with err (nil: succeed again).
func (c *Console) SetPurgeError(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeErr = err
}

// Purges returns every accepted SubmitPurge request.
func (c *Console) Purges() []*nodev1.SubmitPurgeRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.purges)
}

// GetOriginCredentials implements NodeService.
func (c *Console) GetOriginCredentials(_ context.Context, req *connect.Request[nodev1.GetOriginCredentialsRequest]) (*connect.Response[nodev1.GetOriginCredentialsResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.credRequests = append(c.credRequests, slices.Clone(req.Msg.GetIds()))
	resp := &nodev1.GetOriginCredentialsResponse{}
	for _, id := range req.Msg.GetIds() {
		if cred, ok := c.credentials[id]; ok {
			resp.Credentials = append(resp.Credentials, proto.CloneOf(cred))
		}
	}
	return connect.NewResponse(resp), nil
}

// PullTasks implements NodeService: every queued task is handed out once.
func (c *Console) PullTasks(_ context.Context, req *connect.Request[nodev1.PullTasksRequest]) (*connect.Response[nodev1.PullTasksResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	max := len(c.pendingTasks)
	if m := int(req.Msg.GetMaxTasks()); m > 0 && m < max {
		max = m
	}
	var out, rest []*nodev1.NodeTask
	for _, task := range c.pendingTasks {
		_, purge := task.GetKind().(*nodev1.NodeTask_Purge)
		if len(out) < max && (purge || !req.Msg.GetPurgeOnly()) {
			out = append(out, task)
		} else {
			rest = append(rest, task)
		}
	}
	c.pendingTasks = rest
	c.taskPulls = append(c.taskPulls, req.Msg.GetPurgeOnly())
	return connect.NewResponse(&nodev1.PullTasksResponse{Tasks: out}), nil
}

// TaskPulls returns purge_only of every PullTasks call so far.
func (c *Console) TaskPulls() []bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.taskPulls)
}

// ReportTaskResult implements NodeService.
func (c *Console) ReportTaskResult(_ context.Context, req *connect.Request[nodev1.ReportTaskResultRequest]) (*connect.Response[nodev1.ReportTaskResultResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.taskResults = append(c.taskResults, proto.CloneOf(req.Msg))
	return connect.NewResponse(&nodev1.ReportTaskResultResponse{}), nil
}

// ReportStats implements NodeService.
func (c *Console) ReportStats(_ context.Context, req *connect.Request[nodev1.ReportStatsRequest]) (*connect.Response[nodev1.ReportStatsResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if req.Msg.BatchSequence == 0 && len(req.Msg.Stats) == 0 {
		return connect.NewResponse(&nodev1.ReportStatsResponse{BatchSequence: c.statsSequence}), nil
	}
	accepted := uint32(0)
	c.statsSequences = append(c.statsSequences, req.Msg.BatchSequence)
	if req.Msg.BatchSequence > c.statsSequence {
		for _, s := range req.Msg.Stats {
			c.stats = append(c.stats, proto.CloneOf(s))
		}
		accepted = uint32(len(req.Msg.Stats))
		c.statsSequence = req.Msg.BatchSequence
	}
	if c.statsAckFailures > 0 {
		c.statsAckFailures--
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("test acknowledgement lost after commit"))
	}
	return connect.NewResponse(&nodev1.ReportStatsResponse{Accepted: accepted, BatchSequence: req.Msg.BatchSequence}), nil
}

func (c *Console) ReportStatsV2(ctx context.Context, req *connect.Request[nodev1.ReportStatsV2Request]) (*connect.Response[nodev1.ReportStatsV2Response], error) {
	// Layer-4 buckets share the batch (and its sequence) with the sites'.
	c.mu.Lock()
	if req.Msg.BatchSequence == 0 && req.Msg.CompleteUntil == nil && c.statsQueryFailures > 0 {
		c.statsQueryFailures--
		c.mu.Unlock()
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("test cursor query failure"))
	}
	if req.Msg.BatchSequence > c.statsSequence {
		for _, s := range req.Msg.L4Stats {
			c.l4Stats = append(c.l4Stats, proto.CloneOf(s))
		}
	}
	c.mu.Unlock()
	result, err := c.ReportStats(ctx, connect.NewRequest(&nodev1.ReportStatsRequest{Stats: req.Msg.Stats, BatchSequence: req.Msg.BatchSequence}))
	if err != nil {
		return nil, err
	}
	if req.Msg.CompleteUntil != nil {
		c.mu.Lock()
		c.watermarks = append(c.watermarks, Watermark{
			CompleteUntil: req.Msg.CompleteUntil.AsTime(),
			BatchSequence: req.Msg.BatchSequence,
			Acknowledged:  c.statsSequence,
		})
		c.mu.Unlock()
	}
	return connect.NewResponse(&nodev1.ReportStatsV2Response{Accepted: result.Msg.Accepted, BatchSequence: result.Msg.BatchSequence}), nil
}

// FailStatsQueries makes the next count statistics cursor queries fail
// (an empty ReportStatsV2 without a watermark), as while the console is
// unreachable.
func (c *Console) FailStatsQueries(count int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.statsQueryFailures = count
}

func (c *Console) FailStatsAcknowledgements(count int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.statsAckFailures = count
}
func (c *Console) StatsSequences() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.statsSequences)
}

// ReportLogs implements NodeService.
func (c *Console) ReportLogs(_ context.Context, req *connect.Request[nodev1.ReportLogsRequest]) (*connect.Response[nodev1.ReportLogsResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if req.Msg.BatchSequence == 0 && len(req.Msg.Logs) == 0 {
		return connect.NewResponse(&nodev1.ReportLogsResponse{BatchSequence: c.logsSequence}), nil
	}
	accepted := uint32(0)
	c.logsSequences = append(c.logsSequences, req.Msg.BatchSequence)
	if req.Msg.BatchSequence > c.logsSequence {
		for _, s := range req.Msg.Logs {
			c.logs = append(c.logs, proto.CloneOf(s))
		}
		accepted = uint32(len(req.Msg.Logs))
		c.logsSequence = req.Msg.BatchSequence
	}
	if c.logsAckFailures > 0 {
		c.logsAckFailures--
		return nil, connect.NewError(connect.CodeUnavailable, fmt.Errorf("test acknowledgement lost after commit"))
	}
	return connect.NewResponse(&nodev1.ReportLogsResponse{Accepted: accepted, BatchSequence: req.Msg.BatchSequence}), nil
}

func (c *Console) FailLogsAcknowledgements(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.logsAckFailures = n
}
func (c *Console) LogsSequences() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.logsSequences)
}
func (c *Console) Logs() []*nodev1.AccessLog {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := []*nodev1.AccessLog{}
	for _, l := range c.logs {
		out = append(out, proto.CloneOf(l))
	}
	return out
}

type banRow struct {
	ban     *nodev1.Ban
	seq     uint64
	removed bool
	// own: an unshared automatic ban of the node, lifted (lifted_own_bans).
	own bool
}

// AddBan stores (or replaces, by id) an active ban under a new sequence
// and announces it on open watch streams. It returns the sequence.
func (c *Console) AddBan(b *nodev1.Ban) uint64 {
	c.mu.Lock()
	c.banSeq++
	c.bans[b.GetId()] = &banRow{ban: proto.CloneOf(b), seq: c.banSeq}
	seq := c.banSeq
	c.mu.Unlock()
	c.notifyBans()
	return seq
}

// RemoveBan lifts a ban under a new sequence and announces it.
func (c *Console) RemoveBan(id string) uint64 {
	c.mu.Lock()
	c.banSeq++
	if row, ok := c.bans[id]; ok {
		row.removed, row.seq = true, c.banSeq
	}
	seq := c.banSeq
	c.mu.Unlock()
	c.notifyBans()
	return seq
}

// LiftOwnBan lifts an automatic ban of the node that was never shared
// (GetBans returns it in lifted_own_bans) and announces it.
func (c *Console) LiftOwnBan(b *nodev1.Ban) uint64 {
	c.mu.Lock()
	c.banSeq++
	c.bans[b.GetId()] = &banRow{ban: proto.CloneOf(b), seq: c.banSeq, removed: true, own: true}
	seq := c.banSeq
	c.mu.Unlock()
	c.notifyBans()
	return seq
}

// SetBanSequence moves the ban sequence (a console restored from an older
// backup sets it below what nodes have applied).
func (c *Console) SetBanSequence(seq uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.banSeq = seq
}

// SetBanPageLimit caps the bans of one GetBans page (0: 5000).
func (c *Console) SetBanPageLimit(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.banPageLimit = n
}

// FailReportBans makes the next n ReportBans calls fail.
func (c *Console) FailReportBans(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reportBansFail = n
}

// GetBansCalls returns every GetBans request.
func (c *Console) GetBansCalls() []*nodev1.GetBansRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.getBans)
}

// ReportedBans returns every automatic ban the node reported.
func (c *Console) ReportedBans() []*nodev1.AutoBan {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.reportedBans)
}

func (c *Console) notifyBans() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for ch := range c.banWatchers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// GetBans implements NodeService like the console: a snapshot (reset)
// when after_sequence is 0 or ahead of the console, otherwise the changes
// after it, in sequence order and paged.
func (c *Console) GetBans(_ context.Context, req *connect.Request[nodev1.GetBansRequest]) (*connect.Response[nodev1.GetBansResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getBans = append(c.getBans, proto.CloneOf(req.Msg))
	after := req.Msg.GetAfterSequence()
	resp := &nodev1.GetBansResponse{}
	if after == 0 || after > c.banSeq {
		resp.Reset_, after = true, 0
	}
	limit := 5000
	if c.banPageLimit > 0 {
		limit = c.banPageLimit
	}
	if l := int(req.Msg.GetLimit()); l > 0 && l < limit {
		limit = l
	}
	rows := make([]*banRow, 0, len(c.bans))
	for _, row := range c.bans {
		if row.seq <= after {
			continue
		}
		// A snapshot only carries active bans; expired ones are never sent.
		if row.removed && resp.Reset_ || !row.removed && !row.ban.GetExpiresAt().AsTime().After(time.Now()) {
			continue
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b *banRow) int { return cmp.Compare(a.seq, b.seq) })
	resp.Sequence = c.banSeq
	if len(rows) > limit {
		rows, resp.More = rows[:limit], true
		resp.Sequence = rows[limit-1].seq
	}
	for _, row := range rows {
		if row.own {
			resp.LiftedOwnBans = append(resp.LiftedOwnBans, proto.CloneOf(row.ban))
		} else if row.removed {
			resp.RemovedIds = append(resp.RemovedIds, row.ban.GetId())
		} else {
			resp.Bans = append(resp.Bans, proto.CloneOf(row.ban))
		}
	}
	return connect.NewResponse(resp), nil
}

// ReportBans implements NodeService.
func (c *Console) ReportBans(_ context.Context, req *connect.Request[nodev1.ReportBansRequest]) (*connect.Response[nodev1.ReportBansResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reportBansFail > 0 {
		c.reportBansFail--
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("injected ReportBans failure"))
	}
	if len(req.Msg.GetBans()) > 1000 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("more than 1000 bans"))
	}
	for _, b := range req.Msg.GetBans() {
		c.reportedBans = append(c.reportedBans, proto.CloneOf(b))
	}
	return connect.NewResponse(&nodev1.ReportBansResponse{Accepted: uint32(len(req.Msg.GetBans()))}), nil
}

// SetChallengeKey makes GetChallengeKeys hand out a key.
func (c *Console) SetChallengeKey(id string, secret []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.challengeKeys[id] = slices.Clone(secret)
}

// ChallengeKeyRequests returns the ids of every GetChallengeKeys call.
func (c *Console) ChallengeKeyRequests() [][]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.keyRequests)
}

func (c *Console) GetChallengeKeys(_ context.Context, req *connect.Request[nodev1.GetChallengeKeysRequest]) (*connect.Response[nodev1.GetChallengeKeysResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyRequests = append(c.keyRequests, slices.Clone(req.Msg.GetIds()))
	resp := &nodev1.GetChallengeKeysResponse{}
	for _, id := range req.Msg.GetIds() {
		if secret, ok := c.challengeKeys[id]; ok {
			resp.Keys = append(resp.Keys, &nodev1.ChallengeKey{Id: id, Secret: slices.Clone(secret)})
		}
	}
	return connect.NewResponse(resp), nil
}

// SetCertificate makes GetCertificates hand out a site certificate.
func (c *Console) SetCertificate(m *nodev1.CertificateMaterial) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certificates[m.GetId()] = proto.CloneOf(m)
}

// GetCertificates implements NodeService: the certificates it knows,
// others left out.
func (c *Console) GetCertificates(_ context.Context, req *connect.Request[nodev1.GetCertificatesRequest]) (*connect.Response[nodev1.GetCertificatesResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	resp := &nodev1.GetCertificatesResponse{}
	for _, id := range req.Msg.GetIds() {
		if m, ok := c.certificates[id]; ok {
			resp.Certificates = append(resp.Certificates, proto.CloneOf(m))
		}
	}
	return connect.NewResponse(resp), nil
}

// SetSessionTicketKey makes GetSessionTicketKeys hand out a key.
func (c *Console) SetSessionTicketKey(id string, secret []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ticketKeys[id] = slices.Clone(secret)
}

// SessionTicketKeyRequests returns the ids of every GetSessionTicketKeys
// call.
func (c *Console) SessionTicketKeyRequests() [][]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.ticketKeyRequests)
}

// GetSessionTicketKeys implements NodeService: the keys it knows, others
// left out.
func (c *Console) GetSessionTicketKeys(_ context.Context, req *connect.Request[nodev1.GetSessionTicketKeysRequest]) (*connect.Response[nodev1.GetSessionTicketKeysResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ticketKeyRequests = append(c.ticketKeyRequests, slices.Clone(req.Msg.GetIds()))
	resp := &nodev1.GetSessionTicketKeysResponse{}
	for _, id := range req.Msg.GetIds() {
		if secret, ok := c.ticketKeys[id]; ok {
			resp.Keys = append(resp.Keys, &nodev1.SessionTicketKey{Id: id, Secret: slices.Clone(secret)})
		}
	}
	return connect.NewResponse(resp), nil
}

// FailReportSecurityEvents makes the next n ReportSecurityEvents calls fail.
func (c *Console) FailReportSecurityEvents(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reportSecurityFail = n
}

// SecurityEvents returns the stored events (each id once, in arrival order)
// and the size of every accepted call.
func (c *Console) SecurityEvents() ([]*nodev1.SecurityEvent, []int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.securityEvents), slices.Clone(c.securityCalls)
}

func (c *Console) ReportSecurityEvents(_ context.Context, req *connect.Request[nodev1.ReportSecurityEventsRequest]) (*connect.Response[nodev1.ReportSecurityEventsResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reportSecurityFail > 0 {
		c.reportSecurityFail--
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("injected ReportSecurityEvents failure"))
	}
	if len(req.Msg.GetEvents()) > 500 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("more than 500 events"))
	}
	c.securityCalls = append(c.securityCalls, len(req.Msg.GetEvents()))
	for _, e := range req.Msg.GetEvents() {
		if c.securitySeen[e.GetId()] {
			continue
		}
		c.securitySeen[e.GetId()] = true
		c.securityEvents = append(c.securityEvents, proto.CloneOf(e))
	}
	return connect.NewResponse(&nodev1.ReportSecurityEventsResponse{Accepted: uint32(len(req.Msg.GetEvents()))}), nil
}
