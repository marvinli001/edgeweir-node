package fakeconsole

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"slices"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1/nodev1connect"
	"github.com/marvinli001/edgeweir-node/internal/pki/pkitest"
)

// probeState is the ProbeService side of the console.
type probeState struct {
	tokens      map[string]bool
	targets     *nodev1.GetProbeTargetsResponse
	renewNext   bool
	nodeProbe   bool // the node may probe (ReportStatusResponse.probe)
	enrollments int
	renewals    int
	calls       []ProbeTargetsCall
	reports     []ProbeReport
	failTargets int
	failReports int
}

// ProbeTargetsCall is one GetProbeTargets call: who made it (the probe or
// node id) and the ProbeInfo it sent.
type ProbeTargetsCall struct {
	Caller string
	Info   *nodev1.ProbeInfo
}

// ProbeReport is one ReportProbeResults call.
type ProbeReport struct {
	Caller  string
	Request *nodev1.ReportProbeResultsRequest
}

type callerKey struct{}

func isProbeCertificate(c *x509.Certificate) bool {
	return slices.Contains(c.Subject.Organization, pkitest.ProbeOrganization)
}

// authenticateProbe: EnrollProbe needs a token; the other ProbeService calls
// need the probe's certificate, or the node's while the node may probe.
func (c *Console) authenticateProbe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == nodev1connect.ProbeServiceEnrollProbeProcedure {
			next.ServeHTTP(w, r)
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			_ = errWriter.Write(w, r, connect.NewError(connect.CodeUnauthenticated, errors.New("client certificate required")))
			return
		}
		cert := r.TLS.PeerCertificates[0]
		cn := cert.Subject.CommonName
		c.mu.Lock()
		allowed := (isProbeCertificate(cert) && cn == c.opts.ProbeID) ||
			(!isProbeCertificate(cert) && cn == c.opts.NodeID && c.probe.nodeProbe &&
				r.URL.Path != nodev1connect.ProbeServiceRenewProbeCertificateProcedure)
		if allowed {
			c.mtlsCalls[r.URL.Path]++
		}
		c.mu.Unlock()
		if !allowed {
			_ = errWriter.Write(w, r, connect.NewError(connect.CodePermissionDenied, errors.New("not a probe of this console")))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, cn)))
	})
}

func caller(ctx context.Context) string {
	s, _ := ctx.Value(callerKey{}).(string)
	return s
}

// AddProbeToken registers a single-use probe token.
func (c *Console) AddProbeToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.probe.tokens[token] = true
}

// SetProbeTargets sets what GetProbeTargets answers (targets and timing).
func (c *Console) SetProbeTargets(resp *nodev1.GetProbeTargetsResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.probe.targets = proto.CloneOf(resp)
}

// SetNodeProbe lets the node probe (ReportStatusResponse.probe and access
// to ProbeService with the node certificate) or stops it.
func (c *Console) SetNodeProbe(on bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.probe.nodeProbe = on
}

// RequestProbeRenewal sets renew_certificate in the next GetProbeTargets
// response.
func (c *Console) RequestProbeRenewal() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.probe.renewNext = true
}

// FailProbeTargets and FailProbeReports make the next n calls fail with
// Unavailable.
func (c *Console) FailProbeTargets(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.probe.failTargets = n
}

func (c *Console) FailProbeReports(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.probe.failReports = n
}

// ProbeTargetCalls returns every GetProbeTargets call.
func (c *Console) ProbeTargetCalls() []ProbeTargetsCall {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.probe.calls)
}

// ProbeReports returns every stored round.
func (c *Console) ProbeReports() []ProbeReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.probe.reports)
}

// ProbeCounters returns probe enrollments and certificate renewals.
func (c *Console) ProbeCounters() (enrollments, renewals int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.probe.enrollments, c.probe.renewals
}

func (c *Console) signProbe(csrPEM string) ([]byte, *x509.Certificate, error) {
	return c.CA.SignCSRSubject([]byte(csrPEM), pkix.Name{CommonName: c.opts.ProbeID, Organization: []string{pkitest.ProbeOrganization}}, c.opts.CertLifetime)
}

// EnrollProbe implements ProbeService.
func (c *Console) EnrollProbe(_ context.Context, req *connect.Request[nodev1.EnrollProbeRequest]) (*connect.Response[nodev1.EnrollProbeResponse], error) {
	c.mu.Lock()
	ok := c.probe.tokens[req.Msg.GetToken()]
	if ok {
		delete(c.probe.tokens, req.Msg.GetToken())
	}
	c.mu.Unlock()
	if !ok {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("invalid or already used probe token"))
	}
	certPEM, cert, err := c.signProbe(req.Msg.GetCsrPem())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	c.mu.Lock()
	c.probe.enrollments++
	c.mu.Unlock()
	return connect.NewResponse(&nodev1.EnrollProbeResponse{
		ProbeId:          c.opts.ProbeID,
		ProbeName:        c.opts.ProbeName,
		RegionId:         c.opts.RegionID,
		CertificatePem:   string(certPEM),
		CaCertificatePem: string(c.CA.PEM),
		NotAfter:         timestamppb.New(cert.NotAfter),
	}), nil
}

// RenewProbeCertificate implements ProbeService.
func (c *Console) RenewProbeCertificate(_ context.Context, req *connect.Request[nodev1.RenewProbeCertificateRequest]) (*connect.Response[nodev1.RenewProbeCertificateResponse], error) {
	certPEM, cert, err := c.signProbe(req.Msg.GetCsrPem())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	c.mu.Lock()
	c.probe.renewals++
	c.mu.Unlock()
	return connect.NewResponse(&nodev1.RenewProbeCertificateResponse{
		CertificatePem:   string(certPEM),
		CaCertificatePem: string(c.CA.PEM),
		NotAfter:         timestamppb.New(cert.NotAfter),
	}), nil
}

// GetProbeTargets implements ProbeService.
func (c *Console) GetProbeTargets(ctx context.Context, req *connect.Request[nodev1.GetProbeTargetsRequest]) (*connect.Response[nodev1.GetProbeTargetsResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.probe.calls = append(c.probe.calls, ProbeTargetsCall{Caller: caller(ctx), Info: proto.CloneOf(req.Msg.GetInfo())})
	if c.probe.failTargets > 0 {
		c.probe.failTargets--
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("injected GetProbeTargets failure"))
	}
	resp := &nodev1.GetProbeTargetsResponse{IntervalSeconds: 10, TimeoutMs: 3000, Attempts: 3}
	if c.probe.targets != nil {
		resp = proto.CloneOf(c.probe.targets)
	}
	if caller(ctx) == c.opts.ProbeID {
		resp.RenewCertificate = c.probe.renewNext
		c.probe.renewNext = false
	}
	return connect.NewResponse(resp), nil
}

// ReportProbeResults implements ProbeService.
func (c *Console) ReportProbeResults(ctx context.Context, req *connect.Request[nodev1.ReportProbeResultsRequest]) (*connect.Response[nodev1.ReportProbeResultsResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.probe.failReports > 0 {
		c.probe.failReports--
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("injected ReportProbeResults failure"))
	}
	c.probe.reports = append(c.probe.reports, ProbeReport{Caller: caller(ctx), Request: proto.CloneOf(req.Msg)})
	return connect.NewResponse(&nodev1.ReportProbeResultsResponse{Accepted: uint32(len(req.Msg.GetResults()))}), nil
}
