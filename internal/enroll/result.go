package enroll

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"connectrpc.com/connect"

	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/pki"
)

// The result line of `edgeweir-node enroll` (docs: ResultPrefix): one line
// on stdout for a caller that runs it unattended (the console's install
// over SSH), whatever the outcome. Human-readable logs stay on stderr.

// ResultPrefix starts the result line; the rest of the line is JSON.
const ResultPrefix = "EDGEWEIR_RESULT "

// ResultVersion is the version of the result line's fields.
const ResultVersion = 1

// Statuses of the result line, each with its exit status.
const (
	StatusEnrolled          = "enrolled"           // exit 0
	StatusAlreadyEnrolled   = "already_enrolled"   // exit 0 with --if-not-enrolled, else 10
	StatusError             = "error"              // exit 1
	StatusUsage             = "usage"              // exit 2
	StatusEnrolledElsewhere = "enrolled_elsewhere" // exit 11
	StatusTokenRejected     = "token_rejected"     // exit 12
	StatusUnreachable       = "unreachable"        // exit 13
	StatusCAMismatch        = "ca_mismatch"        // exit 14
	StatusStateDir          = "state_dir"          // exit 15
	StatusBusy              = "busy"               // exit 16
	StatusConsoleError      = "console_error"      // exit 17
)

// Exit statuses of `edgeweir-node enroll`.
const (
	ExitOK                = 0
	ExitError             = 1
	ExitUsage             = 2
	ExitAlreadyEnrolled   = 10
	ExitEnrolledElsewhere = 11
	ExitTokenRejected     = 12
	ExitUnreachable       = 13
	ExitCAMismatch        = 14
	ExitStateDir          = 15
	ExitBusy              = 16
	ExitConsoleError      = 17
)

// Result is the result line of one `edgeweir-node enroll`.
type Result struct {
	V      int    `json:"v"`
	Step   string `json:"step"`
	Status string `json:"status"`
	Exit   int    `json:"exit"`
	// Retry tells whether running the same command again (same token) may
	// succeed: the failure was in the network or a concurrent enrollment.
	Retry     bool   `json:"retry"`
	NodeID    string `json:"node_id,omitempty"`
	NodeName  string `json:"node_name,omitempty"`
	ClusterID string `json:"cluster_id,omitempty"`
	// CASHA256 is the CA an existing identity pins (enrolled_elsewhere).
	CASHA256 string `json:"ca_sha256,omitempty"`
	// NotAfter is when the node certificate expires (enrolled).
	NotAfter string `json:"not_after,omitempty"`
	// Message is English detail for logs; callers go by Status.
	Message string `json:"message,omitempty"`
}

// Write writes r as one line.
func (r Result) Write(w io.Writer) error {
	r.V, r.Step = ResultVersion, "enroll"
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, ResultPrefix+string(b)+"\n")
	return err
}

// WithIdentity fills the identity fields of r from id.
func (r Result) WithIdentity(id *identity.Identity) Result {
	if id != nil {
		r.NodeID, r.NodeName, r.ClusterID = id.NodeID, id.NodeName, id.ClusterID
	}
	return r
}

// Succeeded is the result of a completed enrollment.
func Succeeded(id *identity.Identity, notAfter time.Time) Result {
	r := Result{Status: StatusEnrolled, Exit: ExitOK}.WithIdentity(id)
	if !notAfter.IsZero() {
		r.NotAfter = notAfter.UTC().Format(time.RFC3339)
	}
	return r
}

// Outcome classifies an error of Run or Existing for the result line and
// the exit status.
func Outcome(err error) Result {
	r := Result{Message: err.Error()}
	var ce *connect.Error
	switch {
	case errors.Is(err, ErrInvalidOptions):
		r.Status, r.Exit = StatusUsage, ExitUsage
	case errors.Is(err, ErrAlreadyEnrolled), errors.Is(err, ErrProbeAlreadyEnrolled):
		r.Status, r.Exit = StatusAlreadyEnrolled, ExitAlreadyEnrolled
	case errors.Is(err, ErrEnrolledElsewhere):
		r.Status, r.Exit = StatusEnrolledElsewhere, ExitEnrolledElsewhere
	case errors.Is(err, ErrBusy), errors.Is(err, ErrAgentRunning):
		r.Status, r.Exit = StatusBusy, ExitBusy
		// A running agent does not stop by itself.
		r.Retry = errors.Is(err, ErrBusy)
	case errors.Is(err, ErrStateDir):
		r.Status, r.Exit = StatusStateDir, ExitStateDir
	case errors.Is(err, ErrTokenRejected):
		r.Status, r.Exit = StatusTokenRejected, ExitTokenRejected
	// Before the connect codes: a pin failure arrives as "unavailable".
	case errors.Is(err, pki.ErrPinMismatch), errors.Is(err, pki.ErrServerCertificate):
		r.Status, r.Exit = StatusCAMismatch, ExitCAMismatch
	case errors.Is(err, ErrBadResponse):
		r.Status, r.Exit = StatusConsoleError, ExitConsoleError
	case errors.Is(err, context.Canceled):
		// Interrupted (SIGINT, SIGTERM).
		r.Status, r.Exit, r.Retry = StatusError, ExitError, true
	case errors.As(err, &ce):
		switch ce.Code() {
		case connect.CodeUnavailable, connect.CodeDeadlineExceeded, connect.CodeCanceled:
			r.Status, r.Exit, r.Retry = StatusUnreachable, ExitUnreachable, true
		case connect.CodeInternal, connect.CodeUnknown, connect.CodeResourceExhausted, connect.CodeAborted:
			r.Status, r.Exit, r.Retry = StatusConsoleError, ExitConsoleError, true
		default:
			r.Status, r.Exit = StatusConsoleError, ExitConsoleError
		}
	case errors.Is(err, context.DeadlineExceeded):
		r.Status, r.Exit, r.Retry = StatusUnreachable, ExitUnreachable, true
	default:
		r.Status, r.Exit = StatusError, ExitError
	}
	return r
}
