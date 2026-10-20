// Package diag is the agent's diagnostics socket: what the running agent
// knows of its connection to the console, its configuration and its clock
// (GET /status, JSON) and the Go runtime's profiles (/debug/pprof/). The
// socket is a unix socket of the agent's own user (0600), never TCP;
// `edgeweir-node diagnose` and `edgeweir-node pprof` read it.
package diag

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	"slices"
	"strconv"
	"time"
)

// Status is the running agent's view (GET /status).
type Status struct {
	Version   string    `json:"version"`
	StartedAt time.Time `json:"started_at,omitzero"`
	// Empty until the node is enrolled.
	NodeID    string `json:"node_id,omitempty"`
	ClusterID string `json:"cluster_id,omitempty"`
	NodeName  string `json:"node_name,omitempty"`
	// The console address in use; nil before enrollment.
	Console *Console `json:"console,omitempty"`
	Report  Report   `json:"report"`
	Config  Config   `json:"config"`
	// The node's clock against the console's, from the last report that
	// measured it; nil before.
	Clock               *Clock    `json:"clock,omitempty"`
	CertificateNotAfter time.Time `json:"certificate_not_after,omitzero"`
}

// Console is the node channel address in use and the last failed check of
// another one.
type Console struct {
	URL         string `json:"url"`
	ServerName  string `json:"server_name,omitempty"`
	FallbackURL string `json:"fallback_url,omitempty"`
	OnFallback  bool   `json:"on_fallback,omitempty"`
	// The address that failed its check last, with the check's code.
	FailedURL string    `json:"failed_url,omitempty"`
	ErrorCode string    `json:"error_code,omitempty"`
	Error     string    `json:"error,omitempty"`
	FailedAt  time.Time `json:"failed_at,omitzero"`
}

// Report is how the heartbeats (ReportStatus) went.
type Report struct {
	LastOK      time.Time `json:"last_ok,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitzero"`
	// The interval the console asked for.
	IntervalSeconds int `json:"interval_seconds"`
}

// Config is the configuration the node serves.
type Config struct {
	AppliedRevision uint64 `json:"applied_revision"`
	// The console's latest revision for this node, as of the last report.
	LatestRevision   uint64 `json:"latest_revision"`
	State            string `json:"state"`
	Message          string `json:"message,omitempty"`
	DataPlaneHealthy bool   `json:"data_plane_healthy"`
	// Certificates of the applied revision the node could not load.
	CertificateFailures int `json:"certificate_failures"`
}

// Clock is a measurement of the node's clock against the console's.
type Clock struct {
	// Positive: the node's clock is ahead.
	OffsetMillis int64 `json:"offset_millis"`
	// The request's round trip: the offset is off by at most half of it.
	RTTMillis  int64     `json:"rtt_millis"`
	MeasuredAt time.Time `json:"measured_at"`
}

// Profiles are the profiles `edgeweir-node pprof` fetches ("profile" is
// the CPU profile, "trace" the execution trace; both take seconds).
var Profiles = []string{"profile", "trace", "heap", "allocs", "goroutine", "block", "mutex", "threadcreate"}

// MaxSeconds bounds a CPU profile or trace.
const MaxSeconds = 120

// Serve listens on the unix socket path (replacing a stale socket) and
// serves status until ctx ends. It returns once the socket listens.
func Serve(ctx context.Context, path string, status func() Status, log *slog.Logger) error {
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("diagnostics socket %s is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("diagnostics socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status())
	})
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: (MaxSeconds + 30) * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 4096}
	go func() {
		<-ctx.Done()
		_ = server.Close()
		_ = os.Remove(path)
	}()
	go func() {
		if err := server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("diagnostics socket stopped", "err", err)
		}
	}()
	return nil
}

func client(path string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
	}}
}

func get(ctx context.Context, path, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://agent"+target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client(path).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("%s: %s %s", target, resp.Status, body)
	}
	return resp, nil
}

// Fetch reads the agent's status from its socket.
func Fetch(ctx context.Context, path string) (*Status, error) {
	resp, err := get(ctx, path, "/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var st Status
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st); err != nil {
		return nil, fmt.Errorf("status: %w", err)
	}
	return &st, nil
}

// Profile copies one of Profiles to w; seconds is the length of a CPU
// profile or trace (1..MaxSeconds) and ignored for the others.
func Profile(ctx context.Context, path, name string, seconds int, w io.Writer) error {
	if !slices.Contains(Profiles, name) {
		return fmt.Errorf("unknown profile %q", name)
	}
	q := url.Values{}
	if name == "profile" || name == "trace" {
		if seconds < 1 || seconds > MaxSeconds {
			return fmt.Errorf("seconds must be 1..%d", MaxSeconds)
		}
		q.Set("seconds", strconv.Itoa(seconds))
	}
	resp, err := get(ctx, path, "/debug/pprof/"+name+"?"+q.Encode())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(w, resp.Body)
	return err
}
