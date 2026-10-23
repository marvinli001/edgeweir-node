package upgrade

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"

	"github.com/marvinli001/edgeweir-node/internal/nodelog"
)

// Node logs under the supervisor (Options.Logs): the supervisor's own
// warnings and events and OpenResty's error log stay in its buffer, so a
// child that crashed, was replaced or failed an upgrade trial does not
// lose them. The child reads them (GET /logs) when /capabilities offers
// "logs", puts them into its own spool and acknowledges them (POST
// /logs/ack) once that is on disk; the supervisor then drops them.

// maxLogsRead is the most entries one GET /logs returns.
const maxLogsRead = 200

// LogsPage is the answer of GET /logs.
type LogsPage struct {
	// Instance names the supervisor's buffer; numbers start over in a
	// new one.
	Instance string          `json:"instance"`
	Entries  []nodelog.Entry `json:"entries"`
	// Last is the number of the last entry returned (after when none).
	Last uint64 `json:"last"`
	// Entries the supervisor dropped since the last acknowledgement, and
	// its counters (the acknowledgement's marks).
	DroppedRateLimited uint64 `json:"dropped_rate_limited"`
	DroppedOverflow    uint64 `json:"dropped_overflow"`
	RateLimitedMark    uint64 `json:"rate_limited_mark"`
	OverflowMark       uint64 `json:"overflow_mark"`
}

// LogsAck acknowledges entries up to Upto and the drops counted up to the
// marks of one buffer instance.
type LogsAck struct {
	Instance        string `json:"instance"`
	Upto            uint64 `json:"upto"`
	RateLimitedMark uint64 `json:"rate_limited_mark"`
	OverflowMark    uint64 `json:"overflow_mark"`
}

func newLogInstance() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// serveLogs answers /logs and /logs/ack; false when the path is not one.
func (s *Supervisor) serveLogs(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/logs", "/logs/ack":
	default:
		return false
	}
	if s.opts.Logs == nil {
		reply(w, 404, map[string]string{"error": "the supervisor keeps no logs"})
		return true
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/logs":
		q := r.URL.Query()
		after, err := strconv.ParseUint(q.Get("after"), 10, 64)
		if err != nil || q.Get("instance") != s.logInstance {
			after = 0
		}
		entries, last := s.opts.Logs.Read(after, maxLogsRead)
		limited, overflow := s.opts.Logs.Dropped()
		s.logsMu.Lock()
		acked := s.logsAcked
		s.logsMu.Unlock()
		reply(w, 200, LogsPage{Instance: s.logInstance, Entries: entries, Last: last,
			DroppedRateLimited: limited - min(limited, acked[0]), DroppedOverflow: overflow - min(overflow, acked[1]),
			RateLimitedMark: limited, OverflowMark: overflow})
	case r.Method == http.MethodPost && r.URL.Path == "/logs/ack":
		var in LogsAck
		if !body(w, r, &in) {
			return true
		}
		if in.Instance == s.logInstance {
			s.opts.Logs.Discard(in.Upto)
			s.logsMu.Lock()
			s.logsAcked = [2]uint64{max(s.logsAcked[0], in.RateLimitedMark), max(s.logsAcked[1], in.OverflowMark)}
			s.logsMu.Unlock()
		}
		reply(w, 200, map[string]bool{"ok": true})
	default:
		reply(w, 405, map[string]string{"error": "method not allowed"})
	}
	return true
}

// Capabilities are what the supervisor offers its child.
type Capabilities struct {
	Enabled bool `json:"enabled"`
	Engine  bool `json:"engine"`
	Logs    bool `json:"logs"`
	// GET /debug-logs (debug-logs-v1).
	DebugLogs bool `json:"debug_logs"`
}

// Capabilities returns what the supervisor offers.
func (c *Client) Capabilities(ctx context.Context) (Capabilities, error) {
	var out Capabilities
	err := c.do(ctx, http.MethodGet, "/capabilities", nil, &out)
	return out, err
}

// ReadLogs returns the entries after after in the supervisor's buffer
// instance (all it holds for another instance).
func (c *Client) ReadLogs(ctx context.Context, instance string, after uint64) (*LogsPage, error) {
	q := url.Values{"instance": {instance}, "after": {strconv.FormatUint(after, 10)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://upgrade/logs?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("supervisor request failed (%d)", resp.StatusCode)
	}
	var page LogsPage
	// At most maxLogsRead entries of at most a few KiB each.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&page); err != nil {
		return nil, err
	}
	return &page, nil
}

// AckLogs lets the supervisor drop what ack names.
func (c *Client) AckLogs(ctx context.Context, ack LogsAck) error {
	return c.do(ctx, http.MethodPost, "/logs/ack", ack, nil)
}
