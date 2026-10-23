package upgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/nodelog"
)

// Debug logs under the supervisor (Options.DebugLogs): the supervisor's
// own records and OpenResty's error log of every level stay in its ring.
// The child reads the entries a DebugLogsTask selects (GET /debug-logs)
// when /capabilities offers "debug_logs"; nothing is acknowledged or
// dropped.

// serveDebugLogs answers /debug-logs; false when the path is not it.
func (s *Supervisor) serveDebugLogs(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/debug-logs" {
		return false
	}
	if s.opts.DebugLogs == nil {
		reply(w, 404, map[string]string{"error": "the supervisor keeps no debug logs"})
		return true
	}
	if r.Method != http.MethodGet {
		reply(w, 405, map[string]string{"error": "method not allowed"})
		return true
	}
	f, err := parseDebugFilter(r.URL.Query())
	if err != nil {
		reply(w, 400, map[string]string{"error": err.Error()})
		return true
	}
	reply(w, 200, s.opts.DebugLogs.Snapshot(f))
	return true
}

func debugFilterQuery(f nodelog.DebugFilter) url.Values {
	q := url.Values{}
	if !f.Since.IsZero() {
		q.Set("since", f.Since.UTC().Format(time.RFC3339Nano))
	}
	if !f.Until.IsZero() {
		q.Set("until", f.Until.UTC().Format(time.RFC3339Nano))
	}
	for _, c := range f.Components {
		q.Add("component", c)
	}
	for _, s := range f.Sources {
		q.Add("source", string(s))
	}
	return q
}

func parseDebugFilter(q url.Values) (nodelog.DebugFilter, error) {
	var f nodelog.DebugFilter
	for key, t := range map[string]*time.Time{"since": &f.Since, "until": &f.Until} {
		if v := q.Get(key); v != "" {
			parsed, err := time.Parse(time.RFC3339Nano, v)
			if err != nil {
				return f, fmt.Errorf("invalid %s", key)
			}
			*t = parsed
		}
	}
	f.Components = q["component"]
	for _, s := range q["source"] {
		f.Sources = append(f.Sources, nodelog.Source(s))
	}
	return f, nil
}

// ReadDebugLogs returns the entries of the supervisor's ring that f
// selects.
func (c *Client) ReadDebugLogs(ctx context.Context, f nodelog.DebugFilter) (*nodelog.DebugSnapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://upgrade/debug-logs?"+debugFilterQuery(f).Encode(), nil)
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
	var snap nodelog.DebugSnapshot
	// At most MaxDebugUploadBytes of entries, with JSON's escaping.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4*nodelog.MaxDebugUploadBytes)).Decode(&snap); err != nil {
		return nil, err
	}
	return &snap, nil
}
