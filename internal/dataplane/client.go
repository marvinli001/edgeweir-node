// Package dataplane is the agent's client for the OpenResty control API
// (lua/edgeweir/control.lua), served by nginx on a local unix socket.
//
// The agent converts the validated plan into a JSON site table and replaces
// it atomically with PUT /v1/sites; the Lua side never sees protobuf.
package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/edgeweir/edgeweir-node/internal/configir"
)

// SiteTable is the body of PUT /v1/sites.
type SiteTable struct {
	Revision    uint64          `json:"revision,string"`
	ContentHash string          `json:"content_hash"`
	Sites       []configir.Site `json:"sites"`
}

// FromPlan converts a plan into the site table pushed to Lua.
func FromPlan(p *configir.Plan) *SiteTable {
	t := &SiteTable{Revision: p.Revision, ContentHash: p.ContentHash, Sites: p.Sites}
	if t.Sites == nil {
		t.Sites = []configir.Site{}
	}
	return t
}

// Status is the response of GET /v1/status. Version is 0 until the first
// push after nginx (re)started: the shared dicts are empty then.
type Status struct {
	Version       int64   `json:"version"`
	Revision      uint64  `json:"revision,string"`
	ContentHash   string  `json:"content_hash"`
	SiteCount     int     `json:"site_count"`
	PushedAt      float64 `json:"pushed_at"`
	NginxVersion  int64   `json:"nginx_version,omitempty"`
	NgxLuaVersion int64   `json:"ngx_lua_version,omitempty"`
	WorkerPID     int     `json:"worker_pid,omitempty"`
}

// InSync reports whether the data plane serves exactly table t.
func (s *Status) InSync(t *SiteTable) bool {
	return s.Version > 0 && s.Revision == t.Revision && s.ContentHash == t.ContentHash
}

// MinuteStats is one per-site, per-minute bucket from POST /v1/stats/drain.
type MinuteStats struct {
	Minute        int64             `json:"minute"`
	SiteID        string            `json:"site_id"`
	Requests      uint64            `json:"requests"`
	BytesSent     uint64            `json:"bytes_sent"`
	BytesReceived uint64            `json:"bytes_received"`
	CacheHits     uint64            `json:"cache_hits"`
	CacheMisses   uint64            `json:"cache_misses"`
	StatusCodes   map[string]uint64 `json:"status_codes"`
}

// Client talks to the control socket.
type Client struct {
	socket string
	hc     *http.Client
}

// NewClient returns a client for the control API at socket.
func NewClient(socket string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		MaxIdleConns:    2,
		IdleConnTimeout: 30 * time.Second,
	}
	return &Client{socket: socket, hc: &http.Client{Transport: tr, Timeout: 30 * time.Second}}
}

// Socket returns the control socket path.
func (c *Client) Socket() string { return c.socket }

// APIError is a non-2xx answer of the control API.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("data plane control API: HTTP %d: %s", e.Status, e.Message)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	// The host part is ignored: the transport always dials the socket.
	req, err := http.NewRequestWithContext(ctx, method, "http://edgeweir-dataplane"+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("data plane control API %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		msg := string(bytes.TrimSpace(data))
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return &APIError{Status: resp.StatusCode, Message: msg}
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode %s response: %w", path, err)
		}
	}
	return nil
}

// Health checks that the control API answers.
func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/v1/health", nil, nil)
}

// Status returns the data plane's site table status.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	var s Status
	if err := c.do(ctx, http.MethodGet, "/v1/status", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// PutSites replaces the site table atomically.
func (c *Client) PutSites(ctx context.Context, t *SiteTable) (*Status, error) {
	if t == nil {
		return nil, errors.New("nil site table")
	}
	var s Status
	if err := c.do(ctx, http.MethodPut, "/v1/sites", t, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// DrainStats returns and deletes the completed per-minute counters.
func (c *Client) DrainStats(ctx context.Context) ([]MinuteStats, error) {
	var out struct {
		Stats json.RawMessage `json:"stats"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/stats/drain", nil, &out); err != nil {
		return nil, err
	}
	// lua-cjson encodes an empty table as {}: treat it as an empty list.
	raw := bytes.TrimSpace(out.Stats)
	if len(raw) == 0 || bytes.Equal(raw, []byte("{}")) || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	var stats []MinuteStats
	if err := json.Unmarshal(raw, &stats); err != nil {
		return nil, fmt.Errorf("decode stats: %w", err)
	}
	return stats, nil
}
