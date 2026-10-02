package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

// L4Table is the body of PUT /v1/l4: the layer-4 applications without
// what nginx.conf already fixes per port, and the IP lists they use. The
// control API forwards it to the stream subsystem (lua/edgeweir/l4.lua),
// whose shared dicts the http side cannot reach.
type L4Table struct {
	Revision    uint64           `json:"revision,string"`
	ContentHash string           `json:"content_hash"`
	Apps        []configir.L4App `json:"apps"`
	IPLists     []L4IPList       `json:"ip_lists"`
	// OriginAllowedCIDRs lets origins use these special-purpose addresses
	// (DNS answers are checked against them in Lua).
	OriginAllowedCIDRs []string `json:"origin_allowed_cidrs"`
}

// L4IPList is an IP list an application refers to.
type L4IPList struct {
	ID      string   `json:"id"`
	Entries []string `json:"entries"`
}

// L4FromPlan converts the plan's layer-4 applications (nil without any:
// nginx.conf then has no stream subsystem to push to).
func L4FromPlan(p *configir.Plan) *L4Table {
	if p == nil || len(p.L4Apps) == 0 {
		return nil
	}
	t := &L4Table{Revision: p.Revision, ContentHash: p.ContentHash, Apps: p.L4Apps, IPLists: []L4IPList{}, OriginAllowedCIDRs: p.OriginAllowedCIDRs}
	for _, l := range p.L4Lists() {
		entries := l.GetEntries()
		if entries == nil {
			entries = []string{}
		}
		t.IPLists = append(t.IPLists, L4IPList{ID: l.GetId(), Entries: entries})
	}
	if t.OriginAllowedCIDRs == nil {
		t.OriginAllowedCIDRs = []string{}
	}
	return t
}

// L4Status is the answer of GET and PUT /v1/l4. Version is 0 until the
// first push after nginx (re)started.
type L4Status struct {
	Version     int64   `json:"version"`
	Revision    uint64  `json:"revision,string"`
	ContentHash string  `json:"content_hash"`
	Apps        int     `json:"apps"`
	PushedAt    float64 `json:"pushed_at"`
	// Down lists the origins the passive check holds down.
	Down []L4Down `json:"down,omitempty"`
}

// L4Down is an origin of an application that takes no connections until
// DownUntil (Unix seconds).
type L4Down struct {
	AppID     string  `json:"app_id"`
	OriginID  string  `json:"origin_id"`
	DownUntil float64 `json:"down_until"`
}

// InSync reports whether the stream subsystem serves exactly table t.
func (s *L4Status) InSync(t *L4Table) bool {
	return s.Version > 0 && s.Revision == t.Revision && s.ContentHash == t.ContentHash
}

// L4MinuteStats counts one application in one minute (POST
// /v1/l4/stats/drain): connections or UDP sessions accepted and refused,
// the highest concurrent count seen, bytes from and to clients (counted
// while connections run).
type L4MinuteStats struct {
	Minute         int64  `json:"minute"`
	AppID          string `json:"app_id"`
	Connections    uint64 `json:"connections"`
	Refused        uint64 `json:"refused"`
	PeakConcurrent uint64 `json:"peak_concurrent"`
	BytesReceived  uint64 `json:"bytes_received"`
	BytesSent      uint64 `json:"bytes_sent"`
}

// L4Status returns the stream subsystem's table status.
func (c *Client) L4Status(ctx context.Context) (*L4Status, error) {
	var s L4Status
	if err := c.do(ctx, http.MethodGet, "/v1/l4", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// PutL4 replaces the layer-4 table.
func (c *Client) PutL4(ctx context.Context, t *L4Table) (*L4Status, error) {
	if t == nil {
		return nil, errors.New("nil layer-4 table")
	}
	var s L4Status
	if err := c.do(ctx, http.MethodPut, "/v1/l4", t, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// DrainL4Stats returns and deletes the completed per-minute counters of
// the layer-4 applications; with all, the current minute's too.
func (c *Client) DrainL4Stats(ctx context.Context, all bool) ([]L4MinuteStats, error) {
	var out struct {
		Stats json.RawMessage `json:"stats"`
	}
	var body any
	if all {
		body = drainAll
	}
	if err := c.do(ctx, http.MethodPost, "/v1/l4/stats/drain", body, &out); err != nil {
		return nil, err
	}
	raw := bytes.TrimSpace(out.Stats)
	if len(raw) == 0 || bytes.Equal(raw, []byte("{}")) || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	var stats []L4MinuteStats
	if err := json.Unmarshal(raw, &stats); err != nil {
		return nil, fmt.Errorf("decode layer-4 stats: %w", err)
	}
	return stats, nil
}
