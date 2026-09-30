package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Ban is one console ban as the data plane holds it (lua/edgeweir/bans.lua).
type Ban struct {
	ID   string `json:"id"`
	CIDR string `json:"cidr"`
	// Scope is "platform" or "site".
	Scope  string `json:"scope"`
	SiteID string `json:"site_id,omitempty"`
	// Kind is "m" (manual) or "c" (automatic); not needed for removals.
	Kind string `json:"kind,omitempty"`
	// ExpiresAt is the expiry in Unix seconds (millisecond precision).
	ExpiresAt float64 `json:"expires_at,omitempty"`
}

// BanTable is the body of PUT /v1/bans: the whole console set, in the
// order the data plane should keep it when room runs out.
type BanTable struct {
	Sequence uint64 `json:"sequence,string"`
	Bans     []Ban  `json:"bans"`
}

// BanDelta is the body of POST /v1/bans. The data plane applies it only
// while it holds sequence Base (409 otherwise).
type BanDelta struct {
	Base     uint64 `json:"base,string"`
	Sequence uint64 `json:"sequence,string"`
	Upsert   []Ban  `json:"upsert"`
	Remove   []Ban  `json:"remove"`
}

// BanStatus is the response of GET, PUT and POST /v1/bans. After an nginx
// restart the sequence is 0 and the set is empty.
type BanStatus struct {
	Sequence uint64 `json:"sequence,string"`
	// Entries counts every ban held, the node's own included.
	Entries  int `json:"entries"`
	Capacity int `json:"capacity"`
	// Unapplied counts the manual bans that do not fit; UnappliedIDs lists
	// at most 100 of them.
	Unapplied    int      `json:"unapplied"`
	UnappliedIDs []string `json:"unapplied_ids"`
	// AutoEvicted counts automatic bans dropped to make room since nginx
	// started.
	AutoEvicted    uint64 `json:"auto_evicted"`
	PendingReports int    `json:"pending_reports"`
}

// AutoBan is a ban the node created itself, from POST /v1/bans/auto/drain.
type AutoBan struct {
	SiteID        string  `json:"site_id"`
	IP            string  `json:"ip"`
	PrefixLen     int     `json:"prefix_len"`
	CreatedAt     float64 `json:"created_at"`
	ExpiresAt     float64 `json:"expires_at"`
	Reason        string  `json:"reason"`
	Metric        string  `json:"metric"`
	Observed      float64 `json:"observed"`
	Threshold     float64 `json:"threshold"`
	WindowSeconds uint32  `json:"window_seconds"`
}

// isEmptyJSON reports whether raw is absent, null or an empty object
// (lua-cjson encodes an empty table as {}).
func isEmptyJSON(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) == 0 || bytes.Equal(raw, []byte("{}")) || bytes.Equal(raw, []byte("null"))
}

// UnmarshalJSON accepts {} for an empty unapplied_ids list.
func (s *BanStatus) UnmarshalJSON(data []byte) error {
	type plain BanStatus
	var aux struct {
		plain
		UnappliedIDs json.RawMessage `json:"unapplied_ids"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*s = BanStatus(aux.plain)
	s.UnappliedIDs = nil
	if !isEmptyJSON(aux.UnappliedIDs) {
		if err := json.Unmarshal(aux.UnappliedIDs, &s.UnappliedIDs); err != nil {
			return fmt.Errorf("decode unapplied_ids: %w", err)
		}
	}
	return nil
}

// BanStatus returns the data plane's ban set status.
func (c *Client) BanStatus(ctx context.Context) (*BanStatus, error) {
	var s BanStatus
	if err := c.do(ctx, http.MethodGet, "/v1/bans", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// PutBans replaces the console bans (the node's own bans stay).
func (c *Client) PutBans(ctx context.Context, t *BanTable) (*BanStatus, error) {
	if t == nil {
		return nil, errors.New("nil ban table")
	}
	if t.Bans == nil {
		t = &BanTable{Sequence: t.Sequence, Bans: []Ban{}}
	}
	var s BanStatus
	if err := c.do(ctx, http.MethodPut, "/v1/bans", t, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// AddBans applies a delta; a data plane that does not hold d.Base answers
// 409 (an *APIError).
func (c *Client) AddBans(ctx context.Context, d *BanDelta) (*BanStatus, error) {
	if d == nil {
		return nil, errors.New("nil ban delta")
	}
	body := *d
	if body.Upsert == nil {
		body.Upsert = []Ban{}
	}
	if body.Remove == nil {
		body.Remove = []Ban{}
	}
	var s BanStatus
	if err := c.do(ctx, http.MethodPost, "/v1/bans", &body, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// DrainAutoBans returns and deletes up to 1000 queued own bans.
func (c *Client) DrainAutoBans(ctx context.Context) ([]AutoBan, error) {
	var out struct {
		Bans json.RawMessage `json:"bans"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/bans/auto/drain", nil, &out); err != nil {
		return nil, err
	}
	if isEmptyJSON(out.Bans) {
		return nil, nil
	}
	var list []AutoBan
	if err := json.Unmarshal(out.Bans, &list); err != nil {
		return nil, fmt.Errorf("decode automatic bans: %w", err)
	}
	return list, nil
}
