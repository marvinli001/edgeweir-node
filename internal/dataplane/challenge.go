package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// List is a JSON array that also accepts {} and null: lua-cjson encodes
// an empty table as {}.
type List[T any] []T

// UnmarshalJSON implements json.Unmarshaler.
func (l *List[T]) UnmarshalJSON(b []byte) error {
	if isEmptyJSON(b) {
		*l = nil
		return nil
	}
	var v []T
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*l = v
	return nil
}

// ChallengeKey is a challenge pass key; Secret is base64.
type ChallengeKey struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

// ChallengeKeys is the body of PUT /v1/challenge/keys: the keys that
// verify passes (next, current, previous) and the one that signs. ID
// identifies the set (GET /v1/challenge reports it back).
type ChallengeKeys struct {
	ID      string         `json:"id"`
	Current string         `json:"current"`
	Keys    []ChallengeKey `json:"keys"`
}

// Captcha is one image of the captcha pool; PNG is base64.
type Captcha struct {
	Answer string `json:"answer"`
	PNG    string `json:"png"`
}

// CaptchaPool is the body of PUT /v1/challenge/captchas.
type CaptchaPool struct {
	ID     string    `json:"id"`
	Images []Captcha `json:"images"`
}

// ChallengeStatus is the response of GET /v1/challenge and of the PUTs.
// After an nginx restart everything is empty.
type ChallengeStatus struct {
	KeysID     string       `json:"keys_id"`
	Current    string       `json:"current"`
	Keys       List[string] `json:"keys"`
	Captchas   int          `json:"captchas"`
	CaptchasID string       `json:"captchas_id"`
	// NonceOverflow counts tokens accepted while the nonce store was full.
	NonceOverflow uint64 `json:"nonce_overflow"`
}

// ChallengeStatus returns the data plane's keys and captcha pool status.
func (c *Client) ChallengeStatus(ctx context.Context) (*ChallengeStatus, error) {
	var s ChallengeStatus
	if err := c.do(ctx, http.MethodGet, "/v1/challenge", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// PutChallengeKeys replaces the challenge keys.
func (c *Client) PutChallengeKeys(ctx context.Context, k *ChallengeKeys) (*ChallengeStatus, error) {
	if k == nil {
		return nil, errors.New("nil challenge keys")
	}
	body := *k
	if body.Keys == nil {
		body.Keys = []ChallengeKey{}
	}
	var s ChallengeStatus
	if err := c.do(ctx, http.MethodPut, "/v1/challenge/keys", &body, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// PutCaptchas replaces the captcha pool.
func (c *Client) PutCaptchas(ctx context.Context, p *CaptchaPool) (*ChallengeStatus, error) {
	if p == nil {
		return nil, errors.New("nil captcha pool")
	}
	body := *p
	if body.Images == nil {
		body.Images = []Captcha{}
	}
	var s ChallengeStatus
	if err := c.do(ctx, http.MethodPut, "/v1/challenge/captchas", &body, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// SecurityPath is an escalated path of a site.
type SecurityPath struct {
	Path  string `json:"path"`
	Level string `json:"level"`
}

// SecuritySite is the CC state of a site with CC on this node.
type SecuritySite struct {
	SiteID string `json:"site_id"`
	// Level is normal, cookie302, js, pow or captcha.
	Level          string             `json:"level"`
	EscalatedPaths int                `json:"escalated_paths"`
	Paths          List[SecurityPath] `json:"paths"`
	// SiteQPS and ErrorPercent are the rates of the last evaluation.
	SiteQPS      float64 `json:"site_qps"`
	ErrorPercent float64 `json:"error_percent"`
}

// SecurityStatus is the response of GET /v1/security.
type SecurityStatus struct {
	Sites         List[SecuritySite] `json:"sites"`
	PendingEvents int                `json:"pending_events"`
	DroppedEvents uint64             `json:"dropped_events"`
}

// TopCount is one of the heaviest addresses or paths of an event.
type TopCount struct {
	Value string  `json:"value"`
	Count float64 `json:"count"`
}

// SecurityEvent is a CC mitigation event from POST /v1/security/drain.
type SecurityEvent struct {
	ID     string  `json:"id"`
	SiteID string  `json:"site_id"`
	Time   float64 `json:"time"`
	// Kind is site_level, path_level or ip_banned.
	Kind          string         `json:"kind"`
	Level         string         `json:"level"`
	PreviousLevel string         `json:"previous_level"`
	Path          string         `json:"path"`
	Address       string         `json:"address"`
	Metric        string         `json:"metric"`
	Observed      float64        `json:"observed"`
	Threshold     float64        `json:"threshold"`
	TopIPs        List[TopCount] `json:"top_ips"`
	TopPaths      List[TopCount] `json:"top_paths"`
}

// SecurityStatus returns the CC levels of the sites with CC.
func (c *Client) SecurityStatus(ctx context.Context) (*SecurityStatus, error) {
	var s SecurityStatus
	if err := c.do(ctx, http.MethodGet, "/v1/security", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// DrainSecurity returns and deletes up to 1000 queued CC events.
func (c *Client) DrainSecurity(ctx context.Context) ([]SecurityEvent, error) {
	var out struct {
		Events List[SecurityEvent] `json:"events"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/security/drain", nil, &out); err != nil {
		return nil, err
	}
	return out.Events, nil
}
