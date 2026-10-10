// Package dataplane is the agent's client for the OpenResty control API
// (lua/edgeweir/control.lua), served by nginx on a local unix socket.
//
// The agent converts the validated plan into a JSON site table and replaces
// it atomically with PUT /v1/sites; the Lua side never sees protobuf.
package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

// SiteTable is the body of PUT /v1/sites.
type SiteTable struct {
	Revision    uint64          `json:"revision,string"`
	ContentHash string          `json:"content_hash"`
	Sites       []configir.Site `json:"sites"`
	// OriginAllowedCIDRs lets origins use these special-purpose addresses
	// (literals and DNS answers are checked against them in Lua).
	OriginAllowedCIDRs []string `json:"origin_allowed_cidrs"`
	// CDNID is this node's CDN-Loop identifier (RFC 8586); empty before
	// the node is enrolled.
	CDNID          string                   `json:"cdn_id,omitempty"`
	HTTPChallenges []configir.HTTPChallenge `json:"http_challenges,omitempty"`
	IPLists        []*nodev1.IpList         `json:"ip_lists,omitempty"`
	PlatformRules  []*nodev1.EdgeRule       `json:"platform_rules,omitempty"`
	// PlatformProtection is the platform-wide Under Attack.
	PlatformProtection *configir.PlatformProtection `json:"platform_protection,omitempty"`
	// TagTTL is the lifetime of Cache-Tag index entries in seconds: the
	// longest inactive time of the cache zones (an object can stay cached
	// that long after its last request).
	TagTTL uint32 `json:"tag_ttl,omitempty"`
	// PlatformErrorPages are the platform's pages for unknown and offline
	// hosts; OfflineHosts the domains of disabled sites.
	PlatformErrorPages *configir.PlatformErrorPages `json:"platform_error_pages,omitempty"`
	OfflineHosts       []configir.OfflineHost       `json:"offline_hosts,omitempty"`
	// HealthCertificate is the node's self-signed certificate for SNI
	// health.edgeweir.invalid and handshakes without SNI (probe-health-v1).
	HealthCertificate *configir.Certificate `json:"health_certificate,omitempty"`
	// ClientAddress is the cluster's client address setting; the data
	// plane uses its trusted proxies (never banned, not counted by CC).
	ClientAddress *configir.ClientAddress `json:"client_address,omitempty"`
	// UnknownHosts is the cluster's handling of unknown hosts and node IP
	// access, and scan protection (unknown-host-v1).
	UnknownHosts *configir.UnknownHosts `json:"unknown_hosts,omitempty"`
}

// FromPlan converts a plan into the site table pushed to Lua.
func FromPlan(p *configir.Plan) *SiteTable {
	t := &SiteTable{Revision: p.Revision, ContentHash: p.ContentHash, Sites: p.Sites, OriginAllowedCIDRs: p.OriginAllowedCIDRs}
	t.HTTPChallenges = p.HTTPChallenges
	t.IPLists = p.IPLists
	t.PlatformRules = p.PlatformRules
	t.PlatformProtection = p.PlatformProtection
	t.PlatformErrorPages = p.PlatformErrorPages
	t.OfflineHosts = p.OfflineHosts
	t.ClientAddress = p.ClientAddress
	t.UnknownHosts = p.UnknownHosts
	for _, z := range p.CacheZones {
		t.TagTTL = max(t.TagTTL, z.InactiveSeconds)
	}
	if t.Sites == nil {
		t.Sites = []configir.Site{}
	}
	if t.OriginAllowedCIDRs == nil {
		t.OriginAllowedCIDRs = []string{}
	}
	return t
}

// CDNID returns the CDN-Loop identifier of a node (RFC 8586 pseudonym):
// "edgeweir-" and the first 16 hex characters of sha256(node id). It does
// not reveal the node id but is stable across restarts and renewals.
func CDNID(nodeID string) string {
	if nodeID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(nodeID))
	return "edgeweir-" + hex.EncodeToString(sum[:])[:16]
}

// Status is the response of GET /v1/status. Version is 0 until the first
// push after nginx (re)started: the shared dicts are empty then.
type Status struct {
	Version       int64       `json:"version"`
	Revision      uint64      `json:"revision,string"`
	ContentHash   string      `json:"content_hash"`
	SiteCount     int         `json:"site_count"`
	PushedAt      float64     `json:"pushed_at"`
	CDNID         string      `json:"cdn_id"`
	Purge         PurgeStatus `json:"purge"`
	NginxVersion  int64       `json:"nginx_version,omitempty"`
	NgxLuaVersion int64       `json:"ngx_lua_version,omitempty"`
	WorkerPID     int         `json:"worker_pid,omitempty"`
	// ConfID is the id of the nginx.conf the answering worker runs (see
	// render.ConfID).
	ConfID string `json:"conf_id,omitempty"`
	// ConnectionsActive is nginx's $connections_active (stub_status) without
	// the status request itself: client connections, and the edge layer's
	// connections to the origin layer's unix sockets.
	ConnectionsActive uint64 `json:"connections_active,omitempty"`
}

// InSync reports whether the data plane serves exactly table t.
func (s *Status) InSync(t *SiteTable) bool {
	return s.Version > 0 && s.Revision == t.Revision && s.ContentHash == t.ContentHash && s.CDNID == t.CDNID
}

// PurgeMarker invalidates cached objects of a site (see lua/edgeweir/purge.lua).
type PurgeMarker struct {
	SiteID string `json:"site_id"`
	// Type is "url", "prefix", "site" or "tag".
	Type  string `json:"type"`
	Host  string `json:"host,omitempty"`
	Path  string `json:"path,omitempty"`
	Query string `json:"query,omitempty"`
	// Tag is the Cache-Tag of a "tag" marker: 1-128 bytes of printable
	// ASCII without commas and without leading or trailing spaces
	// (compared in lowercase).
	Tag string `json:"tag,omitempty"`
	// Epoch is the purge time in milliseconds; it becomes part of the keys.
	Epoch int64 `json:"epoch"`
}

// PurgeTable is the body of PUT and POST /v1/purge. ID identifies the full
// marker set after the call.
type PurgeTable struct {
	ID      string        `json:"id"`
	Markers []PurgeMarker `json:"markers"`
}

// PurgeStatus is the data plane's marker set. An empty ID after an nginx
// restart means the markers must be pushed again.
type PurgeStatus struct {
	ID      string `json:"id"`
	Entries int    `json:"entries"`
	Markers int    `json:"markers"`
	// Collapsed lists the sites (of a PUT) whose markers did not fit and
	// were replaced by one site-level marker each.
	Collapsed []string `json:"collapsed,omitempty"`
}

// OriginHealth is one entry of GET /v1/origins/health (origins with
// recorded failures; times are Unix seconds, 0 when unset).
type OriginHealth struct {
	SiteID        string  `json:"site_id"`
	OriginID      string  `json:"origin_id"`
	Healthy       bool    `json:"healthy"`
	Failures      uint32  `json:"failures"`
	LastFailureAt float64 `json:"last_failure_at"`
	DownUntil     float64 `json:"down_until"`
	LastError     string  `json:"last_error"`
	// LastErrorCode and LastErrorParams describe the last error for the
	// console (see lua/edgeweir/health.lua); empty for unknown errors.
	LastErrorCode   string            `json:"last_error_code"`
	LastErrorParams map[string]string `json:"last_error_params,omitempty"`
}

// ActiveHealth is the body of PUT /v1/origins/active: the full set of
// origins the agent's active health checks mark down. The marks expire
// after TTL seconds, so they never outlive an agent that stopped pushing.
type ActiveHealth struct {
	TTL  uint32         `json:"ttl"`
	Down []ActiveOrigin `json:"down"`
}

// ActiveOrigin is an origin of a site, marked down by the active check.
type ActiveOrigin struct {
	SiteID   string `json:"site_id"`
	OriginID string `json:"origin_id"`
}

// ActiveHealthStatus is the answer of PUT /v1/origins/active: the number
// of marks installed.
type ActiveHealthStatus struct {
	Down int `json:"down"`
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
	TopURLs       map[string]uint64 `json:"top_urls"`
	TopIPs        map[string]uint64 `json:"top_ips"`
	// WAFRules counts the CRS rules that matched, by rule id (the heaviest
	// 20 of the minute).
	WAFRules map[string]uint64 `json:"waf_rules"`
	// LoggedRules counts the matches of rules with the log action, by rule
	// id (the heaviest 20 of the minute).
	LoggedRules map[string]uint64 `json:"logged_rules"`
	// AuthFailures counts the requests access authentication refused
	// (feature access-auth-v1).
	AuthFailures uint64 `json:"auth_failures"`
	// The bounded dimensions (feature stats-dims-v1, ADR-0041): requests
	// and bytes sent per country ("" unknown, at most 250), the heaviest 50
	// networks (by AS number, with names) and referring hosts, requests per
	// user agent class, HTTP and TLS version and block reason, challenges
	// issued and passed.
	Countries        map[string]CountryCount `json:"countries"`
	ASNs             map[string]ASNCount     `json:"asns"`
	Referers         map[string]uint64       `json:"referers"`
	Browsers         map[string]uint64       `json:"browsers"`
	OperatingSystems map[string]uint64       `json:"operating_systems"`
	Devices          map[string]uint64       `json:"devices"`
	HTTPVersions     map[string]uint64       `json:"http_versions"`
	TLSVersions      map[string]uint64       `json:"tls_versions"`
	BlockReasons     map[string]uint64       `json:"block_reasons"`
	ChallengesIssued uint64                  `json:"challenges_issued"`
	ChallengesPassed uint64                  `json:"challenges_passed"`
}

// CountryCount is a country's requests and bytes sent in a minute.
type CountryCount struct {
	Requests  uint64 `json:"requests"`
	BytesSent uint64 `json:"bytes_sent"`
}

// ASNCount is a network's requests in a minute (approximate) and its name.
type ASNCount struct {
	Requests uint64 `json:"requests"`
	Name     string `json:"name"`
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

// PutPurge replaces the purge marker set.
func (c *Client) PutPurge(ctx context.Context, t *PurgeTable) (*PurgeStatus, error) {
	return c.purge(ctx, http.MethodPut, t)
}

// AddPurge merges markers into the data plane's set.
func (c *Client) AddPurge(ctx context.Context, t *PurgeTable) (*PurgeStatus, error) {
	return c.purge(ctx, http.MethodPost, t)
}

func (c *Client) purge(ctx context.Context, method string, t *PurgeTable) (*PurgeStatus, error) {
	if t == nil {
		return nil, errors.New("nil purge table")
	}
	if t.Markers == nil {
		t = &PurgeTable{ID: t.ID, Markers: []PurgeMarker{}}
	}
	var s PurgeStatus
	if err := c.do(ctx, method, "/v1/purge", t, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// PutActiveHealth replaces the set of origins the active health checks
// mark down.
func (c *Client) PutActiveHealth(ctx context.Context, doc *ActiveHealth) (*ActiveHealthStatus, error) {
	if doc == nil {
		return nil, errors.New("nil active health set")
	}
	if doc.Down == nil {
		doc = &ActiveHealth{TTL: doc.TTL, Down: []ActiveOrigin{}}
	}
	var s ActiveHealthStatus
	if err := c.do(ctx, http.MethodPut, "/v1/origins/active", doc, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// OriginHealth returns the origins with recorded failures.
func (c *Client) OriginHealth(ctx context.Context) ([]OriginHealth, error) {
	var out struct {
		Origins json.RawMessage `json:"origins"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/origins/health", nil, &out); err != nil {
		return nil, err
	}
	raw := bytes.TrimSpace(out.Origins)
	if len(raw) == 0 || bytes.Equal(raw, []byte("{}")) || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}
	var list []OriginHealth
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("decode origin health: %w", err)
	}
	return list, nil
}

// drainAll is the body of a drain that takes the current minute too.
var drainAll = map[string]bool{"all": true}

// DrainStats returns and deletes the completed per-minute counters; with
// all, the current minute's too (nginx is about to stop and would lose
// them).
func (c *Client) DrainStats(ctx context.Context, all bool) ([]MinuteStats, error) {
	var out struct {
		Stats json.RawMessage `json:"stats"`
	}
	var body any
	if all {
		body = drainAll
	}
	if err := c.do(ctx, http.MethodPost, "/v1/stats/drain", body, &out); err != nil {
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
