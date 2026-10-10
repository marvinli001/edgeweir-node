package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type sampledLog struct {
	Time        float64 `json:"time"`
	SiteID      string  `json:"site_id"`
	ClientIP    string  `json:"client_ip"`
	Method      string  `json:"method"`
	Host        string  `json:"host"`
	Path        string  `json:"path"`
	Status      uint32  `json:"status"`
	BytesSent   uint64  `json:"bytes_sent"`
	DurationMS  uint32  `json:"duration_ms"`
	CacheStatus string  `json:"cache_status"`
	SampleRate  uint32  `json:"sample_rate"`
	JA4         string  `json:"ja4"`
	// WAFRuleIDs are the CRS rules that matched (at most 16), WAFBlocked
	// whether CRS blocked the request.
	WAFRuleIDs []uint32 `json:"waf_rule_ids"`
	WAFBlocked bool     `json:"waf_blocked"`
	// RequestID is the X-Request-Id the node answered with.
	RequestID string `json:"request_id"`
	// RuleIDs are the log rules with access_log that asked for the line
	// (at most 8; proto v0.29.0).
	RuleIDs []string `json:"rule_ids"`
	logFields
	// The site's optional fields (proto v0.30.0, feature access-logs-v2).
	Query   string            `json:"query"`
	Headers map[string]string `json:"headers"`
	PeerIP  string            `json:"peer_ip"`
}

// logFields are the fields of proto v0.30.0 (ADR-0041 §1) every line and
// live view record carries.
type logFields struct {
	UserAgent      string `json:"user_agent,omitempty"`
	Referer        string `json:"referer,omitempty"`
	HTTPVersion    string `json:"http_version,omitempty"`
	Scheme         string `json:"scheme,omitempty"`
	Country        string `json:"country,omitempty"`
	ASN            uint32 `json:"asn,omitempty"`
	ASName         string `json:"as_name,omitempty"`
	UpstreamAddr   string `json:"upstream_addr,omitempty"`
	UpstreamStatus uint32 `json:"upstream_status,omitempty"`
	UpstreamMS     uint32 `json:"upstream_ms,omitempty"`
	RequestBytes   uint64 `json:"request_bytes,omitempty"`
	ContentType    string `json:"content_type,omitempty"`
	TLSVersion     string `json:"tls_version,omitempty"`
	BlockReason    string `json:"block_reason,omitempty"`
	BlockRuleID    string `json:"block_rule_id,omitempty"`
}

// maxRequestID bounds AccessLog.request_id.
const maxRequestID = 128

// maxLogRuleIDs bounds AccessLog.waf_rule_ids.
const maxLogRuleIDs = 16

// maxLogRules bounds AccessLog.rule_ids.
const maxLogRules = 8

// Bounds of the proto v0.30.0 fields (the data plane applies the same).
const (
	maxUserAgent    = 512
	maxReferer      = 1024
	maxASName       = 128
	maxUpstreamAddr = 128
	maxContentType  = 128
	maxQuery        = 2048
	maxHeaderValue  = 512
	maxUpstreamMS   = 86_400_000
	// maxSafeInteger is the largest integer a JSON number holds exactly.
	maxSafeInteger = 1<<53 - 1
)

// BlockReasons are the block reasons of AccessLog.block_reason and
// MinuteStats.block_reasons (ADR-0041 §3, the console's BLOCK_REASONS).
var BlockReasons = []string{"ip_banned", "ip_blocked", "rule", "rate_limit", "crs", "cc", "challenge", "auth", "referer",
	"user_agent", "region", "cors", "websocket_origin", "client_cert", "maintenance"}

var (
	countryRE    = regexp.MustCompile(`^[A-Z]{2}$`)
	mediaTypeRE  = regexp.MustCompile(`^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$`)
	logHeaderRE  = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	blockReasons = setOf(BlockReasons...)
	httpVersions = setOf("1.0", "1.1", "2", "3")
	tlsVersions  = setOf("1.2", "1.3")
	forbidden    = setOf("authorization", "cookie", "proxy-authorization")
)

func setOf(keys ...string) map[string]bool {
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[k] = true
	}
	return out
}

// Text strips control characters (and invalid UTF-8) from s and cuts it to
// at most n bytes without splitting a character.
func Text(s string, n int) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > n {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// logRules keeps the valid rule ids of a line, at most maxLogRules.
func logRules(ids []string) []string {
	var out []string
	for _, id := range ids {
		if len(out) == maxLogRules {
			break
		}
		if configir.ValidID(id) {
			out = append(out, id)
		}
	}
	return out
}

// bounded validates the proto v0.30.0 fields with the bounds of ADR-0041:
// what is out of bounds is cut, what is invalid is left empty.
func (f logFields) bounded() logFields {
	f.UserAgent = Text(f.UserAgent, maxUserAgent)
	if i := strings.IndexAny(f.Referer, "?#"); i >= 0 {
		f.Referer = f.Referer[:i]
	}
	f.Referer = Text(f.Referer, maxReferer)
	if !httpVersions[f.HTTPVersion] {
		f.HTTPVersion = ""
	}
	if f.Scheme != "http" && f.Scheme != "https" {
		f.Scheme = ""
	}
	if !countryRE.MatchString(f.Country) {
		f.Country = ""
	}
	f.ASName = Text(f.ASName, maxASName)
	if f.ASN == 0 {
		f.ASName = ""
	}
	if f.UpstreamStatus < 100 || f.UpstreamStatus > 599 {
		f.UpstreamStatus = 0
	}
	f.UpstreamAddr = Text(f.UpstreamAddr, maxUpstreamAddr)
	f.UpstreamMS = min(f.UpstreamMS, maxUpstreamMS)
	f.RequestBytes = min(f.RequestBytes, maxSafeInteger)
	if len(f.ContentType) > maxContentType || !mediaTypeRE.MatchString(f.ContentType) {
		f.ContentType = ""
	}
	if !tlsVersions[f.TLSVersion] {
		f.TLSVersion = ""
	}
	if !blockReasons[f.BlockReason] {
		f.BlockReason = ""
	}
	if f.BlockReason == "" || !configir.ValidID(f.BlockRuleID) {
		f.BlockRuleID = ""
	}
	return f
}

// logHeaders keeps the recorded request headers a line may carry: valid
// lowercase names, never authorization, cookie or proxy-authorization, at
// most configir.MaxLogHeaders (the first by name), each value at most 512
// bytes.
func logHeaders(in map[string]string) map[string]string {
	names := make([]string, 0, len(in))
	for name := range in {
		if logHeaderRE.MatchString(name) && !forbidden[name] {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	slices.Sort(names)
	out := make(map[string]string, min(len(names), configir.MaxLogHeaders))
	for _, name := range names[:min(len(names), configir.MaxLogHeaders)] {
		out[name] = Text(in[name], maxHeaderValue)
	}
	return out
}

// peerIP keeps a valid address.
func peerIP(s string) string {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String()
	}
	return ""
}

func (c *Client) DrainLogs(ctx context.Context) ([]*nodev1.AccessLog, error) {
	var out struct {
		Logs json.RawMessage `json:"logs"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/logs/drain", nil, &out); err != nil {
		return nil, err
	}
	raw := bytes.TrimSpace(out.Logs)
	if bytes.Equal(raw, []byte("{}")) || bytes.Equal(raw, []byte("null")) || len(raw) == 0 {
		return nil, nil
	}
	var rows []sampledLog
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	logs := make([]*nodev1.AccessLog, 0, len(rows))
	for _, l := range rows {
		if len(l.WAFRuleIDs) > maxLogRuleIDs {
			l.WAFRuleIDs = l.WAFRuleIDs[:maxLogRuleIDs]
		}
		if len(l.RequestID) > maxRequestID {
			l.RequestID = l.RequestID[:maxRequestID]
		}
		f := l.logFields.bounded()
		logs = append(logs, &nodev1.AccessLog{
			Time: timestamppb.New(time.UnixMilli(int64(l.Time * 1000))), SiteId: l.SiteID, ClientIp: l.ClientIP, Method: l.Method, Host: l.Host, Path: l.Path, Status: l.Status, BytesSent: l.BytesSent, DurationMs: l.DurationMS, CacheStatus: l.CacheStatus, SampleRate: l.SampleRate, Ja4: l.JA4,
			WafRuleIds: l.WAFRuleIDs, WafBlocked: l.WAFBlocked, RequestId: l.RequestID, RuleIds: logRules(l.RuleIDs),
			UserAgent: f.UserAgent, Referer: f.Referer, HttpVersion: f.HTTPVersion, Scheme: f.Scheme,
			Country: f.Country, Asn: f.ASN, AsName: f.ASName,
			UpstreamAddr: f.UpstreamAddr, UpstreamStatus: f.UpstreamStatus, UpstreamMs: f.UpstreamMS,
			RequestBytes: f.RequestBytes, ContentType: f.ContentType, TlsVersion: f.TLSVersion,
			BlockReason: f.BlockReason, BlockRuleId: f.BlockRuleID,
			Query: Text(l.Query, maxQuery), Headers: logHeaders(l.Headers), PeerIp: peerIP(l.PeerIP),
		})
	}
	return logs, nil
}
