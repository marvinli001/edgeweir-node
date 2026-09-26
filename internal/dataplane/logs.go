package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
	"net/http"
	"time"
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
		logs = append(logs, &nodev1.AccessLog{
			Time: timestamppb.New(time.UnixMilli(int64(l.Time * 1000))), SiteId: l.SiteID, ClientIp: l.ClientIP, Method: l.Method, Host: l.Host, Path: l.Path, Status: l.Status, BytesSent: l.BytesSent, DurationMs: l.DurationMS, CacheStatus: l.CacheStatus, SampleRate: l.SampleRate,
		})
	}
	return logs, nil
}
