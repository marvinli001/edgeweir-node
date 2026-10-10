package dataplane

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
)

// TapEntry is a request of the live view (GET /v1/logs/tap, ADR-0041 §6):
// the fields of a sampled access log line without the site's optional
// ones; SiteID is "" for requests of no site.
type TapEntry struct {
	Time        float64 `json:"time"`
	SiteID      string  `json:"site_id"`
	ClientIP    string  `json:"client_ip"`
	Method      string  `json:"method"`
	Host        string  `json:"host"`
	Path        string  `json:"path"`
	Status      uint32  `json:"status"`
	BytesSent   uint64  `json:"bytes_sent"`
	DurationMS  uint32  `json:"duration_ms"`
	CacheStatus string  `json:"cache_status,omitempty"`
	RequestID   string  `json:"request_id,omitempty"`
	logFields
}

// TapPage is one answer of the live view: the entries after the sequence
// number asked for, the last number read (to ask after next time) and how
// many numbers were missed (expired or over the rate).
type TapPage struct {
	Seq     uint64     `json:"seq"`
	Entries []TapEntry `json:"entries"`
	Missed  uint64     `json:"missed"`
}

// Tap reads the live view after seq (0: the first call, which only returns
// the current number), only the requests of site when it is not empty.
// Each call keeps the data plane recording for five more seconds.
func (c *Client) Tap(ctx context.Context, after uint64, site string) (*TapPage, error) {
	q := url.Values{"after": {strconv.FormatUint(after, 10)}}
	if site != "" {
		q.Set("site", site)
	}
	var out struct {
		Seq     uint64         `json:"seq"`
		Entries List[TapEntry] `json:"entries"`
		Missed  uint64         `json:"missed"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/logs/tap?"+q.Encode(), nil, &out); err != nil {
		return nil, err
	}
	page := &TapPage{Seq: out.Seq, Entries: out.Entries, Missed: out.Missed}
	for i := range page.Entries {
		page.Entries[i].logFields = page.Entries[i].logFields.bounded()
	}
	return page, nil
}
