package upgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

type Client struct{ http *http.Client }

func NewClient(socket string) *Client {
	return &Client{http: &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}, DisableKeepAlives: true}}}
}
func (c *Client) do(ctx context.Context, method, path string, input, output any) error {
	var data []byte
	var err error
	if input != nil {
		data, err = json.Marshal(input)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://upgrade"+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("supervisor request failed (%d)", resp.StatusCode)
	}
	if output != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(output)
	}
	return nil
}
func (c *Client) Available(ctx context.Context) bool {
	var out struct {
		Enabled bool `json:"enabled"`
	}
	return c.do(ctx, http.MethodGet, "/capabilities", nil, &out) == nil && out.Enabled
}
func (c *Client) Stage(ctx context.Context, t Task) error {
	return c.do(ctx, http.MethodPost, "/stage", t, nil)
}
func (c *Client) Result(ctx context.Context) (*Result, error) {
	var out *Result
	err := c.do(ctx, http.MethodGet, "/result", nil, &out)
	return out, err
}
func (c *Client) Ack(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/ack", map[string]string{"id": id}, nil)
}
func (c *Client) ReportHealth(ctx context.Context, version string, healthy bool) error {
	return c.do(ctx, http.MethodPost, "/health", struct {
		PID     int    `json:"pid"`
		Version string `json:"version"`
		Healthy bool   `json:"healthy"`
	}{os.Getpid(), version, healthy}, nil)
}
func (c *Client) Healthy(ctx context.Context, version string) error {
	return c.ReportHealth(ctx, version, true)
}
