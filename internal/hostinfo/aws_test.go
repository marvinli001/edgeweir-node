package hostinfo

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type metadataTransport func(*http.Request) (*http.Response, error)

func (f metadataTransport) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestAWSMetadataPublicIPv4(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		code       int
		want       string
	}{
		{"NAT mapping", "8.8.4.4\n", 200, "8.8.4.4"},
		{"no public mapping", "not found", 404, ""},
		{"private", "172.26.5.67", 200, ""},
		{"shared egress", "100.64.0.1", 200, ""},
		{"IPv6", "2406:da14::1", 200, ""},
		{"expired token", "denied", 401, ""},
		{"redirect", "", 302, ""},
		{"oversize", strings.Repeat("x", 4097), 200, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			client := &http.Client{Transport: metadataTransport(func(req *http.Request) (*http.Response, error) {
				requests++
				if req.URL.Host != "169.254.169.254" {
					t.Fatalf("unexpected host: %s", req.URL.Host)
				}
				body, code := tc.body, tc.code
				if requests == 1 {
					if req.Method != "PUT" || req.URL.Path != "/latest/api/token" || req.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") != "60" {
						t.Fatalf("not IMDSv2: %v", req)
					}
					body, code = "test-only-metadata-token", 200
				} else if req.Method != "GET" || req.URL.Path != "/latest/meta-data/public-ipv4" || req.Header.Get("X-aws-ec2-metadata-token") != "test-only-metadata-token" {
					t.Fatalf("invalid metadata request: %v", req)
				}
				return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})}
			got, err := awsPublicIPv4(context.Background(), client)
			if got != tc.want || (tc.want == "" && tc.code != 404 && err == nil) {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
			if requests != 2 {
				t.Fatalf("requests: %d", requests)
			}
		})
	}
}

func TestAWSMetadataCancellationAndTokenRefusal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := &http.Client{Transport: metadataTransport(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}
	start := time.Now()
	if _, err := awsPublicIPv4(ctx, client); err == nil || time.Since(start) > time.Second {
		t.Fatalf("cancellation: %v", err)
	}
	requests := 0
	client.Transport = metadataTransport(func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader("denied"))}, nil
	})
	if _, err := awsPublicIPv4(context.Background(), client); err == nil || requests != 1 {
		t.Fatalf("token refusal: %v, requests=%d", err, requests)
	}
	transport := metadataClient.Transport.(*http.Transport)
	if transport.Proxy != nil || metadataClient.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("metadata must bypass proxies and refuse redirects")
	}
}
