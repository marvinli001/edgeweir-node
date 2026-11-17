package hostinfo

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

const metadataURL = "http://169.254.169.254/latest/"

var metadataClient = &http.Client{
	Transport: &http.Transport{
		Proxy:             nil,
		DialContext:       (&net.Dialer{Timeout: time.Second}).DialContext,
		DisableKeepAlives: true,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	Timeout:       2 * time.Second,
}

// AWSPublicIPv4 reads the instance's own NAT mapping, never an external echo service or proxy.
func AWSPublicIPv4(ctx context.Context) (string, error) {
	vendor, _ := os.ReadFile("/sys/class/dmi/id/sys_vendor")
	uuid, _ := os.ReadFile("/sys/hypervisor/uuid")
	if strings.TrimSpace(string(vendor)) != "Amazon EC2" && !strings.HasPrefix(strings.ToLower(string(uuid)), "ec2") {
		return "", nil
	}
	return awsPublicIPv4(ctx, metadataClient)
}

func awsPublicIPv4(ctx context.Context, client *http.Client) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	read := func(method, path, token string) (string, int, error) {
		req, err := http.NewRequestWithContext(ctx, method, metadataURL+path, nil)
		if err != nil {
			return "", 0, err
		}
		if method == http.MethodPut {
			req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
		} else {
			req.Header.Set("X-aws-ec2-metadata-token", token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", 0, fmt.Errorf("AWS metadata request failed")
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4097))
		if err != nil || len(body) > 4096 {
			return "", resp.StatusCode, fmt.Errorf("invalid AWS metadata response")
		}
		return strings.TrimSpace(string(body)), resp.StatusCode, nil
	}
	token, code, err := read(http.MethodPut, "api/token", "")
	if err != nil || code != http.StatusOK || token == "" || strings.ContainsAny(token, "\r\n") {
		return "", fmt.Errorf("AWS metadata token unavailable")
	}
	address, code, err := read(http.MethodGet, "meta-data/public-ipv4", token)
	if err != nil {
		return "", err
	}
	if code == http.StatusNotFound {
		return "", nil
	}
	ip, err := netip.ParseAddr(address)
	if code != http.StatusOK || err != nil || !ip.Is4() || (configir.AddressPolicy{}).Forbidden(ip) {
		return "", fmt.Errorf("AWS metadata returned no public IPv4")
	}
	return ip.String(), nil
}
