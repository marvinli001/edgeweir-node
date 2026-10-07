package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/marvinli001/edgeweir-node/internal/agent"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

// agentPost sends a request to the agent socket like the data plane does.
func agentPost(t *testing.T, socket, path string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}, Timeout: 10 * time.Second}
	resp, err := client.Post("http://agent"+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	data, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

// TestAgentPurgeMethod: the agent checks a PURGE request's key against the
// site's key (fetched like S3 credentials) and submits the URL purge to
// the console; the key never reaches the data plane's site table.
func TestAgentPurgeMethod(t *testing.T) {
	site := demoSite("site-p", "p.test")
	site.Purge = &nodev1.PurgeMethod{CredentialId: "purge-key-1", CredentialVersion: 2}
	plain := demoSite("site-q", "q.test")
	e := startEnrolledPrepared(t, "purge-method", nil, func(c *fakeconsole.Console, _ *fakedataplane.Server) {
		c.SetCredential(&nodev1.OriginCredential{Id: "purge-key-1", Version: 2, SecretAccessKey: "s3cret-purge-key"})
	}, baseConfig(site, plain))
	defer e.stop()
	socket := filepath.Join(filepath.Dir(e.cfg.Render.ControlSocket), "agent.sock")
	if st, err := os.Stat(socket); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("agent socket: %v, %v", st, err)
	}
	raw, _ := json.Marshal(e.dp.Table())
	if table := string(raw); strings.Contains(table, "s3cret-purge-key") || !strings.Contains(table, `"purge":true`) {
		t.Fatalf("site table holds the key or lacks the PURGE flag: %s", table)
	}

	url := "https://p.test/a/b.css?v=1"
	status, out := agentPost(t, socket, "/v1/purge", map[string]string{"site_id": "site-p", "url": url, "key": "s3cret-purge-key"})
	if status != http.StatusAccepted || out["task_id"] != "purge-1" {
		t.Fatalf("PURGE = %d %v", status, out)
	}
	if got := e.console.Purges(); len(got) != 1 || got[0].GetSiteId() != "site-p" || got[0].GetUrl() != url {
		t.Fatalf("console got %v", got)
	}
	for _, tc := range []struct {
		name   string
		body   map[string]string
		status int
		code   string
	}{
		{"wrong key", map[string]string{"site_id": "site-p", "url": url, "key": "s3cret-purge-kez"}, 403, "purge-key-invalid"},
		{"no key", map[string]string{"site_id": "site-p", "url": url}, 403, "purge-key-invalid"},
		{"site without PURGE", map[string]string{"site_id": "site-q", "url": url, "key": "s3cret-purge-key"}, 403, "purge-disabled"},
		{"unknown site", map[string]string{"site_id": "nope", "url": url, "key": "s3cret-purge-key"}, 403, "purge-disabled"},
		{"long URL", map[string]string{"site_id": "site-p", "url": "https://p.test/" + strings.Repeat("a", 2048), "key": "s3cret-purge-key"}, 400, "purge-url-invalid"},
	} {
		status, out := agentPost(t, socket, "/v1/purge", tc.body)
		if status != tc.status || out["error"] != tc.code {
			t.Errorf("%s: %d %v, want %d %s", tc.name, status, out, tc.status, tc.code)
		}
	}
	if n := len(e.console.Purges()); n != 1 {
		t.Fatalf("refused requests reached the console: %d purges", n)
	}
	for _, tc := range []struct {
		err    error
		status int
		code   string
		retry  float64
	}{
		{connect.NewError(connect.CodeResourceExhausted, errors.New("retry after 42")), 429, "purge-rate-limited", 42},
		{connect.NewError(connect.CodePermissionDenied, errors.New("no PURGE method")), 403, "purge-disabled", 0},
		{connect.NewError(connect.CodeInvalidArgument, errors.New("host")), 400, "purge-url-invalid", 0},
		{connect.NewError(connect.CodeUnavailable, errors.New("down")), 503, "purge-unavailable", 0},
	} {
		e.console.SetPurgeError(tc.err)
		status, out := agentPost(t, socket, "/v1/purge", map[string]string{"site_id": "site-p", "url": url, "key": "s3cret-purge-key"})
		retry, _ := out["retry_after"].(float64)
		if status != tc.status || out["error"] != tc.code || retry != tc.retry {
			t.Errorf("console error %v: %d %v", tc.err, status, out)
		}
	}
	e.console.SetPurgeError(nil)
	// Requests without the right key never count against the site's
	// budget: after 40 of them the right key still works, and the budget
	// (20 a second) runs out only with accepted requests.
	for range 40 {
		if status, _ := agentPost(t, socket, "/v1/purge", map[string]string{"site_id": "site-p", "url": url, "key": "wrong-key-0123456789"}); status != 403 {
			t.Fatalf("wrong key: %d", status)
		}
	}
	limited := false
	for i := 0; i < 41 && !limited; i++ {
		status, out := agentPost(t, socket, "/v1/purge", map[string]string{"site_id": "site-p", "url": url, "key": "s3cret-purge-key"})
		switch {
		case i == 0 && (status != http.StatusAccepted || out["task_id"] == nil):
			// The 40 wrong keys must not have used up the site's budget.
			t.Fatalf("the right key after 40 wrong ones: %d %v", status, out)
		case status == http.StatusTooManyRequests && out["error"] == "purge-rate-limited" && out["retry_after"] == float64(1):
			limited = true
		case status != http.StatusAccepted:
			t.Fatalf("accepted request %d: %d %v", i+1, status, out)
		}
	}
	if !limited {
		t.Fatal("41 accepted requests within two seconds were not rate limited")
	}
}

// TestAgentCacheUsage: the agent measures the cache zone's directory and
// reports it with the heartbeat, with the zone's size on this node.
func TestAgentCacheUsage(t *testing.T) {
	config := baseConfig(demoSite("site-u", "u.test"))
	config.CacheZones[0].NodeSizes = []*nodev1.CacheZoneNodeSize{{NodeId: "node-usage", MaxSizeMb: 2048, KeysZoneMb: 16}}
	var cacheDir string
	e := startEnrolledPrepared(t, "usage", func(c *agent.Config) {
		c.CacheUsageInterval = 200 * time.Millisecond
		cacheDir = c.Render.CacheDir
		zone := filepath.Join(cacheDir, "default", "a", "bc")
		if err := os.MkdirAll(zone, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(zone, "object"), bytes.Repeat([]byte("x"), 100000), 0o600); err != nil {
			t.Fatal(err)
		}
	}, nil, config)
	defer e.stop()
	var usage *nodev1.CacheZoneUsage
	eventually(t, "cache usage reported", func() bool {
		s := e.console.LastStatus()
		if s == nil || len(s.GetCacheUsage()) != 1 {
			return false
		}
		usage = s.GetCacheUsage()[0]
		return true
	})
	if usage.GetName() != "default" || usage.GetUsedBytes() < 100000 || usage.GetMaxBytes() != 2048<<20 || usage.GetMeasuredAt() == nil {
		t.Fatalf("usage = %v", usage)
	}
	if _, _, conf := e.eng.counts(); !strings.Contains(conf, "max_size=2048m") {
		t.Fatal("nginx.conf does not use the node's own cache size")
	}
}
