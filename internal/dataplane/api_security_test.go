package dataplane_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

func TestDrainLogsCarriesBoundedAPISecurityMetadata(t *testing.T) {
	srv := fakedataplane.Start(t)
	c := dataplane.NewClient(srv.Socket)
	metadata := map[string]any{"template": "/api/users/{id}", "source": "schema", "issues": []any{map[string]any{"check": "jwt", "code": "jwt-invalid", "mode": "enforce"}}, "exceptionIds": []string{}}
	srv.AddLogEntry(map[string]any{"site_id": "s1", "time": 1800000000, "status": 403, "request_id": "api-request", "block_reason": "api_security", "api_security": metadata})
	srv.AddLogEntry(map[string]any{"site_id": "s1", "time": 1800000001, "api_security": map[string]any{"template": "/api", "source": "traffic", "issues": []any{}, "exceptionIds": []string{}, "token": "must-not-enter-log"}})
	srv.AddLogEntry(map[string]any{"site_id": "s1", "time": 1800000002, "api_security": map[string]any{"template": "/" + strings.Repeat("x", 4096), "source": "traffic", "issues": []any{}, "exceptionIds": []string{}}})
	logs, err := c.DrainLogs(context.Background())
	if err != nil || len(logs) != 3 {
		t.Fatalf("logs %v %v", logs, err)
	}
	if logs[0].GetApiSecurityJson() == "" || logs[0].GetBlockReason() != "api_security" || logs[0].GetRequestId() != "api-request" {
		t.Fatalf("missing API log: %v", logs[0])
	}
	var decoded map[string]any
	if json.Unmarshal([]byte(logs[0].GetApiSecurityJson()), &decoded) != nil || decoded["template"] != "/api/users/{id}" {
		t.Fatal("API log corrupted")
	}
	if logs[1].GetApiSecurityJson() != "" || logs[2].GetApiSecurityJson() != "" {
		t.Fatal("unbounded or unknown fields entered proto metadata")
	}
}
