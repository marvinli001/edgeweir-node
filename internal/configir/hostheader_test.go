package configir

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// hostHeaderVectors reads testdata/host_header_vectors.json, a copy of the
// console's packages/rule-engine/test/host_header_vectors.json: the console
// checks the Host header of origins and origin rules with the same cases
// before saving, so that no origin is skipped here for its Host header.
func hostHeaderVectors(t *testing.T) []struct {
	Value string `json:"value"`
	Valid bool   `json:"valid"`
	Note  string `json:"note"`
} {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "host_header_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []struct {
			Value string `json:"value"`
			Valid bool   `json:"valid"`
			Note  string `json:"note"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("no host header vectors")
	}
	return v.Cases
}

func TestHostHeaderVectors(t *testing.T) {
	for _, c := range hostHeaderVectors(t) {
		if got := validHostHeader(c.Value); got != c.Valid {
			t.Errorf("validHostHeader(%s) = %v, want %v (%s)", strconv.Quote(c.Value), got, c.Valid, c.Note)
		}
	}
}

// TestHostHeaderVectorsOrigins runs the vectors through buildOrigin and the
// origin rule check, which refuse an origin or a rule for its Host header.
func TestHostHeaderVectorsOrigins(t *testing.T) {
	for _, c := range hostHeaderVectors(t) {
		if c.Value == "" || strings.TrimSpace(c.Value) != c.Value {
			continue // unset, or trimmed first (as the console does)
		}
		_, err := buildOrigin(&nodev1.Origin{Id: "o", Address: "192.0.2.1", Port: 80, HostHeader: c.Value})
		if (err == nil) != c.Valid {
			t.Errorf("buildOrigin with host_header %s: err = %v, want valid %v", strconv.Quote(c.Value), err, c.Valid)
		}
		if got := validOriginAction(&nodev1.RuleAction{HostHeader: c.Value}); got != c.Valid {
			t.Errorf("validOriginAction with host_header %s = %v, want %v", strconv.Quote(c.Value), got, c.Valid)
		}
	}
}
