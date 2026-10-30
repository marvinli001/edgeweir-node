package configir

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func developmentModeVector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_development_mode.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v hashVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	cfg := &nodev1.NodeConfig{}
	if err := protojson.Unmarshal(v.Config, cfg); err != nil {
		t.Fatal(err)
	}
	return cfg, v
}

// TestContentHashVectorDevelopmentMode matches the console's vector:
// Site.development_mode with its deadline in the hash.
func TestContentHashVectorDevelopmentMode(t *testing.T) {
	cfg, v := developmentModeVector(t)
	if cfg.GetSites()[0].GetId() != "b" {
		t.Fatal("vector is already canonical")
	}
	b, err := CanonicalBytes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ContentHash(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v.CanonicalHex != hex.EncodeToString(b) {
		t.Fatalf("canonical bytes differ from the console\n got %x\nwant %s", b, v.CanonicalHex)
	}
	if v.ContentHash != h {
		t.Fatalf("vector hash %s, Go computes %s", v.ContentHash, h)
	}
	if err := VerifyHash(cfg); err != nil {
		t.Fatal(err)
	}
	c, _ := developmentModeVector(t)
	vectorSite(c, "a").DevelopmentMode.ExpiresAt.Seconds++
	if hc, _ := ContentHash(c); hc == h {
		t.Error("the deadline does not change the hash")
	}
}

// TestDevelopmentMode: the deadline reaches the data plane as a Unix second
// (development_mode_until), sites without it send nothing, the feature is
// announced, and development mode without a valid end rejects the
// configuration.
func TestDevelopmentMode(t *testing.T) {
	if !slices.Contains(SupportedFeatures, FeatureDevelopmentMode) {
		t.Fatalf("SupportedFeatures lacks %s", FeatureDevelopmentMode)
	}
	cfg, _ := developmentModeVector(t)
	Canonicalize(cfg)
	plan, err := Build(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range plan.Sites {
		raw, _ := json.Marshal(site)
		switch site.ID {
		case "a":
			// 2026-11-01T03:00:00Z
			if site.DevelopmentModeUntil != 1793502000 || !strings.Contains(string(raw), `"development_mode_until":1793502000`) {
				t.Fatalf("site a json %s", raw)
			}
		case "b":
			if strings.Contains(string(raw), "development_mode_until") {
				t.Fatalf("site b json %s", raw)
			}
		}
	}

	// A deadline in the past is kept (the data plane treats it as off).
	for _, tc := range []struct {
		mode *nodev1.DevelopmentMode
		want int64
		ok   bool
	}{
		{nil, 0, true},
		{&nodev1.DevelopmentMode{ExpiresAt: &timestamppb.Timestamp{Seconds: 1577836800}}, 1577836800, true},
		{&nodev1.DevelopmentMode{}, 0, false},
		{&nodev1.DevelopmentMode{ExpiresAt: &timestamppb.Timestamp{}}, 0, false},
		{&nodev1.DevelopmentMode{ExpiresAt: &timestamppb.Timestamp{Seconds: 1, Nanos: -1}}, 0, false},
	} {
		got, err := buildDevelopmentMode(&nodev1.Site{DevelopmentMode: tc.mode})
		if tc.ok && (err != nil || got != tc.want) {
			t.Errorf("%v: %d, %v", tc.mode, got, err)
		}
		if !tc.ok && !errors.Is(err, ErrRejected) {
			t.Errorf("%v accepted: %d, %v", tc.mode, got, err)
		}
	}
	bad, _ := developmentModeVector(t)
	vectorSite(bad, "a").DevelopmentMode.ExpiresAt = nil
	Canonicalize(bad)
	if _, err := Build(bad, Options{}); !errors.Is(err, ErrRejected) {
		t.Fatalf("development mode without an end accepted: %v", err)
	}
}
