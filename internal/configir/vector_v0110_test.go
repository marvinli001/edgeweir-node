package configir

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// v0110Fields adds the proto v0.11.0 fields to a copy of the M2 vector:
// Brotli and Zstandard on the first site of the file (types unsorted, with
// a duplicate) and SiteWaf on the second (excluded rule ids unsorted, with
// a duplicate). The canonical form sorts and deduplicates both type lists
// and the rule ids, as the console does before hashing.
func v0110Fields(m2 *nodev1.NodeConfig) *nodev1.NodeConfig {
	c := proto.CloneOf(m2)
	c.Sites[0].Tls = &nodev1.TlsOptions{
		MinimumVersion: "1.2", CipherProfile: "modern", Gzip: true, GzipMinLength: 256,
		GzipTypes:   []string{"text/css", "application/json"},
		Brotli:      true,
		BrotliLevel: 5, BrotliMinLength: 512,
		BrotliTypes: []string{"text/css", "application/json", "text/css"},
		Zstd:        true,
		ZstdLevel:   19, ZstdMinLength: 1024,
		ZstdTypes: []string{"text/plain", "image/svg+xml"},
	}
	c.Sites[1].Waf = &nodev1.SiteWaf{
		Mode: "block", ParanoiaLevel: 2, AnomalyThreshold: 10, RequestBodyLimit: 131072,
		ExcludedRuleIds: []uint32{942100, 920350, 942100},
	}
	c.RequiredFeatures = []string{"zstd-v1", "modsecurity-v1", "brotli-v1"}
	return c
}

// TestContentHashVectorV0110 checks the proto v0.11.0 vector for the
// console (testdata/content_hash_vector_v0110.json): the M2 vector plus
// the fields of v0110Fields. Run with -update to rewrite the file from the
// Go encoding; the console's hash of the same config must match it.
func TestContentHashVectorV0110(t *testing.T) {
	path := filepath.Join("testdata", "content_hash_vector_v0110.json")
	want := v0110Fields(m2VectorConfig(t))
	b, err := CanonicalBytes(want)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ContentHash(want)
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		cfg, err := protojson.MarshalOptions{Multiline: false}.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		out, err := json.MarshalIndent(hashVector{
			Description: "proto v0.11.0 NodeConfig content_hash test vector: the M2 vector plus TlsOptions with gzip, Brotli and Zstandard on the first site of this file (brotli_types unsorted with a duplicate, zstd_types unsorted) and SiteWaf on the second (excluded_rule_ids unsorted with a duplicate), required_features unsorted; the canonical form sorts and deduplicates gzip_types, brotli_types, zstd_types, excluded_rule_ids and required_features: sha256(deterministic binary encoding with revision=0 and content_hash=\"\") after canonical sorting",
			Config:      cfg, CanonicalHex: hex.EncodeToString(b), ContentHash: h,
		}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
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
	if !proto.Equal(cfg, want) {
		t.Fatalf("vector config is not the M2 vector plus the v0.11.0 fields:\n%v", cfg)
	}
	if v.CanonicalHex != hex.EncodeToString(b) || v.ContentHash != h {
		t.Fatalf("vector hash %s, Go computes %s", v.ContentHash, h)
	}
	// The unsorted lists hash like their canonical form: sorted, without
	// duplicates.
	Canonicalize(cfg)
	var tls *nodev1.TlsOptions
	var waf *nodev1.SiteWaf
	for _, s := range cfg.Sites {
		if s.Tls != nil {
			tls = s.Tls
		}
		if s.Waf != nil {
			waf = s.Waf
		}
	}
	for name, got := range map[string][]string{
		"brotli_types": tls.GetBrotliTypes(), "zstd_types": tls.GetZstdTypes(), "gzip_types": tls.GetGzipTypes(),
	} {
		if !slices.IsSorted(got) || len(slices.Compact(slices.Clone(got))) != len(got) {
			t.Errorf("canonical %s %v", name, got)
		}
	}
	if got := tls.GetBrotliTypes(); !slices.Equal(got, []string{"application/json", "text/css"}) {
		t.Errorf("canonical brotli_types %v", got)
	}
	if got := waf.GetExcludedRuleIds(); !slices.Equal(got, []uint32{920350, 942100}) {
		t.Errorf("canonical excluded_rule_ids %v", got)
	}
	if hc, _ := ContentHash(cfg); hc != h {
		t.Fatalf("canonical config hashes to %s, want %s", hc, h)
	}
}
