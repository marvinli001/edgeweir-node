package configir

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// v0310Vector reads testdata/content_hash_vector_v0310.json, a copy of the
// console's fixture: site a converts JPEG originals of 1 KiB to 10 MiB and
// up to 16 megapixels to WebP (quality 80) and AVIF (quality 50), site b
// converts nothing. Sites and required features are reversed.
func v0310Vector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_v0310.json"))
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

// TestContentHashVectorV0310 checks the proto v0.31.0 vector shared with
// the console: every conversion setting in the hash, and the plan.
func TestContentHashVectorV0310(t *testing.T) {
	cfg, v := v0310Vector(t)
	if cfg.GetSites()[0].GetId() != "b" || cfg.GetRequiredFeatures()[0] != "tls-v1" {
		t.Fatalf("vector is already canonical")
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
	conv := func(c *nodev1.NodeConfig) *nodev1.ImageConvert { return vectorSite(c, "a").GetImageConvert() }
	for name, change := range map[string]func(*nodev1.NodeConfig){
		"webp":         func(c *nodev1.NodeConfig) { conv(c).Webp = false },
		"avif":         func(c *nodev1.NodeConfig) { conv(c).Avif = false },
		"webp quality": func(c *nodev1.NodeConfig) { conv(c).WebpQuality = 81 },
		"avif quality": func(c *nodev1.NodeConfig) { conv(c).AvifQuality = 51 },
		"jpeg":         func(c *nodev1.NodeConfig) { conv(c).Jpeg = false },
		"png":          func(c *nodev1.NodeConfig) { conv(c).Png = true },
		"min size":     func(c *nodev1.NodeConfig) { conv(c).MinSize = 0 },
		"max size":     func(c *nodev1.NodeConfig) { conv(c).MaxSize = 1 << 20 },
		"max pixels":   func(c *nodev1.NodeConfig) { conv(c).MaxPixels = 1 },
		"site b":       func(c *nodev1.NodeConfig) { vectorSite(c, "b").ImageConvert = &nodev1.ImageConvert{Webp: true} },
	} {
		c, _ := v0310Vector(t)
		change(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}

	Canonicalize(cfg)
	p, err := Build(cfg, Options{ClusterID: cfg.GetClusterId(), ExtraFeatures: []string{FeatureImageConvert}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sites) != 2 || p.Sites[0].ID != "a" || p.Sites[1].ID != "b" {
		t.Fatalf("plan sites %+v", p.Sites)
	}
	want := ImageConvert{WebP: true, AVIF: true, WebPQuality: 80, AVIFQuality: 50, JPEG: true, MinSize: 1024, MaxSize: 10485760, MaxPixels: 16000000}
	if got := p.Sites[0].ImageConvert; got == nil || *got != want {
		t.Fatalf("site a %+v", got)
	}
	if p.Sites[1].ImageConvert != nil {
		t.Fatalf("site b %+v", p.Sites[1].ImageConvert)
	}
	for _, f := range cfg.GetRequiredFeatures() {
		if !slices.Contains(SupportedFeatures, f) && f != FeatureImageConvert {
			t.Errorf("required feature %s is not supported", f)
		}
	}
	// A node without the converter keeps its last-known-good configuration.
	if _, err := Build(cfg, Options{ClusterID: cfg.GetClusterId()}); err == nil {
		t.Fatal("a node without the converter accepted image-convert-v1")
	}
}
