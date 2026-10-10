package configir

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// validImageConvert is a site's conversion within every bound.
func validImageConvert() *nodev1.ImageConvert {
	return &nodev1.ImageConvert{Webp: true, Avif: true, WebpQuality: 80, AvifQuality: 50, Jpeg: true, Png: true,
		MinSize: 1024, MaxSize: 10 << 20, MaxPixels: 16_000_000}
}

var withConverter = Options{ExtraFeatures: []string{FeatureImageConvert}}

// TestImageConvertIsAnExtraFeature: image-convert-v1 depends on the node's
// --image-workers, not on the agent version.
func TestImageConvertIsAnExtraFeature(t *testing.T) {
	if slices.Contains(SupportedFeatures, FeatureImageConvert) {
		t.Fatal("image-convert-v1 is among SupportedFeatures")
	}
	cfg := g16Config(t, func(c *nodev1.NodeConfig, a *nodev1.Site) {
		a.ImageConvert = validImageConvert()
		c.RequiredFeatures = append(c.RequiredFeatures, FeatureImageConvert)
	})
	if _, err := Build(cfg, Options{}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), FeatureImageConvert) {
		t.Fatalf("without the converter: %v", err)
	}
	// Even when required_features forgets it: the edge would send image
	// requests to a socket nobody serves.
	cfg = g16Config(t, func(_ *nodev1.NodeConfig, a *nodev1.Site) { a.ImageConvert = validImageConvert() })
	if _, err := Build(cfg, Options{}); !errors.Is(err, ErrRejected) {
		t.Fatalf("without the converter, no requirement: %v", err)
	}
	p, err := Build(cfg, withConverter)
	if err != nil {
		t.Fatal(err)
	}
	want := ImageConvert{WebP: true, AVIF: true, WebPQuality: 80, AVIFQuality: 50, JPEG: true, PNG: true,
		MinSize: 1024, MaxSize: 10 << 20, MaxPixels: 16_000_000}
	if got := p.Sites[0].ImageConvert; got == nil || *got != want {
		t.Fatalf("plan %+v", got)
	}
	// The site table: image_convert on site a only.
	raw, _ := json.Marshal(p.Sites)
	var table []map[string]any
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	conv, ok := table[0]["image_convert"].(map[string]any)
	if !ok || conv["webp"] != true || conv["avif_quality"] != float64(50) || conv["max_pixels"] != float64(16_000_000) || conv["png"] != true {
		t.Fatalf("site a table %v", table[0]["image_convert"])
	}
	if _, ok := table[1]["image_convert"]; ok {
		t.Fatal("site b carries image_convert")
	}
}

func TestImageConvertBounds(t *testing.T) {
	ok := map[string]func(*nodev1.ImageConvert){
		"all":                func(*nodev1.ImageConvert) {},
		"webp only":          func(c *nodev1.ImageConvert) { c.Avif, c.AvifQuality = false, 0 },
		"avif only":          func(c *nodev1.ImageConvert) { c.Webp, c.WebpQuality = false, 0 },
		"png only":           func(c *nodev1.ImageConvert) { c.Jpeg = false },
		"no lower bound":     func(c *nodev1.ImageConvert) { c.MinSize = 0 },
		"min equals max":     func(c *nodev1.ImageConvert) { c.MinSize, c.MaxSize = 5, 5 },
		"largest":            func(c *nodev1.ImageConvert) { c.MaxSize, c.MaxPixels = MaxImageSize, MaxImagePixels },
		"qualities 1 to 100": func(c *nodev1.ImageConvert) { c.WebpQuality, c.AvifQuality = 1, 100 },
	}
	for name, change := range ok {
		conv := validImageConvert()
		change(conv)
		if _, err := Build(g16Config(t, func(_ *nodev1.NodeConfig, a *nodev1.Site) { a.ImageConvert = conv }), withConverter); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]func(*nodev1.ImageConvert){
		"no format":        func(c *nodev1.ImageConvert) { c.Webp, c.Avif = false, false },
		"no source type":   func(c *nodev1.ImageConvert) { c.Jpeg, c.Png = false, false },
		"max size 0":       func(c *nodev1.ImageConvert) { c.MaxSize = 0 },
		"max size above":   func(c *nodev1.ImageConvert) { c.MaxSize = MaxImageSize + 1 },
		"min above max":    func(c *nodev1.ImageConvert) { c.MinSize = c.MaxSize + 1 },
		"pixels 0":         func(c *nodev1.ImageConvert) { c.MaxPixels = 0 },
		"pixels above":     func(c *nodev1.ImageConvert) { c.MaxPixels = MaxImagePixels + 1 },
		"webp quality 0":   func(c *nodev1.ImageConvert) { c.WebpQuality = 0 },
		"avif quality 101": func(c *nodev1.ImageConvert) { c.AvifQuality = 101 },
	}
	for name, change := range bad {
		conv := validImageConvert()
		change(conv)
		if _, err := Build(g16Config(t, func(_ *nodev1.NodeConfig, a *nodev1.Site) { a.ImageConvert = conv }), withConverter); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: %v, want rejected", name, err)
		}
	}
	// A disabled site is checked too.
	_, err := Build(g16Config(t, func(c *nodev1.NodeConfig, _ *nodev1.Site) {
		b := vectorSite(c, "b")
		b.Enabled = false
		b.ImageConvert = &nodev1.ImageConvert{Webp: true, WebpQuality: 80}
	}), withConverter)
	if !errors.Is(err, ErrRejected) {
		t.Errorf("disabled site: %v, want rejected", err)
	}
}
