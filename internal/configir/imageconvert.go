package configir

import (
	"fmt"
	"slices"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// FeatureImageConvert is WebP / AVIF conversion of cached JPEG and PNG
// responses (Site.image_convert, proto v0.31.0, ADR-0043) and the bytes it
// saves in MinuteStats.image_bytes_saved. Nodes announce it while their
// converter runs (--image-workers above 0), as an extra feature; the
// console requires it when a served site converts.
const FeatureImageConvert = "image-convert-v1"

// Bounds of ImageConvert.
const (
	MaxImageSize   uint64 = 64 << 20
	MaxImagePixels uint64 = 50_000_000
)

// ImageConvert is a site's WebP / AVIF conversion (site table field
// "image_convert"; lua/edgeweir/imageconv.lua). Qualities are 1-100 for
// the formats offered; MinSize..MaxSize bounds the original's length.
type ImageConvert struct {
	WebP        bool   `json:"webp,omitempty"`
	AVIF        bool   `json:"avif,omitempty"`
	WebPQuality uint32 `json:"webp_quality,omitempty"`
	AVIFQuality uint32 `json:"avif_quality,omitempty"`
	JPEG        bool   `json:"jpeg,omitempty"`
	PNG         bool   `json:"png,omitempty"`
	MinSize     uint64 `json:"min_size"`
	MaxSize     uint64 `json:"max_size"`
	MaxPixels   uint64 `json:"max_pixels"`
}

// buildImageConvert validates Site.image_convert (nil: off). A site that
// converts needs the node's converter (FeatureImageConvert among extra):
// the edge would otherwise send its image requests to a socket nobody
// serves, so such a configuration is rejected whatever its
// required_features say.
func buildImageConvert(s *nodev1.Site, extra []string) (*ImageConvert, error) {
	c := s.GetImageConvert()
	if c == nil {
		return nil, nil
	}
	if !slices.Contains(extra, FeatureImageConvert) {
		return nil, fmt.Errorf("%w: image conversion needs feature %s", ErrRejected, FeatureImageConvert)
	}
	out := &ImageConvert{
		WebP: c.GetWebp(), AVIF: c.GetAvif(),
		JPEG: c.GetJpeg(), PNG: c.GetPng(),
		MinSize: c.GetMinSize(), MaxSize: c.GetMaxSize(), MaxPixels: c.GetMaxPixels(),
	}
	switch {
	case !out.WebP && !out.AVIF:
		return nil, fmt.Errorf("%w: image conversion offers no format", ErrRejected)
	case !out.JPEG && !out.PNG:
		return nil, fmt.Errorf("%w: image conversion converts no source type", ErrRejected)
	case out.MaxSize == 0 || out.MaxSize > MaxImageSize:
		return nil, fmt.Errorf("%w: image conversion max_size out of range", ErrRejected)
	case out.MinSize > out.MaxSize:
		return nil, fmt.Errorf("%w: image conversion min_size above max_size", ErrRejected)
	case out.MaxPixels == 0 || out.MaxPixels > MaxImagePixels:
		return nil, fmt.Errorf("%w: image conversion max_pixels out of range", ErrRejected)
	}
	if out.WebP {
		if q := c.GetWebpQuality(); q >= 1 && q <= 100 {
			out.WebPQuality = q
		} else {
			return nil, fmt.Errorf("%w: WebP quality out of range", ErrRejected)
		}
	}
	if out.AVIF {
		if q := c.GetAvifQuality(); q >= 1 && q <= 100 {
			out.AVIFQuality = q
		} else {
			return nil, fmt.Errorf("%w: AVIF quality out of range", ErrRejected)
		}
	}
	return out, nil
}
