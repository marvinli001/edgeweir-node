// Package imageconv converts cached JPEG and PNG responses to WebP and
// AVIF (ADR-0043). The edge layer sends a request for a variant to the
// agent's image socket with X-Edgeweir-Image; Server passes it on to the
// origin layer it names and converts the answer in a child process
// (edgeweir-node imgconv), or answers with the original when it cannot.
package imageconv

import (
	"errors"
	"strconv"
	"strings"
)

// Header is the request header the edge layer sets on variant requests
// (lua/edgeweir/imageconv.lua).
const Header = "X-Edgeweir-Image"

// SavedHeader carries the bytes a variant saved against its original on
// converted responses; it is cached with them and hidden from clients
// (the edge layer counts it, MinuteStats.image_bytes_saved).
const SavedHeader = "X-Edgeweir-Image-Saved"

// Format is an output format.
type Format string

// Formats.
const (
	WebP Format = "webp"
	AVIF Format = "avif"
)

// MediaType returns the format's media type.
func (f Format) MediaType() string { return "image/" + string(f) }

// Kind is a source type.
type Kind string

// Source types.
const (
	JPEG Kind = "jpeg"
	PNG  Kind = "png"
)

// Limits bound the inputs of the edge's header (configir.ImageConvert).
const (
	maxSize   = 64 << 20
	maxPixels = 50_000_000
)

// Params are a variant request's parameters.
type Params struct {
	Format    Format
	Quality   int
	MinSize   int64
	MaxSize   int64
	MaxPixels int64
	JPEG, PNG bool
	// Upstream is the origin layer the request would have gone to
	// ($edgeweir_origin_layer).
	Upstream string
}

// Accepts reports whether the params convert kind.
func (p Params) Accepts(k Kind) bool {
	return (k == JPEG && p.JPEG) || (k == PNG && p.PNG)
}

var errHeader = errors.New("invalid " + Header)

// ParseHeader parses "<webp|avif>;q=<1-100>;min=<n>;max=<n>;px=<n>;
// src=<jpeg|png|jpeg,png>;up=<upstream>" (every field required, in any
// order after the format).
func ParseHeader(v string) (Params, error) {
	parts := strings.Split(v, ";")
	if len(parts) != 7 {
		return Params{}, errHeader
	}
	var p Params
	switch Format(parts[0]) {
	case WebP, AVIF:
		p.Format = Format(parts[0])
	default:
		return Params{}, errHeader
	}
	seen := map[string]bool{}
	for _, field := range parts[1:] {
		name, value, ok := strings.Cut(field, "=")
		if !ok || seen[name] || value == "" {
			return Params{}, errHeader
		}
		seen[name] = true
		switch name {
		case "q":
			n, err := strconv.Atoi(value)
			if err != nil || n < 1 || n > 100 {
				return Params{}, errHeader
			}
			p.Quality = n
		case "min", "max", "px":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < 0 {
				return Params{}, errHeader
			}
			switch name {
			case "min":
				p.MinSize = n
			case "max":
				p.MaxSize = n
			default:
				p.MaxPixels = n
			}
		case "src":
			for _, k := range strings.Split(value, ",") {
				switch Kind(k) {
				case JPEG:
					p.JPEG = true
				case PNG:
					p.PNG = true
				default:
					return Params{}, errHeader
				}
			}
		case "up":
			p.Upstream = value
		default:
			return Params{}, errHeader
		}
	}
	if p.MaxSize < 1 || p.MaxSize > maxSize || p.MinSize > p.MaxSize || p.MaxPixels < 1 || p.MaxPixels > maxPixels {
		return Params{}, errHeader
	}
	return p, nil
}
