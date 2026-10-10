package imageconv

import (
	"bytes"
	"fmt"
	"image"
	"image/draw"
	"image/jpeg"
	"image/png"

	"github.com/gen2brain/avif"
	"github.com/gen2brain/webp"
)

// Encoder settings (ADR-0043): WebP lossy at method 4, AVIF at speed 8
// with 4:2:0 chroma; alpha planes at quality 100.
const (
	webpMethod   = 4
	avifSpeed    = 8
	alphaQuality = 100
)

// Convert decodes a JPEG or PNG image, turns it upright by its EXIF
// orientation and encodes it as format at quality. The output carries no
// metadata. Images that do not decode, or whose size differs from what
// inspection read, are ErrUnsupported.
func Convert(data []byte, kind Kind, format Format, quality int, info Info) ([]byte, error) {
	var img image.Image
	var err error
	switch kind {
	case JPEG:
		img, err = jpeg.Decode(bytes.NewReader(data))
	case PNG:
		img, err = png.Decode(bytes.NewReader(data))
	default:
		return nil, unsupported("source type")
	}
	if err != nil {
		return nil, unsupported("decode: " + err.Error())
	}
	if b := img.Bounds(); b.Dx() != info.Width || b.Dy() != info.Height {
		return nil, unsupported("dimensions differ from the headers")
	}
	img = Orient(img, info.Orientation)
	var out bytes.Buffer
	switch format {
	case WebP:
		err = webp.Encode(&out, img, webp.Options{Quality: quality, Method: webpMethod})
	case AVIF:
		err = avif.Encode(&out, img, avif.Options{Quality: quality, QualityAlpha: alphaQuality, Speed: avifSpeed,
			ChromaSubsampling: image.YCbCrSubsampleRatio420})
	default:
		return nil, fmt.Errorf("unknown format %q", format)
	}
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", format, err)
	}
	return out.Bytes(), nil
}

// Orient returns img turned upright for an EXIF orientation (2-8: mirror
// and / or rotate; anything else returns img unchanged).
func Orient(img image.Image, orientation int) image.Image {
	if orientation < 2 || orientation > 8 {
		return img
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	src := image.NewNRGBA(image.Rect(0, 0, w, h))
	draw.Draw(src, src.Rect, img, b.Min, draw.Src)
	dw, dh := w, h
	if orientation >= 5 {
		dw, dh = h, w
	}
	dst := image.NewNRGBA(image.Rect(0, 0, dw, dh))
	for y := 0; y < h; y++ {
		row := src.Pix[y*src.Stride:]
		for x := 0; x < w; x++ {
			var dx, dy int
			switch orientation {
			case 2:
				dx, dy = w-1-x, y
			case 3:
				dx, dy = w-1-x, h-1-y
			case 4:
				dx, dy = x, h-1-y
			case 5:
				dx, dy = y, x
			case 6:
				dx, dy = h-1-y, x
			case 7:
				dx, dy = h-1-y, w-1-x
			case 8:
				dx, dy = y, w-1-x
			}
			copy(dst.Pix[dy*dst.Stride+dx*4:dy*dst.Stride+dx*4+4], row[x*4:x*4+4])
		}
	}
	return dst
}
