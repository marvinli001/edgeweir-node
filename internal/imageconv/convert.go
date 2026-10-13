package imageconv

import (
	"bytes"
	"encoding/binary"
	"errors"
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
// metadata. Images that do not decode, whose size differs from what
// inspection read, or whose output would exceed maxOutput bytes are
// ErrUnsupported.
func Convert(data []byte, kind Kind, format Format, quality int, info Info, maxOutput int64) ([]byte, error) {
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
	// The encoders hand over their whole output in one write, which fails
	// past the bound.
	out := &boundedBuffer{max: maxOutput}
	switch format {
	case WebP:
		err = webp.Encode(out, img, webp.Options{Quality: quality, Method: webpMethod})
	case AVIF:
		err = avif.Encode(out, img, avif.Options{Quality: quality, QualityAlpha: alphaQuality, Speed: avifSpeed,
			ChromaSubsampling: image.YCbCrSubsampleRatio420})
	default:
		return nil, fmt.Errorf("unknown format %q", format)
	}
	if errors.Is(err, errOutputBound) {
		return nil, unsupported(fmt.Sprintf("%s output over %d bytes", format, maxOutput))
	}
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", format, err)
	}
	return out.Bytes(), nil
}

// errOutputBound fails a write past a boundedBuffer's bound.
var errOutputBound = errors.New("output over the bound")

// boundedBuffer holds at most max bytes. A write that would go past max
// writes nothing, fails with errOutputBound and calls over (once; the
// parent kills the child with it). It has no ReadFrom, unlike an embedded
// bytes.Buffer: io.Copy, and so os/exec, must go through Write.
type boundedBuffer struct {
	buf      bytes.Buffer
	max      int64
	over     func()
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if int64(b.buf.Len())+int64(len(p)) > b.max {
		if !b.exceeded && b.over != nil {
			b.over()
		}
		b.exceeded = true
		return 0, errOutputBound
	}
	return b.buf.Write(p)
}

// Bytes returns what was written.
func (b *boundedBuffer) Bytes() []byte { return b.buf.Bytes() }

// checkVariant reports whether out is a whole file of format by its
// container: a WebP file is one RIFF chunk of form type WEBP whose size is
// the file's; an AVIF file starts with an ftyp box of major brand avif
// (still images; avis would be a sequence) and is top-level boxes of
// explicit sizes up to its last byte, as libavif writes them. A child's
// output is cached only when it passes.
func checkVariant(format Format, out []byte) error {
	switch format {
	case WebP:
		if len(out) < 12 || string(out[0:4]) != "RIFF" || string(out[8:12]) != "WEBP" ||
			int64(binary.LittleEndian.Uint32(out[4:8])) != int64(len(out))-8 {
			return errors.New("not a WebP file")
		}
		return nil
	case AVIF:
		if len(out) < 16 || string(out[4:8]) != "ftyp" || string(out[8:12]) != "avif" {
			return errors.New("not an AVIF file")
		}
		if n := binary.BigEndian.Uint32(out[0:4]); n < 16 || n%4 != 0 {
			return errors.New("AVIF file with a malformed ftyp box")
		}
		// Box sizes: 32 bits, or 1 for a 64-bit size after the type (0, to
		// the end of the file, is refused: it would let anything trail).
		for rest := out; len(rest) > 0; {
			if len(rest) < 8 {
				return errors.New("AVIF file with a truncated box")
			}
			size, header := uint64(binary.BigEndian.Uint32(rest[0:4])), uint64(8)
			if size == 1 {
				if len(rest) < 16 {
					return errors.New("AVIF file with a truncated box")
				}
				size, header = binary.BigEndian.Uint64(rest[8:16]), 16
			}
			if size < header || size > uint64(len(rest)) {
				return errors.New("AVIF file with a truncated box")
			}
			rest = rest[size:]
		}
		return nil
	}
	return fmt.Errorf("unknown format %q", format)
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
