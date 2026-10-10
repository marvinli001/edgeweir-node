package imageconv

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

// ErrUnsupported marks images that are never converted: the original is
// served (and cached) as it is.
var ErrUnsupported = errors.New("image not convertible")

// Info is what inspection learns from an image's headers.
type Info struct {
	Width, Height int
	// Orientation is the EXIF orientation (1-8; 1 when absent): the child
	// turns the pixels so that the variant, which carries no EXIF, looks
	// like the original does in browsers.
	Orientation int
}

// Pixels returns the image's pixel count.
func (i Info) Pixels() int64 { return int64(i.Width) * int64(i.Height) }

// Inspect reads the headers of a JPEG or PNG image without decoding it and
// rejects (ErrUnsupported) what a conversion could not reproduce: other
// color spaces than sRGB (an ICC profile that is not sRGB, CMYK, a PNG
// gamma other than 1/2.2), animation (APNG), and JPEG flavours Go's
// decoder lacks (arithmetic coding, other precisions than 8 bits).
func Inspect(data []byte, kind Kind) (Info, error) {
	switch kind {
	case JPEG:
		return inspectJPEG(data)
	case PNG:
		return inspectPNG(data)
	}
	return Info{}, ErrUnsupported
}

// unsupported wraps ErrUnsupported with the reason (for the log).
func unsupported(reason string) error { return fmt.Errorf("%w: %s", ErrUnsupported, reason) }

func inspectJPEG(d []byte) (Info, error) {
	if len(d) < 4 || d[0] != 0xFF || d[1] != 0xD8 {
		return Info{}, unsupported("not a JPEG")
	}
	info := Info{Orientation: 1}
	icc := map[byte][]byte{}
	iccCount := byte(0)
	sof := false
	i := 2
	for i < len(d) {
		if d[i] != 0xFF {
			return Info{}, unsupported("garbage between segments")
		}
		for i < len(d) && d[i] == 0xFF {
			i++
		}
		if i >= len(d) {
			break
		}
		m := d[i]
		i++
		if m == 0x01 || (m >= 0xD0 && m <= 0xD7) {
			continue
		}
		if m == 0xD9 || m == 0xDA {
			break
		}
		if i+2 > len(d) {
			return Info{}, unsupported("truncated segment")
		}
		n := int(binary.BigEndian.Uint16(d[i:]))
		if n < 2 || i+n > len(d) {
			return Info{}, unsupported("truncated segment")
		}
		seg := d[i+2 : i+n]
		i += n
		switch {
		case m == 0xE1 && bytes.HasPrefix(seg, []byte("Exif\x00\x00")):
			if o := tiffOrientation(seg[6:]); o >= 1 && o <= 8 {
				info.Orientation = o
			}
		case m == 0xE2 && bytes.HasPrefix(seg, []byte("ICC_PROFILE\x00")) && len(seg) >= 14:
			seq, count := seg[12], seg[13]
			if seq == 0 || count == 0 || seq > count || (iccCount != 0 && count != iccCount) || icc[seq] != nil {
				return Info{}, unsupported("malformed ICC chunks")
			}
			iccCount = count
			icc[seq] = seg[14:]
		case m >= 0xC0 && m <= 0xCF && m != 0xC4 && m != 0xC8 && m != 0xCC:
			// Baseline, extended and progressive Huffman only.
			if m != 0xC0 && m != 0xC1 && m != 0xC2 {
				return Info{}, unsupported("JPEG process")
			}
			if len(seg) < 6 || seg[0] != 8 {
				return Info{}, unsupported("JPEG precision")
			}
			info.Height = int(binary.BigEndian.Uint16(seg[1:]))
			info.Width = int(binary.BigEndian.Uint16(seg[3:]))
			if c := seg[5]; c != 1 && c != 3 {
				return Info{}, unsupported("JPEG components")
			}
			sof = true
		}
	}
	if !sof || info.Width == 0 || info.Height == 0 {
		return Info{}, unsupported("no frame")
	}
	if iccCount > 0 {
		var profile []byte
		for s := byte(1); s <= iccCount; s++ {
			if icc[s] == nil {
				return Info{}, unsupported("missing ICC chunk")
			}
			profile = append(profile, icc[s]...)
		}
		if !isSRGB(profile) {
			return Info{}, unsupported("ICC profile")
		}
	}
	return info, nil
}

var pngSignature = []byte("\x89PNG\r\n\x1a\n")

func inspectPNG(d []byte) (Info, error) {
	if !bytes.HasPrefix(d, pngSignature) {
		return Info{}, unsupported("not a PNG")
	}
	info := Info{Orientation: 1}
	srgb, gamma := false, uint32(0)
	i := len(pngSignature)
	first := true
	for {
		if i+8 > len(d) {
			return Info{}, unsupported("truncated chunk")
		}
		n := int(binary.BigEndian.Uint32(d[i:]))
		typ := string(d[i+4 : i+8])
		if n < 0 || n > len(d)-i-12 {
			return Info{}, unsupported("truncated chunk")
		}
		data := d[i+8 : i+8+n]
		i += 12 + n
		if first != (typ == "IHDR") {
			return Info{}, unsupported("IHDR first")
		}
		first = false
		switch typ {
		case "IHDR":
			if n != 13 {
				return Info{}, unsupported("IHDR")
			}
			info.Width = int(binary.BigEndian.Uint32(data))
			info.Height = int(binary.BigEndian.Uint32(data[4:]))
		case "acTL":
			return Info{}, unsupported("animated PNG")
		case "sRGB":
			srgb = true
		case "gAMA":
			if n == 4 {
				gamma = binary.BigEndian.Uint32(data)
			}
		case "iCCP":
			name, rest, ok := bytes.Cut(data, []byte{0})
			if !ok || len(name) == 0 || len(rest) < 1 || rest[0] != 0 {
				return Info{}, unsupported("iCCP")
			}
			zr, err := zlib.NewReader(bytes.NewReader(rest[1:]))
			if err != nil {
				return Info{}, unsupported("iCCP")
			}
			profile, err := io.ReadAll(io.LimitReader(zr, 4<<20))
			if err != nil || !isSRGB(profile) {
				return Info{}, unsupported("ICC profile")
			}
			srgb = true
		case "eXIf":
			if o := tiffOrientation(data); o >= 1 && o <= 8 {
				info.Orientation = o
			}
		case "IDAT", "IEND":
			if info.Width <= 0 || info.Height <= 0 || info.Width > 1<<24 || info.Height > 1<<24 {
				return Info{}, unsupported("dimensions")
			}
			// gAMA without sRGB: browsers apply it; only 1/2.2 (sRGB's
			// approximation, 45455) looks the same without it.
			if !srgb && gamma != 0 && (gamma < 45000 || gamma > 45910) {
				return Info{}, unsupported("gamma")
			}
			return info, nil
		}
	}
}

// tiffOrientation returns the Orientation (tag 0x0112) of a TIFF
// structure's first IFD, or 0.
func tiffOrientation(t []byte) int {
	if len(t) < 8 {
		return 0
	}
	var bo binary.ByteOrder
	switch string(t[:4]) {
	case "II*\x00":
		bo = binary.LittleEndian
	case "MM\x00*":
		bo = binary.BigEndian
	default:
		return 0
	}
	off := int64(bo.Uint32(t[4:]))
	if off < 8 || off+2 > int64(len(t)) {
		return 0
	}
	count := int64(bo.Uint16(t[off:]))
	for k := int64(0); k < count; k++ {
		e := off + 2 + k*12
		if e+12 > int64(len(t)) {
			return 0
		}
		if bo.Uint16(t[e:]) == 0x0112 && bo.Uint16(t[e+2:]) == 3 {
			return int(bo.Uint16(t[e+8:]))
		}
	}
	return 0
}

// isSRGB reports whether an ICC profile describes sRGB: an RGB profile
// whose description (desc, ICC v2, or mluc, v4) names sRGB.
func isSRGB(p []byte) bool {
	if len(p) < 132 || string(p[16:20]) != "RGB " {
		return false
	}
	count := int64(binary.BigEndian.Uint32(p[128:]))
	for k := int64(0); k < count && k < 256; k++ {
		e := 132 + k*12
		if e+12 > int64(len(p)) {
			return false
		}
		if string(p[e:e+4]) != "desc" {
			continue
		}
		off, size := int64(binary.BigEndian.Uint32(p[e+4:])), int64(binary.BigEndian.Uint32(p[e+8:]))
		if off < 0 || size < 12 || off+size > int64(len(p)) {
			return false
		}
		return strings.Contains(strings.ToLower(description(p[off:off+size])), "srgb")
	}
	return false
}

// description returns the text of a desc or mluc tag.
func description(t []byte) string {
	switch string(t[:4]) {
	case "desc":
		n := int64(binary.BigEndian.Uint32(t[8:]))
		if n < 1 || 12+n > int64(len(t)) {
			return ""
		}
		return string(bytes.TrimRight(t[12:12+n], "\x00"))
	case "mluc":
		if len(t) < 28 || binary.BigEndian.Uint32(t[8:]) < 1 {
			return ""
		}
		n, off := int64(binary.BigEndian.Uint32(t[20:])), int64(binary.BigEndian.Uint32(t[24:]))
		if n%2 != 0 || off+n > int64(len(t)) {
			return ""
		}
		u := make([]uint16, n/2)
		for k := range u {
			u[k] = binary.BigEndian.Uint16(t[off+int64(k)*2:])
		}
		return string(utf16.Decode(u))
	}
	return ""
}
