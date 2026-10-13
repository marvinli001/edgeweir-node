package imageconv

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"strings"
	"testing"

	"github.com/gen2brain/avif"
	"github.com/gen2brain/webp"
)

// testImage is a w x h picture with a gradient and noise (compressible
// like a photo) whose top-left pixel is red and top-right pixel blue.
func testImage(w, h int, alpha bool) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	seed := uint32(1)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			seed = seed*1664525 + 1013904223
			n := uint8(seed >> 28)
			a := uint8(255)
			if alpha && x < w/2 {
				a = 128
			}
			img.SetNRGBA(x, y, color.NRGBA{uint8(x*200/w) + n, uint8(y*200/h) + n, 120 + n, a})
		}
	}
	img.SetNRGBA(0, 0, color.NRGBA{255, 0, 0, 255})
	img.SetNRGBA(w-1, 0, color.NRGBA{0, 0, 255, 255})
	return img
}

func encodeJPEG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := jpeg.Encode(&b, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func encodePNG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// withSegment inserts a JPEG segment (marker, payload) after SOI.
func withSegment(jpg []byte, marker byte, payload []byte) []byte {
	seg := []byte{0xFF, marker, 0, 0}
	binary.BigEndian.PutUint16(seg[2:], uint16(len(payload)+2))
	out := append([]byte{}, jpg[:2]...)
	out = append(out, seg...)
	out = append(out, payload...)
	return append(out, jpg[2:]...)
}

// exifOrientation is an APP1 payload with a big- or little-endian TIFF
// whose IFD0 has Orientation o.
func exifOrientation(o uint16, little bool) []byte {
	var bo binary.AppendByteOrder = binary.BigEndian
	tiff := []byte("MM\x00*")
	if little {
		bo, tiff = binary.LittleEndian, []byte("II*\x00")
	}
	tiff = bo.AppendUint32(tiff, 8)
	tiff = bo.AppendUint16(tiff, 1)
	tiff = bo.AppendUint16(tiff, 0x0112)
	tiff = bo.AppendUint16(tiff, 3)
	tiff = bo.AppendUint32(tiff, 1)
	tiff = bo.AppendUint16(tiff, o)
	tiff = bo.AppendUint16(tiff, 0)
	tiff = bo.AppendUint32(tiff, 0)
	return append([]byte("Exif\x00\x00"), tiff...)
}

// iccProfile is a minimal ICC profile of color space space whose
// description (desc, v2) is name; mluc writes a v4 mluc description.
func iccProfile(space, name string, mluc bool) []byte {
	var tag []byte
	if mluc {
		tag = append([]byte("mluc"), 0, 0, 0, 0)
		tag = binary.BigEndian.AppendUint32(tag, 1)
		tag = binary.BigEndian.AppendUint32(tag, 12)
		tag = append(tag, 'e', 'n', 'U', 'S')
		tag = binary.BigEndian.AppendUint32(tag, uint32(len(name)*2))
		tag = binary.BigEndian.AppendUint32(tag, 28)
		for _, r := range name {
			tag = binary.BigEndian.AppendUint16(tag, uint16(r))
		}
	} else {
		tag = append([]byte("desc"), 0, 0, 0, 0)
		tag = binary.BigEndian.AppendUint32(tag, uint32(len(name)+1))
		tag = append(tag, name...)
		tag = append(tag, 0)
	}
	p := make([]byte, 128)
	copy(p[16:], space)
	copy(p[36:], "acsp")
	p = binary.BigEndian.AppendUint32(p, 1)
	p = append(p, "desc"...)
	p = binary.BigEndian.AppendUint32(p, 144)
	p = binary.BigEndian.AppendUint32(p, uint32(len(tag)))
	p = append(p, tag...)
	binary.BigEndian.PutUint32(p, uint32(len(p)))
	return p
}

// iccSegments splits a profile into APP2 payloads of at most n bytes.
func iccSegments(profile []byte, n int) [][]byte {
	var chunks [][]byte
	for len(profile) > 0 {
		k := min(n, len(profile))
		chunks = append(chunks, profile[:k])
		profile = profile[k:]
	}
	var out [][]byte
	for i, c := range chunks {
		out = append(out, append(append([]byte("ICC_PROFILE\x00"), byte(i+1), byte(len(chunks))), c...))
	}
	return out
}

// withChunk inserts a PNG chunk after IHDR.
func withChunk(p []byte, typ string, data []byte) []byte {
	c := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
	c = append(c, typ...)
	c = append(c, data...)
	c = binary.BigEndian.AppendUint32(c, crc32.ChecksumIEEE(append([]byte(typ), data...)))
	at := 8 + 25
	out := append([]byte{}, p[:at]...)
	out = append(out, c...)
	return append(out, p[at:]...)
}

func iccpChunk(t *testing.T, profile []byte) []byte {
	t.Helper()
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write(profile)
	zw.Close()
	return append([]byte("ICC profile\x00\x00"), z.Bytes()...)
}

func TestInspectJPEG(t *testing.T) {
	base := encodeJPEG(t, testImage(64, 48, false))
	info, err := Inspect(base, JPEG)
	if err != nil || info != (Info{Width: 64, Height: 48, Orientation: 1}) {
		t.Fatalf("plain JPEG: %+v %v", info, err)
	}
	for _, little := range []bool{false, true} {
		info, err = Inspect(withSegment(base, 0xE1, exifOrientation(6, little)), JPEG)
		if err != nil || info.Orientation != 6 {
			t.Fatalf("EXIF orientation (little %v): %+v %v", little, info, err)
		}
	}
	if info, _ := Inspect(withSegment(base, 0xE1, exifOrientation(9, false)), JPEG); info.Orientation != 1 {
		t.Fatalf("an orientation outside 1-8 counts as 1: %+v", info)
	}
	srgb := iccProfile("RGB ", "sRGB IEC61966-2.1", false)
	img := base
	for _, seg := range iccSegments(srgb, 40) {
		img = withSegment(img, 0xE2, seg)
	}
	// withSegment prepends: the chunks end up in reverse order, which
	// the sequence numbers put right.
	if _, err := Inspect(img, JPEG); err != nil {
		t.Fatalf("sRGB profile in several chunks: %v", err)
	}
	if _, err := Inspect(withSegment(base, 0xE2, iccSegments(iccProfile("RGB ", "sRGB v4", true), 1000)[0]), JPEG); err != nil {
		t.Fatalf("sRGB profile (mluc): %v", err)
	}
	for name, img := range map[string][]byte{
		"Display P3 profile": withSegment(base, 0xE2, iccSegments(iccProfile("RGB ", "Display P3", false), 1000)[0]),
		"CMYK profile":       withSegment(base, 0xE2, iccSegments(iccProfile("CMYK", "sRGB-ish", false), 1000)[0]),
		"missing ICC chunk":  withSegment(base, 0xE2, iccSegments(srgb, 40)[1]),
		"not a JPEG":         []byte("GIF89a"),
		"truncated":          base[:20],
	} {
		if _, err := Inspect(img, JPEG); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: %v, want ErrUnsupported", name, err)
		}
	}
	// Arithmetic coding (SOF9) and 12-bit precision.
	sof := bytes.Index(base, []byte{0xFF, 0xC0})
	arith := append([]byte{}, base...)
	arith[sof+1] = 0xC9
	twelve := append([]byte{}, base...)
	twelve[sof+4] = 12
	cmyk := append([]byte{}, base...)
	cmyk[sof+9] = 4
	for name, img := range map[string][]byte{"arithmetic": arith, "12-bit": twelve, "4 components": cmyk} {
		if _, err := Inspect(img, JPEG); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: %v, want ErrUnsupported", name, err)
		}
	}
	var prog bytes.Buffer
	if err := jpeg.Encode(&prog, image.NewGray(image.Rect(0, 0, 8, 8)), nil); err != nil {
		t.Fatal(err)
	}
	if info, err := Inspect(prog.Bytes(), JPEG); err != nil || info.Width != 8 {
		t.Fatalf("grayscale JPEG: %+v %v", info, err)
	}
}

func TestInspectPNG(t *testing.T) {
	base := encodePNG(t, testImage(40, 30, true))
	if info, err := Inspect(base, PNG); err != nil || info != (Info{Width: 40, Height: 30, Orientation: 1}) {
		t.Fatalf("plain PNG: %+v %v", info, err)
	}
	gamma := func(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
	srgbICCP := iccpChunk(t, iccProfile("RGB ", "sRGB built-in", false))
	ok := map[string][]byte{
		"sRGB chunk":           withChunk(base, "sRGB", []byte{0}),
		"gAMA 1/2.2":           withChunk(base, "gAMA", gamma(45455)),
		"gAMA 1.0 with sRGB":   withChunk(withChunk(base, "gAMA", gamma(100000)), "sRGB", []byte{0}),
		"sRGB ICC profile":     withChunk(base, "iCCP", iccpChunk(t, iccProfile("RGB ", "sRGB built-in", false))),
		"eXIf orientation":     withChunk(base, "eXIf", exifOrientation(8, true)[6:]),
		"unknown chunk before": withChunk(base, "tEXt", []byte("Comment\x00hi")),
	}
	for name, img := range ok {
		info, err := Inspect(img, PNG)
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if name == "eXIf orientation" && info.Orientation != 8 {
			t.Errorf("eXIf orientation: %d", info.Orientation)
		}
	}
	bad := map[string][]byte{
		"animated":       withChunk(base, "acTL", make([]byte, 8)),
		"gAMA 1.0":       withChunk(base, "gAMA", gamma(100000)),
		"P3 ICC profile": withChunk(base, "iCCP", iccpChunk(t, iccProfile("RGB ", "Display P3", false))),
		"broken iCCP":    withChunk(base, "iCCP", []byte("x\x00\x00garbage")),
		// One iCCP, no sRGB with it, no profile over 64 KiB: a bomb of many
		// chunks is refused before a second one is inflated.
		"two iCCP":        withChunk(withChunk(base, "iCCP", srgbICCP), "iCCP", srgbICCP),
		"iCCP after sRGB": withChunk(withChunk(base, "iCCP", srgbICCP), "sRGB", []byte{0}),
		"sRGB after iCCP": withChunk(withChunk(base, "sRGB", []byte{0}), "iCCP", srgbICCP),
		"large profile":   withChunk(base, "iCCP", iccpChunk(t, append(iccProfile("RGB ", "sRGB built-in", false), make([]byte, 64<<10)...))),
		"truncated":       base[:30],
		"not a PNG":       []byte("\xFF\xD8\xFF"),
		"IHDR not first":  append(append([]byte{}, pngSignature...), withChunk(base, "sRGB", []byte{0})[33:]...),
	}
	for name, img := range bad {
		if _, err := Inspect(img, PNG); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: %v, want ErrUnsupported", name, err)
		}
	}
}

func TestOrient(t *testing.T) {
	src := testImage(4, 2, false)
	red, blue := color.NRGBA{255, 0, 0, 255}, color.NRGBA{0, 0, 255, 255}
	// Where the top-left (red) and top-right (blue) pixels land.
	for o, want := range map[int][2]image.Point{
		1: {{0, 0}, {3, 0}}, 2: {{3, 0}, {0, 0}}, 3: {{3, 1}, {0, 1}}, 4: {{0, 1}, {3, 1}},
		5: {{0, 0}, {0, 3}}, 6: {{1, 0}, {1, 3}}, 7: {{1, 3}, {1, 0}}, 8: {{0, 3}, {0, 0}},
	} {
		got := Orient(src, o)
		size := got.Bounds().Size()
		if (o >= 5) != (size == image.Pt(2, 4)) || (o < 5 && size != image.Pt(4, 2)) {
			t.Fatalf("orientation %d: size %v", o, size)
		}
		if c := color.NRGBAModel.Convert(got.At(want[0].X, want[0].Y)); c != red {
			t.Errorf("orientation %d: red at %v is %v", o, want[0], c)
		}
		if c := color.NRGBAModel.Convert(got.At(want[1].X, want[1].Y)); c != blue {
			t.Errorf("orientation %d: blue at %v is %v", o, want[1], c)
		}
	}
}

func TestConvert(t *testing.T) {
	jpg := encodeJPEG(t, testImage(120, 80, false))
	pngData := encodePNG(t, testImage(60, 40, true))
	for _, c := range []struct {
		kind   Kind
		data   []byte
		format Format
		info   Info
		size   image.Point
	}{
		{JPEG, jpg, WebP, Info{120, 80, 1}, image.Pt(120, 80)},
		{JPEG, jpg, AVIF, Info{120, 80, 1}, image.Pt(120, 80)},
		{JPEG, jpg, WebP, Info{120, 80, 6}, image.Pt(80, 120)},
		{PNG, pngData, WebP, Info{60, 40, 1}, image.Pt(60, 40)},
		{PNG, pngData, AVIF, Info{60, 40, 1}, image.Pt(60, 40)},
	} {
		out, err := Convert(c.data, c.kind, c.format, 70, c.info, maxSize)
		if err != nil {
			t.Fatalf("%s -> %s: %v", c.kind, c.format, err)
		}
		// The bound is the largest output allowed: one byte less is
		// ErrUnsupported.
		if exact, err := Convert(c.data, c.kind, c.format, 70, c.info, int64(len(out))); err != nil || !bytes.Equal(exact, out) {
			t.Fatalf("%s -> %s within a bound of its size (%d): %v", c.kind, c.format, len(out), err)
		}
		if short, err := Convert(c.data, c.kind, c.format, 70, c.info, int64(len(out))-1); !errors.Is(err, ErrUnsupported) || short != nil {
			t.Fatalf("%s -> %s over its bound: %d bytes, %v, want ErrUnsupported", c.kind, c.format, len(short), err)
		}
		var cfg image.Config
		if c.format == WebP {
			if !bytes.HasPrefix(out, []byte("RIFF")) || string(out[8:12]) != "WEBP" {
				t.Fatalf("%s -> webp: not a WebP file", c.kind)
			}
			cfg, err = webp.DecodeConfig(bytes.NewReader(out))
		} else {
			if string(out[4:12]) != "ftypavif" {
				t.Fatalf("%s -> avif: not an AVIF file", c.kind)
			}
			cfg, err = avif.DecodeConfig(bytes.NewReader(out))
		}
		if err != nil || image.Pt(cfg.Width, cfg.Height) != c.size {
			t.Fatalf("%s -> %s (orientation %d): %+v %v, want %v", c.kind, c.format, c.info.Orientation, cfg, err, c.size)
		}
		if bytes.Contains(out, []byte("Exif")) {
			t.Fatalf("%s -> %s carries EXIF", c.kind, c.format)
		}
	}
	if _, err := Convert(jpg, JPEG, WebP, 70, Info{10, 10, 1}, maxSize); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("dimensions that differ from the headers: %v", err)
	}
	if _, err := Convert([]byte("garbage"), PNG, WebP, 70, Info{1, 1, 1}, maxSize); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("undecodable input: %v", err)
	}
}

// TestCheckVariant: the encoders' output passes, anything else of the
// wrong container, brand or length does not.
func TestCheckVariant(t *testing.T) {
	jpg := encodeJPEG(t, testImage(120, 80, false))
	pngData := encodePNG(t, testImage(60, 40, true))
	real := map[Format][][]byte{}
	for _, format := range []Format{WebP, AVIF} {
		for _, c := range []struct {
			kind Kind
			data []byte
			info Info
		}{{JPEG, jpg, Info{120, 80, 1}}, {PNG, pngData, Info{60, 40, 1}}} {
			out, err := Convert(c.data, c.kind, format, 70, c.info, maxSize)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkVariant(format, out); err != nil {
				t.Fatalf("%s -> %s: %v", c.kind, format, err)
			}
			real[format] = append(real[format], out)
		}
	}
	// libavif's still images: major brand avif, then avif, mif1 and miaf
	// among the compatible brands.
	avifOut := real[AVIF][0]
	ftyp := avifOut[:binary.BigEndian.Uint32(avifOut)]
	t.Logf("AVIF ftyp: major %q, compatible %q", ftyp[8:12], ftyp[16:])
	for _, brand := range []string{"avif", "mif1", "miaf"} {
		if !bytes.Contains(ftyp[16:], []byte(brand)) {
			t.Errorf("AVIF output without the compatible brand %s: %q", brand, ftyp)
		}
	}
	webpOut := real[WebP][0]
	withBrand := func(major, compatible string) []byte {
		b := append([]byte{}, avifOut...)
		copy(b[8:12], major)
		copy(b[16:20], compatible)
		return b
	}
	bad := map[string]struct {
		format Format
		out    []byte
	}{
		"empty":                  {WebP, nil},
		"AVIF for WebP":          {WebP, avifOut},
		"WebP for AVIF":          {AVIF, webpOut},
		"text":                   {WebP, []byte("<html><script>alert(1)</script></html>")},
		"WebP form type WEBX":    {WebP, append(append([]byte{}, webpOut[:8]...), append([]byte("WEBX"), webpOut[12:]...)...)},
		"WebP cut short":         {WebP, webpOut[:len(webpOut)-1]},
		"WebP with a trailer":    {WebP, append(append([]byte{}, webpOut...), 0)},
		"WebP header only":       {WebP, webpOut[:12]},
		"AVIF sequence (avis)":   {AVIF, withBrand("avis", "avis")},
		"avif only compatible":   {AVIF, withBrand("mif1", "avif")},
		"AVIF cut short":         {AVIF, avifOut[:len(avifOut)-1]},
		"AVIF with a trailer":    {AVIF, append(append([]byte{}, avifOut...), 0, 0, 0)},
		"AVIF with a size-0 box": {AVIF, append(append([]byte{}, avifOut...), "\x00\x00\x00\x00free"...)},
		"AVIF short ftyp":        {AVIF, append([]byte{0, 0, 0, 12}, avifOut[4:]...)},
		"AVIF ftyp past the end": {AVIF, append([]byte{0, 0, 0xff, 0xf0}, avifOut[4:]...)},
		"AVIF header only":       {AVIF, avifOut[:16]},
	}
	for name, c := range bad {
		if err := checkVariant(c.format, c.out); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestParseHeader(t *testing.T) {
	p, err := ParseHeader("avif;q=50;min=1024;max=10485760;px=16000000;src=jpeg,png;up=edgeweir_origin_verify")
	if err != nil {
		t.Fatal(err)
	}
	want := Params{Format: AVIF, Quality: 50, MinSize: 1024, MaxSize: 10485760, MaxPixels: 16000000, JPEG: true, PNG: true, Upstream: "edgeweir_origin_verify"}
	if p != want {
		t.Fatalf("%+v, want %+v", p, want)
	}
	if p, err := ParseHeader("webp;up=x;src=png;px=1;max=1;min=0;q=100"); err != nil || p.JPEG || !p.PNG || p.Format != WebP {
		t.Fatalf("fields in any order: %+v %v", p, err)
	}
	for _, bad := range []string{
		"", "gif;q=50;min=0;max=1;px=1;src=jpeg;up=x", "webp;q=0;min=0;max=1;px=1;src=jpeg;up=x",
		"webp;q=101;min=0;max=1;px=1;src=jpeg;up=x", "webp;q=50;min=2;max=1;px=1;src=jpeg;up=x",
		"webp;q=50;min=0;max=0;px=1;src=jpeg;up=x", "webp;q=50;min=0;max=67108865;px=1;src=jpeg;up=x",
		"webp;q=50;min=0;max=1;px=0;src=jpeg;up=x", "webp;q=50;min=0;max=1;px=50000001;src=jpeg;up=x",
		"webp;q=50;min=0;max=1;px=1;src=gif;up=x", "webp;q=50;min=0;max=1;px=1;src=jpeg;up=",
		"webp;q=50;q=50;max=1;px=1;src=jpeg;up=x", "webp;q=50;min=0;max=1;px=1;src=jpeg;up=x;extra=1",
		"webp;q=50;min=-1;max=1;px=1;src=jpeg;up=x", "webp;q=50;min=0;max=1;px=1;src=jpeg;zz=x",
	} {
		if _, err := ParseHeader(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestETags(t *testing.T) {
	for in, want := range map[string]string{
		`"abc"`: `"abc-webp"`, `W/"abc"`: `W/"abc-webp"`, `""`: `"-webp"`,
		`abc`: "", `"a"b"`: "", ``: "", `W/`: "",
	} {
		if got := variantETag(in, WebP); got != want {
			t.Errorf("variantETag(%q) = %q, want %q", in, got, want)
		}
	}
	if o, ok := originalETag(`W/"abc-avif"`, AVIF); !ok || o != `W/"abc"` {
		t.Errorf("originalETag weak: %q %v", o, ok)
	}
	if _, ok := originalETag(`"abc-avif"`, WebP); ok {
		t.Error("another format's suffix is kept")
	}
	if !strings.HasSuffix(transientTTLValue("3600"), "60") || transientTTLValue("0") != "0" || transientTTLValue("30") != "30" ||
		transientTTLValue("") != "60" || transientTTLValue("@1700000000") != "60" {
		t.Error("transientTTLValue")
	}
}
