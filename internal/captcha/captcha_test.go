package captcha

import (
	"bytes"
	crand "crypto/rand"
	"image"
	"image/png"
	"os"
	"strings"
	"testing"
)

func TestFontCoversTheAlphabet(t *testing.T) {
	if len(glyphs) != len(Alphabet) {
		t.Fatalf("%d glyphs for %d characters", len(glyphs), len(Alphabet))
	}
	for i := 0; i < len(Alphabet); i++ {
		g, ok := glyphs[Alphabet[i]]
		if !ok {
			t.Fatalf("no glyph for %q", Alphabet[i])
		}
		dots := 0
		for _, row := range g {
			if len(row) != 5 || strings.Trim(row, "#.") != "" {
				t.Fatalf("glyph %q: bad row %q", Alphabet[i], row)
			}
			dots += strings.Count(row, "#")
		}
		if dots < 7 {
			t.Fatalf("glyph %q is nearly empty", Alphabet[i])
		}
	}
	for _, confusing := range "01ILOil" {
		if strings.ContainsRune(Alphabet, confusing) {
			t.Fatalf("alphabet contains %q", confusing)
		}
	}
}

func TestNewDrawsAValidPNG(t *testing.T) {
	img, err := New(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(img.Answer) != Length || strings.Trim(img.Answer, Alphabet) != "" {
		t.Fatalf("answer %q", img.Answer)
	}
	decoded, err := png.Decode(bytes.NewReader(img.PNG))
	if err != nil {
		t.Fatal(err)
	}
	if b := decoded.Bounds(); b.Dx() != Width || b.Dy() != Height {
		t.Fatalf("size %v", b)
	}
	if len(img.PNG) > 16<<10 {
		t.Fatalf("PNG of %d bytes", len(img.PNG))
	}
	// Every character cell has ink.
	p, ok := decoded.(*image.Paletted)
	if !ok {
		t.Fatalf("decoded as %T, want a paletted image", decoded)
	}
	for i := 0; i < Length; i++ {
		ink := 0
		for y := 0; y < Height; y++ {
			for x := i * Width / Length; x < (i+1)*Width/Length; x++ {
				if c := p.ColorIndexAt(x, y); c >= inkFirst && c < inkFirst+inkCount {
					ink++
				}
			}
		}
		if ink < 60 {
			t.Fatalf("character %d has %d ink pixels", i, ink)
		}
	}
	if os.Getenv("CAPTCHA_SAMPLE") != "" {
		_ = os.WriteFile(os.Getenv("CAPTCHA_SAMPLE"), img.PNG, 0o644)
		t.Logf("sample %s written", img.Answer)
	}
}

func TestDrawIsRandomized(t *testing.T) {
	x, err := Draw(nil, "K7PXQ")
	if err != nil {
		t.Fatal(err)
	}
	y, err := Draw(crand.Reader, "K7PXQ")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(x, y) {
		t.Fatal("the same answer drew the same image twice")
	}
	if _, err := Draw(nil, "K7PX"); err == nil {
		t.Fatal("short answer accepted")
	}
	if _, err := Draw(nil, "K7PX0"); err == nil {
		t.Fatal("character outside the alphabet accepted")
	}
}

func TestPoolHasDistinctAnswers(t *testing.T) {
	pool, err := Pool(nil, 256)
	if err != nil {
		t.Fatal(err)
	}
	if len(pool) != 256 {
		t.Fatalf("%d images", len(pool))
	}
	seen := map[string]bool{}
	used := map[rune]bool{}
	for _, img := range pool {
		if seen[img.Answer] {
			t.Fatalf("answer %s twice", img.Answer)
		}
		seen[img.Answer] = true
		for _, c := range img.Answer {
			used[c] = true
		}
	}
	if len(used) < len(Alphabet)-3 {
		t.Fatalf("answers use only %d characters", len(used))
	}
	// Collisions are drawn again, never returned.
	pool, err = Pool(&repeat{answers: []string{"AAAAA", "AAAAA", "BBBBB"}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if pool[0].Answer != "AAAAA" || pool[1].Answer != "BBBBB" {
		t.Fatalf("answers %s %s", pool[0].Answer, pool[1].Answer)
	}
}

func TestAnswerIsUniform(t *testing.T) {
	// Bytes at or above the largest multiple of the alphabet size are
	// skipped: 250 would otherwise favour the first characters.
	got, err := Answer(bytes.NewReader([]byte{250, 255, 0, 31, 30, 62, 247}))
	if err != nil {
		t.Fatal(err)
	}
	if got != "AA9A9" {
		t.Fatalf("answer %q", got)
	}
}

// repeat yields the given answers (then random bytes for the drawing).
type repeat struct {
	answers []string
	pending []byte
	seed    int
}

func (r *repeat) Read(p []byte) (int, error) {
	if len(p) == 1 && len(r.pending) == 0 && len(r.answers) > 0 {
		for _, c := range r.answers[0] {
			r.pending = append(r.pending, byte(strings.IndexRune(Alphabet, c)))
		}
		r.answers = r.answers[1:]
	}
	if len(p) == 1 && len(r.pending) > 0 {
		p[0], r.pending = r.pending[0], r.pending[1:]
		return 1, nil
	}
	for i := range p {
		r.seed++
		p[i] = byte(r.seed)
	}
	return len(p), nil
}
