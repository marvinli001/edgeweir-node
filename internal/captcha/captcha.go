// Package captcha draws the image captchas of the captcha challenge with
// the standard library only: a built-in 5x7 dot-matrix font, randomly
// placed, scaled, rotated and sheared characters on a wavy baseline, with
// noise lines and dots, encoded as a small paletted PNG.
//
// The agent generates a pool every few minutes and hands it to the data
// plane (PUT /v1/challenge/captchas); the answers never leave the node.
package captcha

import (
	"bytes"
	crand "crypto/rand"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"math/rand/v2"
)

// Alphabet leaves out characters that are easy to confuse (0/O, 1/I/L).
const Alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

const (
	// Length is the number of characters of an answer.
	Length = 5
	// Width and Height are the image size in pixels.
	Width  = 160
	Height = 60
)

// Image is one captcha: its answer and the PNG.
type Image struct {
	Answer string
	PNG    []byte
}

// glyphs is the 5x7 dot-matrix font of the alphabet.
var glyphs = map[byte][7]string{
	'A': {".###.", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"},
	'B': {"####.", "#...#", "#...#", "####.", "#...#", "#...#", "####."},
	'C': {".###.", "#...#", "#....", "#....", "#....", "#...#", ".###."},
	'D': {"####.", "#...#", "#...#", "#...#", "#...#", "#...#", "####."},
	'E': {"#####", "#....", "#....", "####.", "#....", "#....", "#####"},
	'F': {"#####", "#....", "#....", "####.", "#....", "#....", "#...."},
	'G': {".###.", "#...#", "#....", "#.###", "#...#", "#...#", ".####"},
	'H': {"#...#", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"},
	'J': {"..###", "...#.", "...#.", "...#.", "...#.", "#..#.", ".##.."},
	'K': {"#...#", "#..#.", "#.#..", "##...", "#.#..", "#..#.", "#...#"},
	'M': {"#...#", "##.##", "#.#.#", "#.#.#", "#...#", "#...#", "#...#"},
	'N': {"#...#", "#...#", "##..#", "#.#.#", "#..##", "#...#", "#...#"},
	'P': {"####.", "#...#", "#...#", "####.", "#....", "#....", "#...."},
	'Q': {".###.", "#...#", "#...#", "#...#", "#.#.#", "#..#.", ".##.#"},
	'R': {"####.", "#...#", "#...#", "####.", "#.#..", "#..#.", "#...#"},
	'S': {".####", "#....", "#....", ".###.", "....#", "....#", "####."},
	'T': {"#####", "..#..", "..#..", "..#..", "..#..", "..#..", "..#.."},
	'U': {"#...#", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."},
	'V': {"#...#", "#...#", "#...#", "#...#", "#...#", ".#.#.", "..#.."},
	'W': {"#...#", "#...#", "#...#", "#.#.#", "#.#.#", "#.#.#", ".#.#."},
	'X': {"#...#", "#...#", ".#.#.", "..#..", ".#.#.", "#...#", "#...#"},
	'Y': {"#...#", "#...#", ".#.#.", "..#..", "..#..", "..#..", "..#.."},
	'Z': {"#####", "....#", "...#.", "..#..", ".#...", "#....", "#####"},
	'2': {".###.", "#...#", "....#", "...#.", "..#..", ".#...", "#####"},
	'3': {"#####", "...#.", "..#..", "...#.", "....#", "#...#", ".###."},
	'4': {"...#.", "..##.", ".#.#.", "#..#.", "#####", "...#.", "...#."},
	'5': {"#####", "#....", "####.", "....#", "....#", "#...#", ".###."},
	'6': {"..##.", ".#...", "#....", "####.", "#...#", "#...#", ".###."},
	'7': {"#####", "....#", "...#.", "..#..", ".#...", ".#...", ".#..."},
	'8': {".###.", "#...#", "#...#", ".###.", "#...#", "#...#", ".###."},
	'9': {".###.", "#...#", "#...#", ".####", "....#", "...#.", ".##.."},
}

// Palette: background, four ink colours, two noise colours.
var palette = color.Palette{
	color.RGBA{0xf6, 0xf7, 0xf9, 0xff},
	color.RGBA{0x1f, 0x2a, 0x44, 0xff},
	color.RGBA{0x3b, 0x2f, 0x5c, 0xff},
	color.RGBA{0x24, 0x4b, 0x3a, 0xff},
	color.RGBA{0x5a, 0x2a, 0x2a, 0xff},
	color.RGBA{0x8a, 0x94, 0xa6, 0xff},
	color.RGBA{0xb4, 0xbb, 0xc6, 0xff},
}

const (
	inkFirst   = 1
	inkCount   = 4
	noiseFirst = 5
	noiseCount = 2
)

// index returns a uniform random index below n (n <= 256) read from r.
func index(r io.Reader, n int) (int, error) {
	limit := 256 - 256%n
	var b [1]byte
	for {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, err
		}
		if int(b[0]) < limit {
			return int(b[0]) % n, nil
		}
	}
}

// Answer returns a random answer read from r.
func Answer(r io.Reader) (string, error) {
	out := make([]byte, Length)
	for i := range out {
		k, err := index(r, len(Alphabet))
		if err != nil {
			return "", err
		}
		out[i] = Alphabet[k]
	}
	return string(out), nil
}

// New draws a captcha for a random answer; r supplies the randomness
// (crypto/rand.Reader when nil).
func New(r io.Reader) (Image, error) {
	if r == nil {
		r = crand.Reader
	}
	answer, err := Answer(r)
	if err != nil {
		return Image{}, err
	}
	b, err := Draw(r, answer)
	if err != nil {
		return Image{}, err
	}
	return Image{Answer: answer, PNG: b}, nil
}

// Pool draws n captchas with distinct answers.
func Pool(r io.Reader, n int) ([]Image, error) {
	if r == nil {
		r = crand.Reader
	}
	out := make([]Image, 0, n)
	seen := make(map[string]bool, n)
	for len(out) < n {
		img, err := New(r)
		if err != nil {
			return nil, err
		}
		if seen[img.Answer] {
			continue
		}
		seen[img.Answer] = true
		out = append(out, img)
	}
	return out, nil
}

// Draw renders answer (characters of Alphabet) as a PNG; the geometry
// comes from a ChaCha8 stream seeded from r (crypto/rand.Reader when nil).
func Draw(r io.Reader, answer string) ([]byte, error) {
	if r == nil {
		r = crand.Reader
	}
	if len(answer) != Length {
		return nil, fmt.Errorf("answer must have %d characters", Length)
	}
	var seed [32]byte
	if _, err := io.ReadFull(r, seed[:]); err != nil {
		return nil, err
	}
	rng := rand.New(rand.NewChaCha8(seed))
	between := func(lo, hi float64) float64 { return lo + rng.Float64()*(hi-lo) }

	img := image.NewPaletted(image.Rect(0, 0, Width, Height), palette)
	// Light speckle under the characters.
	for range 180 {
		img.SetColorIndex(rng.IntN(Width), rng.IntN(Height), uint8(noiseFirst+1))
	}
	// A wavy baseline shared by the characters.
	amp, period, phase := between(2, 5), between(28, 60), between(0, 2*math.Pi)
	cell := float64(Width) / Length
	for i := 0; i < Length; i++ {
		g, ok := glyphs[answer[i]]
		if !ok {
			return nil, errors.New("character outside the captcha alphabet")
		}
		ink := uint8(inkFirst + rng.IntN(inkCount))
		cx := cell*(float64(i)+0.5) + between(-3, 3)
		cy := float64(Height)/2 + between(-5, 5)
		sx, sy := between(3.6, 4.5), between(3.6, 4.4)
		angle, shear := between(-0.35, 0.35), between(-0.3, 0.3)
		cos, sin := math.Cos(angle), math.Sin(angle)
		for y := 0; y < Height; y++ {
			for x := int(cx - cell); x <= int(cx+cell); x++ {
				if x < 0 || x >= Width {
					continue
				}
				dx := float64(x) - cx
				dy := float64(y) - cy - amp*math.Sin(float64(x)/period*2*math.Pi+phase)
				u := dx*cos + dy*sin
				v := -dx*sin + dy*cos
				u -= shear * v
				gx, gy := u/sx+2.5, v/sy+3.5
				if gx < 0 || gy < 0 || gx >= 5 || gy >= 7 {
					continue
				}
				if g[int(gy)][int(gx)] == '#' {
					img.SetColorIndex(x, y, ink)
				}
			}
		}
	}
	// Noise lines across the characters, then dots.
	for range 3 + rng.IntN(3) {
		c := uint8(noiseFirst + rng.IntN(noiseCount))
		if rng.IntN(2) == 0 {
			c = uint8(inkFirst + rng.IntN(inkCount))
		}
		line(img, rng.IntN(Width/4), rng.IntN(Height), Width-1-rng.IntN(Width/4), rng.IntN(Height), c, 1+rng.IntN(2))
	}
	for range 120 {
		img.SetColorIndex(rng.IntN(Width), rng.IntN(Height), uint8(inkFirst+rng.IntN(inkCount)))
	}
	var buf bytes.Buffer
	if err := (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// line draws a line of width w (Bresenham).
func line(img *image.Paletted, x0, y0, x1, y1 int, c uint8, w int) {
	dx, dy := abs(x1-x0), -abs(y1-y0)
	sx, sy := sign(x1-x0), sign(y1-y0)
	e := dx + dy
	for {
		for k := 0; k < w; k++ {
			img.SetColorIndex(x0, y0+k, c)
		}
		if x0 == x1 && y0 == y1 {
			return
		}
		e2 := 2 * e
		if e2 >= dy {
			e += dy
			x0 += sx
		}
		if e2 <= dx {
			e += dx
			y0 += sy
		}
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

func sign(v int) int {
	switch {
	case v < 0:
		return -1
	case v > 0:
		return 1
	}
	return 0
}
