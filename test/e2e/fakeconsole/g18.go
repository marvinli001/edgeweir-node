package main

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

// The proto v0.31.0 sites (image-convert-v1, ADR-0043):
//
//	img.test   origin console:8082, everything cached 60 s; converts JPEG
//	              and PNG of 1 KiB to 10 MiB and up to 1,000,000 pixels to
//	              WebP (quality 80) and AVIF (quality 50)
//	webp.test  the same origin; WebP only, JPEG only
//
// The test origin's image paths: /pics/photo.jpg (640 x 480 JPEG),
// /pics/photo (the same without an extension), /pics/icon.png (200 x 150 PNG
// with transparency), /pics/huge.jpg (1200 x 1000 JPEG, over the pixel
// limit), /pics/tiny.jpg (under the size limit), /pics/app.js (a script);
// /pics/count tells how often the origin served /pics/photo.jpg.
func imageSite(id, domain string, conv *nodev1.ImageConvert) *nodev1.Site {
	s := site(id, domain, "console", 8082)
	s.ImageConvert = conv
	return s
}

func imageSites() []*nodev1.Site {
	return []*nodev1.Site{
		imageSite("site-img", "img.test", &nodev1.ImageConvert{Webp: true, Avif: true, WebpQuality: 80, AvifQuality: 50,
			Jpeg: true, Png: true, MinSize: 1024, MaxSize: 10 << 20, MaxPixels: 1_000_000}),
		imageSite("site-webp", "webp.test", &nodev1.ImageConvert{Webp: true, WebpQuality: 80,
			Jpeg: true, MinSize: 1024, MaxSize: 10 << 20, MaxPixels: 1_000_000}),
	}
}

// imagesModified is the test images' Last-Modified.
var imagesModified = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// photoServed counts the origin's answers for /pics/photo.jpg.
var photoServed atomic.Int32

// testPicture is a w x h picture with gradients and noise; alpha makes
// its left half translucent.
func testPicture(w, h int, alpha bool) image.Image {
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	seed := uint32(7)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			seed = seed*1664525 + 1013904223
			n := uint8(seed >> 28)
			a := uint8(255)
			if alpha && x < w/2 {
				a = 160
			}
			img.SetNRGBA(x, y, color.NRGBA{uint8(x*200/w) + n, uint8(y*200/h) + n, 140 + n, a})
		}
	}
	return img
}

func encodedJPEG(img image.Image) []byte {
	var b bytes.Buffer
	_ = jpeg.Encode(&b, img, &jpeg.Options{Quality: 90})
	return b.Bytes()
}

var (
	photoJPEG = encodedJPEG(testPicture(640, 480, false))
	hugeJPEG  = encodedJPEG(testPicture(1200, 1000, false))
	tinyJPEG  = encodedJPEG(testPicture(8, 8, false))
	iconPNG   = func() []byte {
		var b bytes.Buffer
		_ = png.Encode(&b, testPicture(200, 150, true))
		return b.Bytes()
	}()
)

// serveImages answers the test origin's image paths; false for any other.
func serveImages(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/pics/") {
		return false
	}
	h := w.Header()
	send := func(contentType string, body []byte) {
		h.Set("Content-Type", contentType)
		h.Set("ETag", fmt.Sprintf(`"img-%d"`, len(body)))
		http.ServeContent(w, r, "", imagesModified, bytes.NewReader(body))
	}
	switch r.URL.Path {
	case "/pics/photo.jpg":
		photoServed.Add(1)
		send("image/jpeg", photoJPEG)
	case "/pics/photo":
		send("image/jpeg", photoJPEG)
	case "/pics/icon.png":
		send("image/png", iconPNG)
	case "/pics/huge.jpg":
		send("image/jpeg", hugeJPEG)
	case "/pics/tiny.jpg":
		send("image/jpeg", tinyJPEG)
	case "/pics/app.js":
		send("text/javascript", []byte("console.log('e2e');\n"))
	case "/pics/count":
		h.Set("Cache-Control", "no-store")
		fmt.Fprintf(w, "%d\n", photoServed.Load())
	default:
		http.NotFound(w, r)
	}
	return true
}

// imageHelpers registers GET /g18/saved: the bytes WebP / AVIF responses
// saved per site, from the reported statistics.
func imageHelpers(mux *http.ServeMux, c *fakeconsole.Console) {
	mux.HandleFunc("GET /g18/saved", func(w http.ResponseWriter, _ *http.Request) {
		saved := map[string]uint64{}
		for _, m := range c.Stats() {
			saved[m.GetSiteId()] += m.GetImageBytesSaved()
		}
		fmt.Fprintf(w, "%d\n", saved["site-img"])
	})
}
