package desktop

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"os"
	"regexp"
	"testing"
)

// The application icon is full bleed: the whole square is painted (the system rounds it), with the navy of the brand at the corners, and the mark
// beside the title of the window is made from it.
var navy = color.RGBA{0x17, 0x2B, 0x45, 0xFF}

func isNavy(c color.Color) bool {
	r, g, b, a := c.RGBA()
	return a == 0xFFFF && color.RGBA{uint8(r >> 8), uint8(g >> 8), uint8(b >> 8), 0xFF} == navy
}

func TestAppIconIsFullBleed(t *testing.T) {
	f, err := os.Open("../../cmd/icevault-desktop/app/icon-1024.png")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	b := img.Bounds()
	if b.Dx() != 1024 || b.Dy() != 1024 {
		t.Fatalf("%dx%d, want 1024x1024", b.Dx(), b.Dy())
	}
	for _, p := range []image.Point{{0, 0}, {1023, 0}, {0, 1023}, {1023, 1023}, {512, 4}, {4, 512}} {
		if !isNavy(img.At(p.X, p.Y)) {
			t.Errorf("the pixel %v is not the opaque navy: the icon must be painted to its edges", p)
		}
	}
	// nothing transparent anywhere, and the mark is there (the middle is not navy)
	for y := 0; y < 1024; y += 16 {
		for x := 0; x < 1024; x += 16 {
			if _, _, _, a := img.At(x, y).RGBA(); a != 0xFFFF {
				t.Fatalf("a transparent pixel at %d,%d", x, y)
			}
		}
	}
	if isNavy(img.At(512, 700)) {
		t.Error("no mark in the middle of the icon")
	}
}

func TestWindowMarkIsMadeFromTheIcon(t *testing.T) {
	css, err := os.ReadFile("../../cmd/icevault-desktop/frontend/appicon.css")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("base64,([A-Za-z0-9+/=]+)").FindSubmatch(css)
	if m == nil {
		t.Fatal("no inline image")
	}
	raw, err := base64.StdEncoding.DecodeString(string(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if b := img.Bounds(); b.Dx() != 64 || b.Dy() != 64 {
		t.Fatalf("%dx%d, want 64x64", b.Dx(), b.Dy())
	}
	if !isNavy(img.At(0, 0)) || !isNavy(img.At(63, 63)) {
		t.Error("the window mark does not have the navy corners of the icon")
	}
	if isNavy(img.At(32, 44)) {
		t.Error("the window mark has no crest: it is not made from the new icon")
	}
}
