package staticembed

import (
	"bytes"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Bulma ships @media (prefers-color-scheme: dark), but defines .theme-light
// afterwards at the same specificity, so a page that pins the class can never
// reach the dark palette whatever the viewer's system is set to. The class was
// on every page here, which made the framework's dark theme unreachable in
// every deployment (SUNET/vc#930).
func TestNoPagePinsTheLightTheme(t *testing.T) {
	pages, err := fs.Glob(FS, "*.html")
	if err != nil {
		t.Fatalf("glob embedded pages: %v", err)
	}
	if len(pages) == 0 {
		t.Fatal("no embedded pages found, so this guard proves nothing")
	}

	for _, name := range pages {
		body, err := fs.ReadFile(FS, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if bytes.Contains(body, []byte(`class="theme-light"`)) {
			t.Errorf("%s pins the light theme, so it can never follow the viewer's system setting", name)
		}
	}
}

// An outlined button paints its text and border in its colour modifier's
// lightness and leaves the background transparent, so the modifier has to
// contrast with whichever scheme the page is rendered in. Bulma redefines
// --bulma-scheme-main-l per scheme (100% light, 9% dark) but redefines no
// palette lightness at all, so a modifier pinned near either end collides with
// one of the two backgrounds: black is 4% and vanished into the dark page this
// repository's pages can now render, white is 100% and vanishes into the light
// one, and light (90%) and dark (20%) are each within about ten points of a
// background. The mid-range modifiers - danger and info at 70%, link 63%,
// success and warning 53%, primary 41% - are at least thirty points clear of
// both and are fine outlined.
func TestNoOutlinedButtonUsesAnExtremeLightness(t *testing.T) {
	extremes := []string{"is-black", "is-white", "is-light", "is-dark"}

	pages, err := fs.Glob(FS, "*.html")
	if err != nil {
		t.Fatalf("glob embedded pages: %v", err)
	}
	if len(pages) == 0 {
		t.Fatal("no embedded pages found, so this guard proves nothing")
	}

	classAttr := regexp.MustCompile(`class="([^"]*)"`)
	for _, name := range pages {
		body, err := fs.ReadFile(FS, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}

		for _, match := range classAttr.FindAllStringSubmatch(string(body), -1) {
			classes := strings.Fields(match[1])
			if !slices.Contains(classes, "is-outlined") {
				continue
			}
			for _, extreme := range extremes {
				if slices.Contains(classes, extreme) {
					t.Errorf("%s: %q outlines in a lightness that collides with one scheme's background", name, match[1])
				}
			}
		}
	}
}
