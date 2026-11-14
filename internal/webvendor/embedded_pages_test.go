package webvendor

import (
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"

	apigwembed "github.com/SUNET/vc/internal/apigw/staticembed"
	verifierembed "github.com/SUNET/vc/internal/verifier/staticembed"

	"github.com/stretchr/testify/require"
)

// pageSets is every embedded browser page this repository serves. The guards
// below hold for all of them, which is why they live beside the vendored
// assets both services share rather than once per staticembed package: the
// same two tests written twice are two tests to keep in step, and are counted
// as duplicated source by static analysis - the reason this package exists at
// all, per its own doc comment.
func pageSets() map[string]fs.FS {
	return map[string]fs.FS{
		"verifier": verifierembed.FS,
		"apigw":    apigwembed.FS,
	}
}

// eachPage calls check for every embedded HTML page in every set, failing the
// test rather than skipping when a set turns out to have no pages - a guard
// over an empty list proves nothing.
func eachPage(t *testing.T, check func(t *testing.T, service, name, body string)) {
	t.Helper()

	for service, assets := range pageSets() {
		pages, err := fs.Glob(assets, "*.html")
		require.NoErrorf(t, err, "glob %s pages", service)
		require.NotEmptyf(t, pages, "%s has no embedded pages, so this guard proves nothing", service)

		for _, name := range pages {
			body, err := fs.ReadFile(assets, name)
			require.NoErrorf(t, err, "read %s/%s", service, name)
			check(t, service, name, string(body))
		}
	}
}

// Bulma ships @media (prefers-color-scheme: dark), but defines .theme-light
// afterwards at the same specificity, so a page that pins the class can never
// reach the dark palette whatever the viewer's system is set to. The class was
// on every Bulma page here, which made the framework's dark theme unreachable
// in every deployment, and on consent.html - a Tailwind page - where it did
// nothing at all (SUNET/vc#930).
func TestNoPagePinsTheLightTheme(t *testing.T) {
	eachPage(t, func(t *testing.T, service, name, body string) {
		if strings.Contains(body, `class="theme-light"`) {
			t.Errorf("%s/%s pins the light theme, so it can never follow the viewer's system setting", service, name)
		}
	})
}

// An outlined button paints its text and border in its colour modifier's
// lightness and leaves the background transparent, so the modifier has to
// contrast with whichever scheme the page is rendered in. Bulma redefines
// --bulma-scheme-main-l per scheme (100% light, 9% dark) but redefines no
// palette lightness at all, so a modifier pinned near either end collides with
// one of the two backgrounds: black is 4% and vanished into the dark page
// these pages can now render, white is 100% and vanishes into the light one,
// and light (90%) and dark (20%) are each within about ten points of a
// background. The mid-range modifiers - danger and info at 70%, link 63%,
// success and warning 53%, primary 41% - are at least thirty points clear of
// both and are fine outlined.
func TestNoOutlinedButtonUsesAnExtremeLightness(t *testing.T) {
	extremes := []string{"is-black", "is-white", "is-light", "is-dark"}
	classAttr := regexp.MustCompile(`class="([^"]*)"`)

	eachPage(t, func(t *testing.T, service, name, body string) {
		for _, match := range classAttr.FindAllStringSubmatch(body, -1) {
			classes := strings.Fields(match[1])
			if !slices.Contains(classes, "is-outlined") {
				continue
			}
			for _, extreme := range extremes {
				if slices.Contains(classes, extreme) {
					t.Errorf("%s/%s: %q outlines in a lightness that collides with one scheme's background", service, name, match[1])
				}
			}
		}
	})
}
