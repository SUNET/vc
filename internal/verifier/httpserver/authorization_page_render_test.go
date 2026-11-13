package httpserver

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// renderPage executes one embedded template with the view helpers the real
// server registers, so a test sees exactly the bytes a browser would.
func renderPage(t *testing.T, name string, data any) string {
	t.Helper()

	var buf bytes.Buffer
	require.NoError(t, htmlTemplates().ExecuteTemplate(&buf, name, data))

	return buf.String()
}

// The theme block used to redefine --primary-color after the configured value,
// two :root rules of equal specificity in one stylesheet, so "blue" and
// "purple" discarded whatever primary_color an operator had set. The resolved
// pair now reaches the template already decided, and the theme block must not
// put a second definition of either variable after it.
func TestAuthorizationPageRendersOnlyTheResolvedBrandColors(t *testing.T) {
	for _, theme := range []string{"light", "dark", "blue", "purple"} {
		t.Run(theme, func(t *testing.T) {
			page := renderPage(t, "authorize_enhanced.html", map[string]any{
				"Theme":          theme,
				"PrimaryColor":   "#1e40af",
				"SecondaryColor": "#1e3a8a",
				"Title":          "Employee Verification",
			})

			assert.Equal(t, 1, strings.Count(page, "--primary-color:"),
				"exactly one --primary-color definition, or the later one wins")
			assert.Equal(t, 1, strings.Count(page, "--secondary-color:"),
				"exactly one --secondary-color definition, or the later one wins")
			assert.Contains(t, page, "--primary-color: #1e40af;")
			assert.Contains(t, page, "--secondary-color: #1e3a8a;")

			// The colors the theme blocks used to force.
			assert.NotContains(t, page, "#3182ce")
			assert.NotContains(t, page, "#805ad5")
		})
	}

	// The dark theme still changes the page's surfaces; only the brand colors
	// moved out of the theme block.
	dark := renderPage(t, "authorize_enhanced.html", map[string]any{"Theme": "dark", "PrimaryColor": "#1e40af", "SecondaryColor": "#1e3a8a"})
	assert.Contains(t, dark, "--container-bg: #1a202c;")
	light := renderPage(t, "authorize_enhanced.html", map[string]any{"Theme": "light", "PrimaryColor": "#1e40af", "SecondaryColor": "#1e3a8a"})
	assert.NotContains(t, light, "--container-bg: #1a202c;")
}

// ZgotmplZ is what html/template substitutes when a value cannot be made safe
// in the context it was interpolated into. A page carrying it is a page with a
// silently dropped value, which is how custom_css spent its whole life: a
// stylesheet interpolated into a <style> element as a plain string.
//
// The free-text values below carry braces and parentheses deliberately. A
// plain alphanumeric string survives html/template's CSS-value filter intact,
// so a test rendering "Employee Verification" would pass with the page's title
// interpolated into a <style> element and prove nothing; these characters are
// the ones that filter refuses, which is what makes the guard sensitive to a
// stylesheet context being reintroduced anywhere a value is rendered.
func TestEmbeddedPagesRenderNoUnsafeValueSentinel(t *testing.T) {
	const cssHostile = "Employee {Verification} (ACME Ltd)"

	pages := map[string]any{
		"authorize_enhanced.html": map[string]any{
			"Theme": "dark", "PrimaryColor": "#1e40af", "SecondaryColor": "#1e3a8a",
			"Title": cssHostile, "Subtitle": cssHostile,
			"LogoURL": "https://brand.example/logo.png",
		},
		"credential_display.html": map[string]any{
			"PrimaryColor": "#1e40af", "SecondaryColor": "#1e3a8a",
			"SessionID": "session-1", "ShowClaims": true,
			"ClientID": cssHostile, "State": cssHostile,
		},
	}

	for name, data := range pages {
		t.Run(name, func(t *testing.T) {
			page := renderPage(t, name, data)
			assert.NotContains(t, page, "ZgotmplZ")
			// The guard only means something if the hostile value really did
			// reach the page; an unused key would pass trivially.
			assert.Contains(t, page, "Employee {Verification}")
		})
	}
}

// css_file renders as a <link>, which is what has always made it work for a
// URL - and what made its old documentation, which called it a path read from
// disk, produce a 404 for every deployment that followed it.
func TestAuthorizationPageLinksTheConfiguredStylesheet(t *testing.T) {
	base := map[string]any{"Theme": "light", "PrimaryColor": "#1e40af", "SecondaryColor": "#1e3a8a"}

	withFile := map[string]any{"CSSFile": "https://static.example.com/verifier.css"}
	for k, v := range base {
		withFile[k] = v
	}
	page := renderPage(t, "authorize_enhanced.html", withFile)
	assert.Contains(t, page, `<link rel="stylesheet" href="https://static.example.com/verifier.css">`)
	// After the built-in styles, or it cannot override them.
	assert.Greater(t, strings.Index(page, "static.example.com"), strings.Index(page, "</style>"))

	// Absent, no empty link element.
	assert.NotContains(t, renderPage(t, "authorize_enhanced.html", base), `rel="stylesheet"`)
}
