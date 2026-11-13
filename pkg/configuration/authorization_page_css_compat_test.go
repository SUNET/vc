package configuration

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// custom_css was removed from AuthorizationPageCSSConfig because it could never
// apply (SUNET/vc#930). Removing a configuration key is only
// safe while the loader ignores keys it does not know: this one calls plain
// yaml.Unmarshal on gopkg.in/yaml.v2, which discards them, so a deployment
// that still sets them keeps booting and keeps the settings that do work.
//
// A switch to yaml.v3 with KnownFields, or to UnmarshalStrict, would turn
// every such deployment into a startup failure. That is the regression this
// guards, and it is cheap next to re-learning it from a refusing cluster.
func TestRemovedAuthorizationPageCSSKeysAreIgnored(t *testing.T) {
	raw := []byte(`
verifier:
  authorization_page_css:
    theme: "purple"
    primary_color: "#1e40af"
    custom_css: |
      .container { max-width: 600px; }
`)

	cfg := &model.Cfg{}
	require.NoError(t, yaml.Unmarshal(raw, cfg),
		"a configuration still carrying the removed keys must parse, not refuse")
	require.NotNil(t, cfg.Verifier)

	css := cfg.Verifier.AuthorizationPageCSS
	assert.Equal(t, "purple", css.Theme, "the keys that remain are still read")
	assert.Equal(t, "#1e40af", css.PrimaryColor, "the keys that remain are still read")
}

// css_file is NOT removed. It renders as a <link href>, so it has always
// worked for a value the browser can fetch - only its documentation was wrong,
// describing a path read from disk. Removing it would have silently dropped
// the styling of every deployment that had set it to a URL, which is the one
// thing the removal above is safe from and this one would not have been.
func TestCSSFileSurvivesAsAStylesheetURL(t *testing.T) {
	raw := []byte(`
verifier:
  authorization_page_css:
    css_file: "https://static.example.com/verifier.css"
`)

	cfg := &model.Cfg{}
	require.NoError(t, yaml.Unmarshal(raw, cfg))
	require.NotNil(t, cfg.Verifier)
	assert.Equal(t, "https://static.example.com/verifier.css", cfg.Verifier.AuthorizationPageCSS.CSSFile)
}
