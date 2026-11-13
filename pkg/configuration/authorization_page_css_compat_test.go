package configuration

import (
	"os"
	"path/filepath"
	"strings"
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

// The two tests above exercise yaml.Unmarshal, which is where the keys are
// discarded - but not that the real loader gets past them, and a config that
// died earlier for another reason would prove nothing either way. This drives
// New itself.
//
// The configuration is deliberately incomplete, because a complete verifier
// config is long and none of it is the point. What matters is WHICH error
// comes back: the three genuinely required verifier fields, and nothing about
// the removed key. A loader that became strict - yaml.v3 with KnownFields, or
// UnmarshalStrict - would name custom_css in that error instead, and this
// fails. Asserting the expected fields are named is what stops it passing
// because the load died before reaching validation at all.
func TestNew_DoesNotRefuseAConfigCarryingTheRemovedKey(t *testing.T) {
	dir := t.TempDir()

	vctm := filepath.Join(dir, "vctm.json")
	require.NoError(t, os.WriteFile(vctm, []byte(`{"vct":"urn:example:pid","name":"PID"}`), 0o600))

	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
common:
  mongo:
    uri: mongodb://localhost:27017
  credential_metadata:
    pid:
      format: vc+sd-jwt
      vctm_file_path: `+vctm+`
verifier:
  authorization_page_css:
    theme: "purple"
    primary_color: "#1e40af"
    css_file: "https://static.example.com/verifier.css"
    custom_css: |
      .container { max-width: 600px; }
`), 0o600))

	t.Setenv("VC_CONFIG_YAML", path)

	_, err := New(t.Context(), "verifier")
	require.Error(t, err, "this configuration is incomplete, so it must fail - on its missing fields")

	assert.NotContains(t, err.Error(), "custom_css",
		"the removed key must be discarded, not refused")
	assert.NotContains(t, strings.ToLower(err.Error()), "unknown",
		"a strict loader would reject the key as unknown, breaking every deployment that still sets it")

	// Proof the load reached validation rather than dying before it: these are
	// the fields a verifier genuinely requires.
	for _, field := range []string{"public_url", "key_config", "openid4vp"} {
		assert.Contains(t, err.Error(), field,
			"the load must have reached validation, or this test proves nothing")
	}
}
