package configuration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/creasty/defaults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// registrationAuthConfig runs the loader's steps over the YAML given - the
// same yaml.Unmarshal, defaults.Set and dropInertRegistrationAuth that New
// runs, in that order - and hands back the OIDC provider stanza that
// helpers.Check would then see.
//
// Calling New instead would need a complete, valid verifier config including
// VCTM files to get as far as validation; what is under test is which stanza
// reaches the validator, and that is settled by these three steps.
func registrationAuthConfig(t *testing.T, raw string) model.OIDCOP {
	t.Helper()

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	cfg := &model.Cfg{}
	require.NoError(t, yaml.Unmarshal([]byte(raw), cfg))
	require.NoError(t, defaults.Set(cfg))

	dropInertRegistrationAuth(cfg, log)

	require.NotNil(t, cfg.Verifier.Outbound.OIDCProvider)

	return *cfg.Verifier.Outbound.OIDCProvider
}

// A deployment that has closed registration can retire the whole auth policy,
// token file included, rather than keeping it on disk to satisfy a
// required_if for an endpoint that is no longer served.
//
// mode: static with no static_bearer_token_file is the shape that proves it:
// validated, it fails required_if (pkg/model/config.go), and the struct-level
// rule in pkg/helpers/validate.go would also refuse settings paired with the
// wrong mode. Neither can fire on a stanza that is not there.
func TestClosedRegistrationDropsTheInertAuthStanza(t *testing.T) {
	oidcProvider := registrationAuthConfig(t, `
verifier:
  outbound:
    oidc_provider:
      issuer: https://verifier.example.org
      subject_type: public
      subject_salt: test-salt
      dynamic_registration:
        enabled: false
      dynamic_registration_auth:
        mode: static
`)

	assert.Nil(t, oidcProvider.DynamicRegistrationAuth,
		"an auth stanza that configures nothing reachable must not reach the validator")
	assert.NoError(t, helpers.CheckSimple(oidcProvider),
		"a retired registration credential must not keep the verifier from starting")
}

// ... and the moment registration is offered again, the same stanza is held
// to the same rules. Closing registration relaxes nothing for a deployment
// that still serves it.
func TestOfferedRegistrationStillValidatesTheAuthStanza(t *testing.T) {
	for _, tt := range []struct {
		name         string
		registration string
	}{
		{
			name: "explicitly enabled",
			registration: `      dynamic_registration:
        enabled: true
`,
		},
		{
			name:         "no dynamic_registration block",
			registration: "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			oidcProvider := registrationAuthConfig(t, `
verifier:
  outbound:
    oidc_provider:
      issuer: https://verifier.example.org
      subject_type: public
      subject_salt: test-salt
`+tt.registration+`      dynamic_registration_auth:
        mode: static
`)

			require.NotNil(t, oidcProvider.DynamicRegistrationAuth,
				"an auth stanza that still guards a served endpoint must reach the validator")

			err := helpers.CheckSimple(oidcProvider)
			require.Error(t, err, "mode: static with no token file must still be refused at startup")
			assert.Contains(t, err.Error(), "static_bearer_token_file",
				"the error must name the key the operator has to fix")
		})
	}
}

// TestNew_DropsTheInertAuthStanza drives the real loader, because the tests
// above cannot see WHERE the stanza is dropped - and a drop that runs after
// validation, or that nothing calls, changes nothing. Removing the call from
// New() compiles and leaves every test above passing.
//
// Neither case asserts the load SUCCEEDS: these configs are deliberately
// minimal and fail later on other incomplete stanzas. What each asserts is
// which failure the operator gets.
func TestNew_DropsTheInertAuthStanza(t *testing.T) {
	dir := t.TempDir()

	// A local VCTM document: the verifier loads credential schemas before
	// validation runs, so a bare vct would send it to the credential
	// registry and fail there, and the stanza under test would never be
	// reached.
	vctm := filepath.Join(dir, "vctm.json")
	require.NoError(t, os.WriteFile(vctm, []byte(`{"vct":"urn:example:degree","name":"Degree"}`), 0o600))

	write := func(t *testing.T, name, registration string) string {
		t.Helper()
		path := filepath.Join(dir, "config-"+name+".yaml")
		require.NoError(t, os.WriteFile(path, []byte(`
common:
  mongo:
    uri: mongodb://localhost:27017
  credential_metadata:
    degree:
      format: dc+sd-jwt
      vctm_file_path: `+vctm+`
verifier:
  outbound:
    oidc_provider:
      issuer: https://verifier.example.org
      subject_type: public
      subject_salt: test-salt
`+registration+`      dynamic_registration_auth:
        mode: static
`), 0o600))

		return path
	}

	t.Run("a retired token file does not stop a closed verifier", func(t *testing.T) {
		t.Setenv("VC_CONFIG_YAML", write(t, "closed", `      dynamic_registration:
        enabled: false
`))

		_, err := New(t.Context(), "verifier")
		if err != nil {
			require.NotContains(t, err.Error(), "static_bearer_token_file",
				"a stanza that configures nothing reachable must not be validated")
		}
	})

	// The control: the same stanza, still guarding a served endpoint, is
	// still held to the same rule. Without it this test would pass just as
	// well if validation had been dropped for everyone.
	t.Run("an open verifier is still held to it", func(t *testing.T) {
		t.Setenv("VC_CONFIG_YAML", write(t, "open", ""))

		_, err := New(t.Context(), "verifier")
		require.Error(t, err)
		require.Contains(t, err.Error(), "static_bearer_token_file",
			"mode: static with no token file must still be refused while /register is served")
	})
}
