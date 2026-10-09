package model

import (
	"testing"

	"github.com/creasty/defaults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

// require_pkce is a pointer for one reason, and this is it: defaults.Set
// fills any field still at its ZERO value, and false is the zero value of a
// bool. A plain bool with default:"true" could never be set to false -
// `require_pkce: false` would unmarshal to false, be indistinguishable from
// absent, and be overwritten with true.
//
// Exercised through yaml.Unmarshal and defaults.Set in that order, which is
// what pkg/configuration's loader does, rather than by constructing a *bool
// in the test - the latter cannot catch this regression at all.
func TestRequirePKCESurvivesAnExplicitFalse(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want bool
	}{
		{"absent", "issuer: https://verifier.example.com\n", true},
		{"explicit false", "issuer: https://verifier.example.com\nrequire_pkce: false\n", false},
		{"explicit true", "issuer: https://verifier.example.com\nrequire_pkce: true\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var op OIDCOP
			require.NoError(t, yaml.Unmarshal([]byte(tc.yaml), &op))
			require.NoError(t, defaults.Set(&op))

			assert.Equal(t, tc.want, BoolVal(op.RequirePKCE, true),
				"defaults.Set overwrote the configured value")
		})
	}
}

// The same for a single static client, where unset means "inherit the OP's
// policy" and so must stay nil rather than becoming false.
func TestStaticClientRequirePKCEStaysUnsetWhenAbsent(t *testing.T) {
	var client StaticOIDCClient
	require.NoError(t, yaml.Unmarshal([]byte("client_id: c\n"), &client))
	require.NoError(t, defaults.Set(&client))

	assert.Nil(t, client.RequirePKCE, "unset must stay unset, or it cannot inherit")

	require.NoError(t, yaml.Unmarshal([]byte("client_id: c\nrequire_pkce: false\n"), &client))
	require.NoError(t, defaults.Set(&client))
	require.NotNil(t, client.RequirePKCE)
	assert.False(t, *client.RequirePKCE)
}
