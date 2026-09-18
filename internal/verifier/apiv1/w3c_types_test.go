package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// diplomaTypeIRIs is the DCQL constraint for the fixture credential: fully
// expanded IRIs, which is what meta.type_values requires.
var diplomaTypeIRIs = [][]string{{
	"https://www.w3.org/2018/credentials#VerifiableCredential",
	"https://example.org/diploma#DiplomaCredential",
}}

// w3cScopeWithTypes is a W3C VC scope that declares the DCQL type values it is
// requested by, which is what makes it requestable at all (SUNET/vc#680).
func w3cScopeWithTypes(typeValues ...[]string) *model.CredentialMetadata {
	return &model.CredentialMetadata{
		Format:               "ldp_vc",
		VCTMFilePath:         "/path/to/vctm",
		VCTM:                 &sdjwtvc.VCTM{VCT: "urn:eudi:diploma:1"},
		CredentialTypes:      []string{"VerifiableCredential", "DiplomaCredential"},
		CredentialTypeValues: typeValues,
	}
}

// TestW3CScopeIsRequestable is the point of SUNET/vc#680: before it, a
// configured ldp_vc scope had no expressible DCQL constraint, so every path
// refused it - the query builder errored, presets dropped it and the UI picker
// omitted it. With credential_types configured it is a first-class scope.
func TestW3CScopeIsRequestable(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"diploma_ldp": w3cScopeWithTypes(diplomaTypeIRIs...),
		"pid":         sdJWTScope("urn:eudi:pid:1"),
	}, map[string]model.PresetDefinition{
		"DIPLOMA": {Credentials: model.VerificationPreset{"diploma_ldp": nil}},
	})

	t.Run("the query builder emits type_values", func(t *testing.T) {
		dcql, err := client.buildDCQLQueryFromConfig([]string{"diploma_ldp"})
		require.NoError(t, err)
		require.Len(t, dcql.Credentials, 1)

		cred := dcql.Credentials[0]
		assert.Equal(t, diplomaTypeIRIs, cred.Meta.TypeValues)
		assert.Empty(t, cred.Meta.VCTValues, "a W3C query must not carry vct_values")
		assert.Empty(t, cred.Meta.DoctypeValue)
		// The shape this repo's own validator demands for the format.
		assert.NoError(t, openid4vp.ValidateCredentialQuery(cred))
	})

	t.Run("a mixed request is no longer rejected", func(t *testing.T) {
		dcql, err := client.buildDCQLQueryFromConfig([]string{"pid", "diploma_ldp"})
		require.NoError(t, err)
		assert.Len(t, dcql.Credentials, 2)
	})

	t.Run("the UI picker offers it with its types", func(t *testing.T) {
		reply, err := client.UIMetadata(t.Context())
		require.NoError(t, err)

		require.Contains(t, reply.Credentials, "diploma_ldp")
		info := reply.Credentials["diploma_ldp"]
		assert.Equal(t, diplomaTypeIRIs, info.TypeValues)
		assert.Empty(t, info.VCTValues, "a W3C credential is not matched by vct_values")

		require.Contains(t, reply.Presets, "DIPLOMA")
		require.Len(t, reply.Presets["DIPLOMA"].Credentials, 1)
		assert.Equal(t, diplomaTypeIRIs, reply.Presets["DIPLOMA"].Credentials[0].Meta.TypeValues)
	})
}

// TestW3CScopeWithoutTypesStaysUnusable pins the half of #680 that is a refusal
// rather than a feature: the bare base type matches every W3C credential in the
// wallet, so a scope that names only it - or names nothing - is still reported
// as unconstrainable instead of being sent as an over-broad query.
func TestW3CScopeWithoutTypesStaysUnusable(t *testing.T) {
	for _, tc := range []struct {
		name  string
		types [][]string
	}{
		{"no credential_type_values at all", nil},
		{"only the base type IRI", [][]string{{"https://www.w3.org/2018/credentials#VerifiableCredential"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
				"diploma_ldp": w3cScopeWithTypes(tc.types...),
			}, map[string]model.PresetDefinition{
				"DIPLOMA": {Credentials: model.VerificationPreset{"diploma_ldp": nil}},
			})

			_, err := client.buildDCQLQueryFromConfig([]string{"diploma_ldp"})
			assert.Error(t, err)

			reply, err := client.UIMetadata(t.Context())
			require.NoError(t, err)
			assert.NotContains(t, reply.Credentials, "diploma_ldp")
			assert.NotContains(t, reply.Presets, "DIPLOMA")
		})
	}
}
