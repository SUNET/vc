package apiv1

import (
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"
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
// requested by, which is what makes it requestable at all.
func w3cScopeWithTypes(typeValues ...[]string) *model.CredentialMetadata {
	return &model.CredentialMetadata{
		Format:               "ldp_vc",
		VCTMFilePath:         "/path/to/vctm",
		VCTM:                 &sdjwtvc.VCTM{VCT: "urn:eudi:diploma:1"},
		CredentialTypes:      []string{"VerifiableCredential", "DiplomaCredential"},
		CredentialTypeValues: typeValues,
	}
}

// TestW3CScopeIsRequestable pins the point of the change: without configured
// types an ldp_vc scope has no expressible DCQL constraint, so the query
// builder errors, presets drop it and the UI picker omits it. With
// credential_types configured it is a first-class scope.
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

// TestZKPresetOverrideSurvivesTheUsabilityCheck pins the documented ZK preset
// shape against the check that drops unconstrainable preset credentials.
//
// DCQLMetaQuery deliberately refuses mso_mdoc_zk, since meta.zk_system_type
// lives on VerificationPresetScope and nothing in credential_metadata can
// supply it. The documented way to request a ZK proof is the other way round:
// the scope declares plain mso_mdoc and the PRESET overrides Format while
// supplying ZKSystemType - so the usability check sees the metadata's own
// mso_mdoc, resolves a doctype, and the override is applied afterwards.
//
// Raised in review as a case where the check would drop such a preset. It does
// not, for the documented shape, and this keeps it that way.
func TestZKPresetOverrideSurvivesTheUsabilityCheck(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid_mdoc": {Format: "mso_mdoc", MDDL: &mdoc.MDDLSchema{DocType: "eu.europa.ec.eudi.pid.1"}},
	}, map[string]model.PresetDefinition{
		"ZK": {Credentials: model.VerificationPreset{"pid_mdoc": &model.VerificationPresetScope{
			Format:       "mso_mdoc_zk",
			ZKSystemType: []openid4vp.ZKSystemTypeSpec{{ID: "circuit-1", System: "longfellow"}},
		}}},
	})

	reply, err := client.UIMetadata(t.Context())
	require.NoError(t, err)

	require.Contains(t, reply.Presets, "ZK")
	require.Len(t, reply.Presets["ZK"].Credentials, 1)
	cred := reply.Presets["ZK"].Credentials[0]

	assert.Equal(t, "mso_mdoc_zk", cred.Format, "the preset's format override applies")
	assert.Equal(t, "eu.europa.ec.eudi.pid.1", cred.Meta.DoctypeValue, "from the scope's own mso_mdoc metadata")
	assert.Len(t, cred.Meta.ZKSystemType, 1, "the preset supplies the ZK system types")
}

// TestUIInteractionRejectsUnconstrainedQuery covers a review finding: the DCQL
// in a UI interaction request arrives from the caller with only
// validate:"required" behind it, so ValidateCredentialQuery - which this PR
// extended - had no production caller at all and nothing checked that a
// credential query carried the constraint its format needs.
//
// An empty meta is not a narrow request but no request: DCQL reads it as
// matching every credential of that format.
func TestUIInteractionRejectsUnconstrainedQuery(t *testing.T) {
	client := dcqlClientFor(t, map[string]*model.CredentialMetadata{
		"pid": sdJWTScope("urn:eudi:pid:1"),
	}, nil)

	for _, tc := range []struct {
		name string
		cred openid4vp.CredentialQuery
	}{
		{"W3C with no type_values", openid4vp.CredentialQuery{ID: "diploma", Format: "ldp_vc"}},
		{"W3C with an empty alternative", openid4vp.CredentialQuery{
			ID: "diploma", Format: "ldp_vc",
			Meta: openid4vp.MetaQuery{TypeValues: [][]string{{}}},
		}},
		{"SD-JWT with no vct_values", openid4vp.CredentialQuery{ID: "pid", Format: openid4vp.FormatSDJWTVC}},
		{"mdoc with no doctype_value", openid4vp.CredentialQuery{ID: "mdl", Format: openid4vp.FormatMsoMdoc}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.UIInteraction(t.Context(), &UIInteractionRequest{
				DCQLQuery: &openid4vp.DCQL{Credentials: []openid4vp.CredentialQuery{tc.cred}},
			})
			require.Error(t, err, "an unconstrained query must not be signed and served")
			assert.Contains(t, err.Error(), tc.cred.ID)
		})
	}
}
