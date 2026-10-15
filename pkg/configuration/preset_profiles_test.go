package configuration

import (
	"testing"

	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func presetCfg(scopeCfg *model.VerificationPresetScope) *model.Cfg {
	schema := &mdoc.MDDLSchema{
		Format:  "mso_mdoc",
		DocType: "eu.europa.ec.eudi.nym_auth.1",
		Claims: map[string]mdoc.NamespaceClaims{
			"eu.europa.ec.eudi.nym_auth.1": {"secret_seed_commitment": {Mandatory: true, ValueType: "bstr"}},
		},
	}
	return &model.Cfg{
		Common: &model.Common{
			CredentialMetadata: map[string]*model.CredentialMetadata{
				"nym": {Format: "mso_mdoc", MDDL: schema},
			},
		},
		Verifier: &model.Verifier{
			Presets: map[string]model.PresetDefinition{
				"Nym": {Credentials: model.VerificationPreset{"nym": scopeCfg}},
			},
		},
	}
}

func conformingScope() *model.VerificationPresetScope {
	return &model.VerificationPresetScope{
		Format:   openid4vp.FormatCircuitZk,
		Validate: openid4vp.ProfileNymAuth,
		Req: []openid4vp.ReqItem{{
			ID:     openid4vp.FunctionPseudonym,
			Return: "nym-123",
			Params: map[string]any{"config": "known-offender-matching-ssc"},
		}},
	}
}

// The profile judges the query the UI would PUBLISH, not the config
// struct. A check that judged something else would be worse than none:
// it would report on a request the verifier never sends.
func TestPresetProfileAcceptsAConformingPreset(t *testing.T) {
	require.NoError(t, checkPresetValidationProfiles(presetCfg(conformingScope())))
}

func TestPresetProfileReportsWhereTheViolationIs(t *testing.T) {
	scope := conformingScope()
	scope.Req[0].Params["config"] = "not-a-rulebook-configuration"

	err := checkPresetValidationProfiles(presetCfg(scope))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verifier.presets")
	assert.Contains(t, err.Error(), `"Nym"`)
	assert.Contains(t, err.Error(), `"nym"`)
	assert.Contains(t, err.Error(), "not-a-rulebook-configuration")
}

// The doctype comes from the scope's own credential_metadata, not from
// the preset - so a profile that requires one has to see it. Dropping the
// metadata is how the reconstruction would silently stop matching what
// the UI builds.
func TestPresetProfileReadsMetaFromCredentialMetadata(t *testing.T) {
	cfg := presetCfg(conformingScope())
	require.NoError(t, checkPresetValidationProfiles(cfg))

	cfg.Common.CredentialMetadata["nym"].MDDL = nil
	err := checkPresetValidationProfiles(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "doctype_value")
}

// Opt-in. A preset that names no profile is not judged, because a
// circuit_zk request that is not a nym_auth request is not invalid and
// this server is not the one to decide.
func TestPresetProfileIsOptIn(t *testing.T) {
	scope := conformingScope()
	scope.Validate = ""
	scope.Req[0].Params["config"] = "not-a-rulebook-configuration"
	require.NoError(t, checkPresetValidationProfiles(presetCfg(scope)))

	// Including the case with no req at all, which the profile requires.
	require.NoError(t, checkPresetValidationProfiles(presetCfg(&model.VerificationPresetScope{
		Format: openid4vp.FormatCircuitZk,
	})))
}

// The UI drops a circuit_zk scope's claims, so judging them here would
// report a conflict the wire never carries.
func TestPresetProfileIgnoresClaimsTheUIWouldDrop(t *testing.T) {
	scope := conformingScope()
	scope.Claims = []model.VerificationPresetClaim{
		{Path: []string{"eu.europa.ec.eudi.nym_auth.1", "secret_seed_commitment"}},
	}
	require.NoError(t, checkPresetValidationProfiles(presetCfg(scope)))
}

// A nil scope value is a preset credential with no overrides at all, and
// a nil Verifier stanza is every non-verifier service. Both reach this.
func TestPresetProfileToleratesAbsentConfiguration(t *testing.T) {
	require.NoError(t, checkPresetValidationProfiles(presetCfg(nil)))
	require.NoError(t, checkPresetValidationProfiles(&model.Cfg{}))
	require.NoError(t, checkPresetValidationProfiles(nil))
}
