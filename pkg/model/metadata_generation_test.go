package model

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"vc/pkg/pki"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetadataGenerationAgainstReference(t *testing.T) {
	// Setup test PKI
	_, _, ecKeyPath, ecCertPath := setupTestPKI(t)
	keyConfig := &pki.KeyConfig{
		PrivateKeyPath: ecKeyPath,
		ChainPath:      ecCertPath,
	}

	// Load reference metadata
	referenceData, err := os.ReadFile("../../metadata/issuer_metadata.json")
	require.NoError(t, err, "Failed to read reference metadata")

	var referenceMetadata map[string]any
	err = json.Unmarshal(referenceData, &referenceMetadata)
	require.NoError(t, err, "Failed to unmarshal reference metadata")

	// Setup test configuration matching the reference
	cfg := &IssuerMetadata{}

	// Setup credential constructors
	credentialConstructors := map[string]*CredentialConstructor{
		"diploma": {
			VCT:          "urn:eudi:diploma:1",
			VCTMFilePath: "../../metadata/vctm_diploma.json",
			Format:       "dc+sd-jwt",
			AuthMethod:   "basic",
		},
		"pid_1_5": {
			VCT:          "urn:eudi:pid:arf-1.5:1",
			VCTMFilePath: "../../metadata/vctm_pid_arf_1_5.json",
			Format:       "dc+sd-jwt",
			AuthMethod:   "pid_auth",
		},
		"ehic": {
			VCT:          "urn:eudi:ehic:1",
			VCTMFilePath: "../../metadata/vctm_ehic.json",
			Format:       "dc+sd-jwt",
			AuthMethod:   "basic",
		},
		"pda1": {
			VCT:          "urn:eudi:pda1:1",
			VCTMFilePath: "../../metadata/vctm_pda1.json",
			Format:       "dc+sd-jwt",
			AuthMethod:   "basic",
		},
	}

	// Load VCTM files
	ctx := context.Background()
	for scope, constructor := range credentialConstructors {
		err := constructor.LoadVCTMetadata(ctx, scope)
		require.NoError(t, err, "Failed to load VCTM for %s", scope)
	}

	// Generate metadata
	metadata, _, _, _, err := cfg.LoadAndSign(ctx, "http://vc_dev_apigw:8080", keyConfig, credentialConstructors)
	require.NoError(t, err, "Failed to generate metadata")

	// Marshal to JSON for comparison
	generatedData, err := json.MarshalIndent(metadata, "", "  ")
	require.NoError(t, err, "Failed to marshal generated metadata")

	var generatedMetadata map[string]any
	err = json.Unmarshal(generatedData, &generatedMetadata)
	require.NoError(t, err, "Failed to unmarshal generated metadata")

	// Compare top-level fields
	assert.Equal(t, referenceMetadata["credential_issuer"], generatedMetadata["credential_issuer"], "credential_issuer mismatch")
	assert.Equal(t, referenceMetadata["credential_endpoint"], generatedMetadata["credential_endpoint"], "credential_endpoint mismatch")

	// Get credential configurations
	refConfigs, ok := referenceMetadata["credential_configurations_supported"].(map[string]any)
	require.True(t, ok, "Reference credential_configurations_supported not found or wrong type")

	genConfigs, ok := generatedMetadata["credential_configurations_supported"].(map[string]any)
	require.True(t, ok, "Generated credential_configurations_supported not found or wrong type")

	// Check each credential type
	for scope := range credentialConstructors {
		t.Run(scope, func(t *testing.T) {
			refConfig, refExists := refConfigs[scope].(map[string]any)
			genConfig, genExists := genConfigs[scope].(map[string]any)

			assert.True(t, refExists, "Reference config for %s not found", scope)
			assert.True(t, genExists, "Generated config for %s not found", scope)

			if refExists && genExists {
				// Check core fields
				assert.Equal(t, refConfig["scope"], genConfig["scope"], "%s: scope mismatch", scope)
				assert.Equal(t, refConfig["vct"], genConfig["vct"], "%s: vct mismatch", scope)
				assert.Equal(t, refConfig["format"], genConfig["format"], "%s: format mismatch", scope)

				// Check display (should exist from VCTM)
				refDisplay, refHasDisplay := refConfig["display"]
				genDisplay, genHasDisplay := genConfig["display"]

				if refHasDisplay {
					assert.True(t, genHasDisplay, "%s: generated metadata missing display", scope)

					if genHasDisplay {
						t.Logf("%s Reference display: %+v", scope, refDisplay)
						t.Logf("%s Generated display: %+v", scope, genDisplay)
					}
				}

				// Check crypto binding methods
				assert.Equal(t, refConfig["cryptographic_binding_methods_supported"],
					genConfig["cryptographic_binding_methods_supported"],
					"%s: cryptographic_binding_methods_supported mismatch", scope)

				// Check signing algorithms
				assert.NotNil(t, genConfig["credential_signing_alg_values_supported"],
					"%s: missing credential_signing_alg_values_supported", scope)

				// Check proof types
				assert.NotNil(t, genConfig["proof_types_supported"],
					"%s: missing proof_types_supported", scope)
			}
		})
	}

	// Print generated metadata for inspection
	t.Logf("Generated metadata:\n%s", string(generatedData))
}
