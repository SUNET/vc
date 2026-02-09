package apiv1

import (
	"encoding/json"
	"testing"
	"vc/pkg/openid4vci"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDeriveVPFormatsFromMetadata_CompareWithHardcoded compares the new derived VP formats
// with the old hardcoded version to show the differences
func TestDeriveVPFormatsFromMetadata_CompareWithHardcoded(t *testing.T) {
	// Old hardcoded format
	oldHardcoded := []byte(`{
      "vc+sd-jwt": {
        "sd-jwt_alg_values": [
          "ES256"
        ],
        "kb-jwt_alg_values": [
          "ES256"
        ]
      },
      "dc+sd-jwt": {
        "sd-jwt_alg_values": [
          "ES256"
        ],
        "kb-jwt_alg_values": [
          "ES256"
        ]
      },
      "mso_mdoc": {
        "alg": [
          "ES256"
        ]
      }
    }`)

	var oldFormat map[string]map[string]any
	err := json.Unmarshal(oldHardcoded, &oldFormat)
	require.NoError(t, err)

	// Simulate metadata similar to what we have in production
	metadata := &openid4vci.CredentialIssuerMetadataParameters{
		CredentialConfigurationsSupported: map[string]openid4vci.CredentialConfigurationsSupported{
			"diploma": {
				Format:                              "dc+sd-jwt",
				CredentialSigningAlgValuesSupported: []any{"ES256"},
				ProofTypesSupported: map[string]openid4vci.ProofsTypesSupported{
					"jwt": {
						ProofSigningAlgValuesSupported: []string{"ES256"},
					},
				},
			},
			"pid_1_5": {
				Format:                              "dc+sd-jwt",
				CredentialSigningAlgValuesSupported: []any{"ES256"},
				ProofTypesSupported: map[string]openid4vci.ProofsTypesSupported{
					"jwt": {
						ProofSigningAlgValuesSupported: []string{"ES256"},
					},
				},
			},
			"pid_1_5_mdoc": {
				Format:                              "mso_mdoc",
				CredentialSigningAlgValuesSupported: []any{float64(-7)}, // -7 is ES256 in COSE
			},
		},
	}

	// Derive VP formats from metadata
	result := deriveVPFormatsFromMetadata(metadata)
	require.NotNil(t, result)

	// Convert to JSON to compare
	newFormatJSON, err := json.MarshalIndent(result, "", "  ")
	require.NoError(t, err)

	var newFormat map[string]map[string]any
	err = json.Unmarshal(newFormatJSON, &newFormat)
	require.NoError(t, err)

	t.Logf("Old hardcoded format:\n%s", string(oldHardcoded))
	t.Logf("\nNew derived format:\n%s", string(newFormatJSON))

	// Compare the formats
	t.Run("dc+sd-jwt comparison", func(t *testing.T) {
		// Both should have dc+sd-jwt
		assert.Contains(t, oldFormat, "dc+sd-jwt")
		assert.Contains(t, newFormat, "dc+sd-jwt")

		// Field names should match
		assert.Contains(t, oldFormat["dc+sd-jwt"], "sd-jwt_alg_values")
		assert.Contains(t, oldFormat["dc+sd-jwt"], "kb-jwt_alg_values")
		assert.Contains(t, newFormat["dc+sd-jwt"], "sd-jwt_alg_values")
		assert.Contains(t, newFormat["dc+sd-jwt"], "kb-jwt_alg_values")

		// Values should match
		assert.Equal(t, []any{"ES256"}, oldFormat["dc+sd-jwt"]["sd-jwt_alg_values"])
		assert.Equal(t, []any{"ES256"}, newFormat["dc+sd-jwt"]["sd-jwt_alg_values"])
	})

	t.Run("vc+sd-jwt difference", func(t *testing.T) {
		// Old had vc+sd-jwt but new doesn't (because metadata doesn't have any)
		assert.Contains(t, oldFormat, "vc+sd-jwt", "Old hardcoded has vc+sd-jwt")
		assert.NotContains(t, newFormat, "vc+sd-jwt", "New derived doesn't have vc+sd-jwt (not in metadata)")
	})

	t.Run("mso_mdoc comparison - CRITICAL DIFFERENCES", func(t *testing.T) {
		// Both should have mso_mdoc
		assert.Contains(t, oldFormat, "mso_mdoc")
		assert.Contains(t, newFormat, "mso_mdoc")

		// DIFFERENCE 1: Field names
		// Old (WRONG): uses "alg"
		// New (CORRECT): uses "issuerauth_alg_values" and "deviceauth_alg_values"
		assert.Contains(t, oldFormat["mso_mdoc"], "alg", "Old uses 'alg' field")
		assert.Contains(t, newFormat["mso_mdoc"], "issuerauth_alg_values", "New uses spec-compliant 'issuerauth_alg_values'")
		assert.Contains(t, newFormat["mso_mdoc"], "deviceauth_alg_values", "New uses spec-compliant 'deviceauth_alg_values'")

		// DIFFERENCE 2: Value types
		// Old (WRONG): uses string "ES256"
		// New (CORRECT): uses integer -7 (COSE algorithm identifier)
		oldAlg := oldFormat["mso_mdoc"]["alg"].([]any)
		assert.Equal(t, "ES256", oldAlg[0], "Old uses string 'ES256'")

		newIssuerAuth := newFormat["mso_mdoc"]["issuerauth_alg_values"].([]any)
		assert.Equal(t, float64(-7), newIssuerAuth[0], "New uses integer -7 (COSE identifier for ES256)")

		t.Logf("\nCRITICAL: Old mso_mdoc format was INCORRECT!")
		t.Logf("  Old: {\"alg\": [\"ES256\"]}")
		t.Logf("  New: {\"issuerauth_alg_values\": [-7], \"deviceauth_alg_values\": [-7]}")
		t.Logf("  -7 is the COSE algorithm identifier for ES256")
	})

	// Show summary
	t.Run("summary", func(t *testing.T) {
		t.Log("\n=== COMPARISON SUMMARY ===")
		t.Log("1. vc+sd-jwt: Removed (wasn't in actual metadata)")
		t.Log("2. dc+sd-jwt: ✓ Same structure, derived from metadata")
		t.Log("3. mso_mdoc: FIXED - now uses correct field names and COSE integer identifiers")
		t.Log("   - Old: {\"alg\": [\"ES256\"]} ❌")
		t.Log("   - New: {\"issuerauth_alg_values\": [-7], \"deviceauth_alg_values\": [-7]} ✓")
	})
}
