package model

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/sdjwtvc"

	"github.com/stretchr/testify/require"
)

func proofTypesCredMeta() map[string]*CredentialMetadata {
	return map[string]*CredentialMetadata{
		"pid": {
			VCTM:   &sdjwtvc.VCTM{VCT: "urn:eudi:pid:1"},
			VCTURL: "https://issuer.sunet.se/type-metadata/pid",
			Format: "dc+sd-jwt",
		},
	}
}

func generateFor(t *testing.T, cfg *IssuerMetadata) openid4vci.CredentialConfigurationsSupported {
	t.Helper()
	metadata, err := cfg.Generate(context.Background(), "https://issuer.sunet.se", proofTypesCredMeta())
	require.NoError(t, err)
	credConfig, ok := metadata.CredentialConfigurationsSupported["pid"]
	require.True(t, ok)
	return credConfig
}

// OpenID4VCI 1.0 12.2.4 on key_attestations_required: "If the Credential
// Issuer does not require a key attestation, this parameter MUST NOT be
// present in the metadata. If both key_storage and user_authentication
// parameters are absent, the key_attestations_required parameter may be
// empty, indicating a key attestation is needed without additional
// constraints."
//
// So `{}` is not the neutral value - it asserts an unconstrained
// requirement. This issuer accepts a plain "jwt" proof carrying no
// attestation, so claiming the requirement was untrue, and it was claimed
// on every credential configuration. The field was emitted unconditionally
// to satisfy eudi-lib-jvm-openid4vci-kt 0.12.1, which rejects metadata
// without it - a lagging implementation rather than the specification.
func TestKeyAttestationsRequiredIsAbsentUnlessConfigured(t *testing.T) {
	t.Run("absent by default", func(t *testing.T) {
		credConfig := generateFor(t, &IssuerMetadata{})
		for proofType, proof := range credConfig.ProofTypesSupported {
			require.Nil(t, proof.KeyAttestationsRequired,
				"proof type %q must not claim a key attestation this issuer does not require", proofType)
		}

		// Asserted on the wire too: a non-pointer field with no omitempty
		// serialized as `{}` however it was set, so the Go-level check
		// above would have passed while the JSON still made the claim.
		encoded, err := json.Marshal(credConfig)
		require.NoError(t, err)
		require.NotContains(t, string(encoded), "key_attestations_required",
			"the parameter MUST NOT be present when no attestation is required")
	})

	t.Run("present when a deployment configures it", func(t *testing.T) {
		credConfig := generateFor(t, &IssuerMetadata{
			KeyAttestationsRequired: &openid4vci.KeyAttestationRequirement{},
		})
		for proofType, proof := range credConfig.ProofTypesSupported {
			require.NotNil(t, proof.KeyAttestationsRequired,
				"proof type %q should carry the configured requirement", proofType)
		}

		encoded, err := json.Marshal(credConfig)
		require.NoError(t, err)
		require.Contains(t, string(encoded), `"key_attestations_required":{}`,
			"an empty object is the spec's way of saying 'required, no constraints'")
	})

	t.Run("constraints survive", func(t *testing.T) {
		credConfig := generateFor(t, &IssuerMetadata{
			KeyAttestationsRequired: &openid4vci.KeyAttestationRequirement{
				KeyStorage:         []string{"iso_18045_high"},
				UserAuthentication: []string{"iso_18045_high"},
			},
		})
		for _, proof := range credConfig.ProofTypesSupported {
			require.NotNil(t, proof.KeyAttestationsRequired)
			require.Equal(t, []string{"iso_18045_high"}, proof.KeyAttestationsRequired.KeyStorage)
		}
	})
}

// proof_types_supported is OPTIONAL in 12.2.4 and the spec never requires
// advertising more than one type. Both are implemented here - attestation
// proofs are signature-verified against the x5c in their own header - so
// the default advertises both, and a deployment narrows it only for a
// wallet that cannot cope with one (SUNET/vc#671).
func TestProofTypesSupportedDefaultsToWhatIsImplemented(t *testing.T) {
	t.Run("both by default", func(t *testing.T) {
		credConfig := generateFor(t, &IssuerMetadata{})
		require.ElementsMatch(t, []string{"jwt", "attestation"}, keysOf(credConfig.ProofTypesSupported))
	})

	t.Run("narrowed by configuration", func(t *testing.T) {
		credConfig := generateFor(t, &IssuerMetadata{ProofTypesSupported: []string{"jwt"}})
		require.Equal(t, []string{"jwt"}, keysOf(credConfig.ProofTypesSupported),
			"a deployment targeting a wallet with incomplete attestation support advertises only jwt")
	})

	// The signing algorithms must reach every advertised type, or a wallet
	// reading the narrowed metadata finds a proof type it cannot sign for.
	t.Run("algorithms reach each advertised type", func(t *testing.T) {
		credConfig := generateFor(t, &IssuerMetadata{
			ProofSigningAlgValuesSupported: []string{"ES256"},
			ProofTypesSupported:            []string{"jwt", "attestation"},
		})
		for proofType, proof := range credConfig.ProofTypesSupported {
			require.Equal(t, []string{"ES256"}, proof.ProofSigningAlgValuesSupported,
				"proof type %q lost its algorithms", proofType)
		}
	})
}

func keysOf(m map[string]openid4vci.ProofsTypesSupported) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
