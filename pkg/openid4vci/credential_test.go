package openid4vci

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var mockProofJWT ProofJWTToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0IiwiandrIjp7ImNydiI6IlAtMjU2IiwiZXh0Ijp0cnVlLCJrZXlfb3BzIjpbInZlcmlmeSJdLCJrdHkiOiJFQyIsIngiOiJ1aGZ3M3pyOWJBWTlERDV0QkN0RVVfOVdNaFdvTWFlYVVSNGY3U2dKQzlvIiwieSI6ImJZR2JlV2xWYlJrNktxT1hRX0VUeWxaZ3NKMDR0Nld5UTZiZFhYMHUxV0UifX0.eyJub25jZSI6IiIsImF1ZCI6Imh0dHBzOi8vdmMtaW50ZXJvcC0zLnN1bmV0LnNlIiwiaXNzIjoiMTAwMyIsImlhdCI6MTc1MTM2ODI1NX0.ri7zfnClkmVYFPRxV5IWiatmXHjmDNcd9FGJJNngUFjvDkVIfeYKr-bb_aUXU0DgkesIi8XvyKM149tlP-e6gA"

// build an unsigned key-attestation JWT containing the
// given attested_keys. ExtractAllJWKs uses ParseUnverified, so the signature
// segment is a placeholder and does not need to be valid.
func makeTestAttestationJWT(t *testing.T, keys []map[string]any) ProofAttestation {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "ES256", "typ": "key-attestation+jwt"})
	require.NoError(t, err)
	claims, err := json.Marshal(map[string]any{"iat": int64(1234567890), "attested_keys": keys})
	require.NoError(t, err)
	h := base64.RawURLEncoding.EncodeToString(header)
	c := base64.RawURLEncoding.EncodeToString(claims)
	return ProofAttestation(h + "." + c + ".fakeSig")
}

func TestCredentialValidation(t *testing.T) {
	tts := []struct {
		name                 string
		credentialRequest    *CredentialRequest
		authorizationDetails []AuthorizationDetailsParameter
		wantErr              bool
		errContains          string
	}{
		{
			name: "scope-based flow with credential_configuration_id",
			credentialRequest: &CredentialRequest{
				CredentialConfigurationID: "vc+ldp",
			},
			authorizationDetails: nil,
			wantErr:              false,
		},
		{
			name: "authorization_details flow with valid credential_identifier",
			credentialRequest: &CredentialRequest{
				CredentialIdentifier: "cred-id-1",
			},
			authorizationDetails: []AuthorizationDetailsParameter{
				{
					Type:                      "openid_credential",
					CredentialConfigurationID: "vc+ldp",
					CredentialIdentifiers:     []string{"cred-id-1"},
				},
			},
			wantErr: false,
		},
		{
			name: "authorization_details flow with unknown credential_identifier",
			credentialRequest: &CredentialRequest{
				CredentialIdentifier: "unknown-id",
			},
			authorizationDetails: []AuthorizationDetailsParameter{
				{
					Type:                      "openid_credential",
					CredentialConfigurationID: "vc+ldp",
					CredentialIdentifiers:     []string{"cred-id-1"},
				},
			},
			wantErr:     true,
			errContains: "not found in Token Response",
		},
		{
			name: "authorization_details flow without credential_identifier",
			credentialRequest: &CredentialRequest{
				CredentialConfigurationID: "vc+ldp",
			},
			authorizationDetails: []AuthorizationDetailsParameter{
				{
					Type:                      "openid_credential",
					CredentialConfigurationID: "vc+ldp",
					CredentialIdentifiers:     []string{"cred-id-1"},
				},
			},
			wantErr:     true,
			errContains: "credential_identifier is required",
		},
		{
			name: "authorization_details flow with both identifier and configuration_id",
			credentialRequest: &CredentialRequest{
				CredentialIdentifier:      "cred-id-1",
				CredentialConfigurationID: "vc+ldp",
			},
			authorizationDetails: []AuthorizationDetailsParameter{
				{
					Type:                      "openid_credential",
					CredentialConfigurationID: "vc+ldp",
					CredentialIdentifiers:     []string{"cred-id-1"},
				},
			},
			wantErr:     true,
			errContains: "credential_configuration_id must not be present",
		},
		{
			name: "scope-based flow without credential_configuration_id",
			credentialRequest: &CredentialRequest{
				CredentialIdentifier: "some-id",
			},
			authorizationDetails: nil,
			wantErr:              true,
			errContains:          "credential_configuration_id is required",
		},
		{
			name: "scope-based flow with both identifier and configuration_id",
			credentialRequest: &CredentialRequest{
				CredentialConfigurationID: "vc+ldp",
				CredentialIdentifier:      "some-id",
			},
			authorizationDetails: nil,
			wantErr:              true,
			errContains:          "credential_identifier must not be present",
		},
		{
			name: "credential_identifier matches second authorization_details entry",
			credentialRequest: &CredentialRequest{
				CredentialIdentifier: "cred-id-2",
			},
			authorizationDetails: []AuthorizationDetailsParameter{
				{
					Type:                      "openid_credential",
					CredentialConfigurationID: "config-a",
					CredentialIdentifiers:     []string{"cred-id-1"},
				},
				{
					Type:                      "openid_credential",
					CredentialConfigurationID: "config-b",
					CredentialIdentifiers:     []string{"cred-id-2", "cred-id-3"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			err := tt.credentialRequest.Validate(ctx, tt.authorizationDetails)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHashAuthorizeToken(t *testing.T) {
	tts := []struct {
		name     string
		request  CredentialRequest
		expected string
	}{
		{
			name: "test",
			request: CredentialRequest{
				Authorization: "DPoP yRPOM7mz7sPllePuy3oka7k1uJtdy1q97zjxaT4y11I=",
			},
			expected: "dHN_VHc7eNSICfPTvtw4gr_8XIH7g91jo8_Bq2bmAcc",
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.request.HashAuthorizeToken()
			assert.Equal(t, tt.expected, got, "HashAuthorizeToken should return expected value")
		})
	}
}

func TestExtractJWK(t *testing.T) {
	tts := []struct {
		name string
		have *Proofs
		want *apiv1_issuer.Jwk
	}{
		{
			name: "test",
			have: &Proofs{
				JWT: []ProofJWTToken{mockProofJWT},
			},
			want: &apiv1_issuer.Jwk{
				Crv:    "P-256",
				Kty:    "EC",
				X:      "uhfw3zr9bAY9DD5tBCtEU_9WMhWoMaeaUR4f7SgJC9o",
				Y:      "bYGbeWlVbRk6KqOXQ_ETylZgsJ04t6WyQ6bdXX0u1WE",
				KeyOps: []string{"verify"},
				Ext:    true,
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.have.ExtractJWK()
			assert.NoError(t, err, "ExtractJWK should not return an error")
			assert.NotNil(t, got, "JWK should not be nil")
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractAllJWKs(t *testing.T) {
	expectedJWK := &apiv1_issuer.Jwk{
		Crv:    "P-256",
		Kty:    "EC",
		X:      "uhfw3zr9bAY9DD5tBCtEU_9WMhWoMaeaUR4f7SgJC9o",
		Y:      "bYGbeWlVbRk6KqOXQ_ETylZgsJ04t6WyQ6bdXX0u1WE",
		KeyOps: []string{"verify"},
		Ext:    true,
	}

	t.Run("single JWT proof", func(t *testing.T) {
		proofs := &Proofs{JWT: []ProofJWTToken{mockProofJWT}}
		jwks, err := proofs.ExtractAllJWKs(1)
		assert.NoError(t, err)
		assert.Len(t, jwks, 1)
		assert.Equal(t, expectedJWK, jwks[0])
	})

	t.Run("multiple JWT proofs", func(t *testing.T) {
		proofs := &Proofs{JWT: []ProofJWTToken{mockProofJWT, mockProofJWT, mockProofJWT}}
		jwks, err := proofs.ExtractAllJWKs(3)
		assert.NoError(t, err)
		assert.Len(t, jwks, 3)
		for i, jwk := range jwks {
			assert.Equal(t, expectedJWK, jwk, "JWK at index %d should match", i)
		}
	})

	t.Run("empty proofs", func(t *testing.T) {
		proofs := &Proofs{}
		jwks, err := proofs.ExtractAllJWKs(1)
		assert.Error(t, err)
		assert.Nil(t, jwks)
		assert.Contains(t, err.Error(), "no proofs provided")
	})

	didKey1 := "did:example:123#key-1"
	didKey2 := "did:example:456#key-2"

	t.Run("single DIVP proof", func(t *testing.T) {
		proofs := &Proofs{DIVP: []ProofDIVP{
			{Proof: &DIVPProof{VerificationMethod: didKey1}},
		}}
		jwks, err := proofs.ExtractAllJWKs(1)
		assert.NoError(t, err)
		assert.Len(t, jwks, 1)
		assert.Equal(t, &apiv1_issuer.Jwk{Kid: didKey1}, jwks[0])
	})

	t.Run("multiple DIVP proofs", func(t *testing.T) {
		proofs := &Proofs{DIVP: []ProofDIVP{
			{Proof: &DIVPProof{VerificationMethod: didKey1}},
			{Proof: &DIVPProof{VerificationMethod: didKey2}},
		}}
		jwks, err := proofs.ExtractAllJWKs(2)
		assert.NoError(t, err)
		assert.Len(t, jwks, 2)
		assert.Equal(t, &apiv1_issuer.Jwk{Kid: didKey1}, jwks[0])
		assert.Equal(t, &apiv1_issuer.Jwk{Kid: didKey2}, jwks[1])
	})

	t.Run("attestation with single attested key", func(t *testing.T) {
		attestation := makeTestAttestationJWT(t, []map[string]any{
			{"kty": "EC", "crv": "P-256", "x": "key1x", "y": "key1y"},
		})
		proofs := &Proofs{Attestation: attestation}
		jwks, err := proofs.ExtractAllJWKs(1)
		assert.NoError(t, err)
		assert.Len(t, jwks, 1)
		assert.Equal(t, "EC", jwks[0].Kty)
		assert.Equal(t, "P-256", jwks[0].Crv)
		assert.Equal(t, "key1x", jwks[0].X)
		assert.Equal(t, "key1y", jwks[0].Y)
	})

	t.Run("attestation with multiple attested keys", func(t *testing.T) {
		// This is the critical regression test: Count() returns 1 for any attestation
		// but ExtractAllJWKs returns one JWK per key, so batch-size enforcement
		// must validate len(jwks) rather than Count().
		attestation := makeTestAttestationJWT(t, []map[string]any{
			{"kty": "EC", "crv": "P-256", "x": "key1x", "y": "key1y"},
			{"kty": "EC", "crv": "P-256", "x": "key2x", "y": "key2y"},
			{"kty": "EC", "crv": "P-256", "x": "key3x", "y": "key3y"},
		})
		proofs := &Proofs{Attestation: attestation}
		jwks, err := proofs.ExtractAllJWKs(3)
		assert.NoError(t, err)
		assert.Len(t, jwks, 3)
		assert.Equal(t, "key1x", jwks[0].X)
		assert.Equal(t, "key2x", jwks[1].X)
		assert.Equal(t, "key3x", jwks[2].X)
	})

	t.Run("JWT proofs exceeding maxLength", func(t *testing.T) {
		proofs := &Proofs{JWT: []ProofJWTToken{mockProofJWT, mockProofJWT, mockProofJWT}}
		jwks, err := proofs.ExtractAllJWKs(2)
		assert.Error(t, err)
		assert.Nil(t, jwks)
		assert.Contains(t, err.Error(), "exceeds")
	})

	t.Run("DIVP proofs exceeding maxLength", func(t *testing.T) {
		proofs := &Proofs{DIVP: []ProofDIVP{
			{Proof: &DIVPProof{VerificationMethod: didKey1}},
			{Proof: &DIVPProof{VerificationMethod: didKey2}},
		}}
		jwks, err := proofs.ExtractAllJWKs(1)
		assert.Error(t, err)
		assert.Nil(t, jwks)
		assert.Contains(t, err.Error(), "exceeds")
	})

	t.Run("attestation exceeding maxLength", func(t *testing.T) {
		attestation := makeTestAttestationJWT(t, []map[string]any{
			{"kty": "EC", "crv": "P-256", "x": "key1x", "y": "key1y"},
			{"kty": "EC", "crv": "P-256", "x": "key2x", "y": "key2y"},
			{"kty": "EC", "crv": "P-256", "x": "key3x", "y": "key3y"},
		})
		proofs := &Proofs{Attestation: attestation}
		jwks, err := proofs.ExtractAllJWKs(2)
		assert.Error(t, err)
		assert.Nil(t, jwks)
		assert.Contains(t, err.Error(), "exceeds")
	})
}

func TestProofsCount(t *testing.T) {
	t.Run("JWT proofs count", func(t *testing.T) {
		proofs := &Proofs{JWT: []ProofJWTToken{mockProofJWT, mockProofJWT, mockProofJWT}}
		assert.Equal(t, 3, len(proofs.JWT))
	})

	t.Run("single JWT proof count", func(t *testing.T) {
		proofs := &Proofs{JWT: []ProofJWTToken{mockProofJWT}}
		assert.Equal(t, 1, len(proofs.JWT))
	})

	t.Run("DIVP proofs count", func(t *testing.T) {
		proofs := &Proofs{DIVP: []ProofDIVP{{}, {}}}
		assert.Equal(t, 2, len(proofs.DIVP))
	})

	t.Run("attestation count", func(t *testing.T) {
		proofs := &Proofs{Attestation: ProofAttestation("some.jwt.token")}
		assert.NotEmpty(t, proofs.Attestation)
	})

	t.Run("empty proofs count", func(t *testing.T) {
		proofs := &Proofs{}
		assert.Equal(t, 0, len(proofs.JWT)+len(proofs.DIVP)+len(proofs.Attestation))
	})
}

func TestResolveCredentialFormat(t *testing.T) {
	tests := []struct {
		name        string
		request     *CredentialRequest
		metadata    *CredentialIssuerMetadataParameters
		wantFormat  string
		wantErr     bool
		errContains string
	}{
		{
			name: "resolve by credential_configuration_id",
			request: &CredentialRequest{
				CredentialConfigurationID: "pid_config",
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"pid_config": {
						Format: "dc+sd-jwt",
					},
				},
			},
			wantFormat: "dc+sd-jwt",
			wantErr:    false,
		},
		{
			name: "resolve by credential_identifier",
			request: &CredentialRequest{
				CredentialIdentifier: "ehic_identifier",
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"ehic_identifier": {
						Format: "mso_mdoc",
					},
				},
			},
			wantFormat: "mso_mdoc",
			wantErr:    false,
		},
		{
			name: "fallback to dc+sd-jwt for unknown credential_identifier",
			request: &CredentialRequest{
				CredentialIdentifier: "unknown_identifier",
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"pid_config": {
						Format: "dc+sd-jwt",
					},
				},
			},
			wantFormat: "dc+sd-jwt",
			wantErr:    false,
		},
		{
			name: "error when metadata is nil",
			request: &CredentialRequest{
				CredentialConfigurationID: "pid_config",
			},
			metadata:    nil,
			wantErr:     true,
			errContains: "metadata is required",
		},
		{
			name: "error when credential_configuration_id not found",
			request: &CredentialRequest{
				CredentialConfigurationID: "unknown_config",
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"pid_config": {
						Format: "dc+sd-jwt",
					},
				},
			},
			wantErr:     true,
			errContains: "unknown credential_configuration_id",
		},
		{
			name:    "error when neither credential_configuration_id nor credential_identifier provided",
			request: &CredentialRequest{
				// Both fields empty
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"pid_config": {
						Format: "dc+sd-jwt",
					},
				},
			},
			wantErr:     true,
			errContains: "either credential_configuration_id or credential_identifier must be provided",
		},
		{
			name: "resolve vc+sd-jwt format",
			request: &CredentialRequest{
				CredentialConfigurationID: "vc_config",
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"vc_config": {
						Format: "vc+sd-jwt",
					},
				},
			},
			wantFormat: "vc+sd-jwt",
			wantErr:    false,
		},
		{
			name: "resolve ldp_vc format",
			request: &CredentialRequest{
				CredentialConfigurationID: "ldp_config",
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"ldp_config": {
						Format: "ldp_vc",
					},
				},
			},
			wantFormat: "ldp_vc",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, err := tt.request.ResolveCredentialFormat(tt.metadata)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantFormat, format)
			}
		})
	}
}
