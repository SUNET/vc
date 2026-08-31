package openid4vci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
	"github.com/SUNET/vc/pkg/bbs"

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
			// Proofs omitted entirely (nil) -- the deprecated singular
			// "proof" field case -- must still be allowed.
			name: "nil proofs is allowed (deprecated singular proof field)",
			credentialRequest: &CredentialRequest{
				CredentialConfigurationID: "vc+ldp",
				Proofs:                    nil,
			},
			authorizationDetails: nil,
			wantErr:              false,
		},
		{
			// An explicitly-present but entirely empty proofs object
			// declares zero proof types, which is exactly as invalid as
			// declaring more than one -- must be rejected, matching
			// VerifyProofWithOptions's existing behavior.
			name: "explicitly empty proofs object is rejected",
			credentialRequest: &CredentialRequest{
				CredentialConfigurationID: "vc+ldp",
				Proofs:                    &Proofs{},
			},
			authorizationDetails: nil,
			wantErr:              true,
			errContains:          "proofs must declare exactly one proof type",
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
			name: "authorization_details flow with credential_configuration_id only",
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
			errContains: "credential_configuration_id must not be used when authorization_details",
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
			errContains: "must not both be present",
		},
		{
			name: "scope-based flow with unknown credential_identifier",
			credentialRequest: &CredentialRequest{
				CredentialIdentifier: "some-id",
			},
			authorizationDetails: nil,
			wantErr:              true,
			errContains:          "cannot be resolved",
		},
		{
			name: "scope-based flow with both identifier and configuration_id",
			credentialRequest: &CredentialRequest{
				CredentialConfigurationID: "vc+ldp",
				CredentialIdentifier:      "some-id",
			},
			authorizationDetails: nil,
			wantErr:              true,
			errContains:          "must not both be present",
		},
		{
			name: "credential_identifier matches second authorization_details entry",
			credentialRequest: &CredentialRequest{ // #nosec G101
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
		proofs := &Proofs{Attestation: []ProofAttestation{attestation}}
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
		proofs := &Proofs{Attestation: []ProofAttestation{attestation}}
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
		proofs := &Proofs{Attestation: []ProofAttestation{attestation}}
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
		proofs := &Proofs{Attestation: []ProofAttestation{ProofAttestation("some.jwt.token")}}
		assert.NotEmpty(t, proofs.Attestation)
	})

	t.Run("empty proofs count", func(t *testing.T) {
		proofs := &Proofs{}
		assert.Equal(t, 0, len(proofs.JWT)+len(proofs.DIVP)+len(proofs.Attestation))
	})
}

func TestResolveCredentialFormat(t *testing.T) {
	tests := []struct {
		name                 string
		request              *CredentialRequest
		metadata             *CredentialIssuerMetadataParameters
		authorizationDetails []AuthorizationDetailsParameter
		wantFormat           string
		wantErr              bool
		errContains          string
	}{
		{
			name: "resolve by credential_configuration_id",
			request: &CredentialRequest{ // #nosec G101
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
			name: "resolve by credential_identifier via authorization_details",
			request: &CredentialRequest{ // #nosec G101
				CredentialIdentifier: "ehic_identifier",
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{
					"ehic_config": {
						Format: "mso_mdoc",
					},
				},
			},
			authorizationDetails: []AuthorizationDetailsParameter{
				{
					Type:                      "openid_credential",
					CredentialConfigurationID: "ehic_config",
					CredentialIdentifiers:     []string{"ehic_identifier"},
				},
			},
			wantFormat: "mso_mdoc",
			wantErr:    false,
		},
		{
			name: "error for unknown credential_identifier",
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
			authorizationDetails: []AuthorizationDetailsParameter{
				{
					Type:                      "openid_credential",
					CredentialConfigurationID: "pid_config",
					CredentialIdentifiers:     []string{"other_identifier"},
				},
			},
			wantErr:     true,
			errContains: "could not resolve credential_identifier",
		},
		{
			name: "error when metadata is nil",
			request: &CredentialRequest{ // #nosec G101
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
			request: &CredentialRequest{ // #nosec G101
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
			request: &CredentialRequest{ // #nosec G101
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
		{
			name: "resolve by credential_identifier via format-based authorization_details",
			request: &CredentialRequest{
				CredentialIdentifier: "format_based_id",
			},
			metadata: &CredentialIssuerMetadataParameters{
				CredentialConfigurationsSupported: map[string]CredentialConfigurationsSupported{},
			},
			authorizationDetails: []AuthorizationDetailsParameter{
				{
					Type:                  "openid_credential",
					Format:                "vc+sd-jwt",
					VCT:                   "VerifiablePortableDocumentA1",
					CredentialIdentifiers: []string{"format_based_id"},
				},
			},
			wantFormat: "vc+sd-jwt",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format, err := tt.request.ResolveCredentialFormatWithAuthDetails(tt.metadata, tt.authorizationDetails)

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

// A commitment that cannot be decoded must be rejected at the request
// boundary, where the error can say the transport encoding was wrong,
// rather than deeper in where it surfaces as an opaque verification
// failure.
func TestCredentialRequestValidatesBBSCommitment(t *testing.T) {
	base := func() *CredentialRequest {
		return &CredentialRequest{
			Authorization:             "Bearer x",
			CredentialConfigurationID: "cfg",
		}
	}

	t.Run("absent is fine", func(t *testing.T) {
		if err := base().Validate(context.Background(), nil); err != nil {
			t.Fatalf("a request without a commitment must still validate: %v", err)
		}
	})

	t.Run("valid base64url accepted", func(t *testing.T) {
		r := base()
		r.BBSCommitment = "AQIDBAU"
		r.BBSSuite = bbs.SuiteNameSchnorr
		if err := r.Validate(context.Background(), nil); err != nil {
			t.Fatalf("valid commitment rejected: %v", err)
		}
	})

	for _, tc := range []struct{ name, value string }{
		{"not base64url", "!!!!"},
		{"standard base64 alphabet", "a+/b=="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			r.BBSCommitment = tc.value
			r.BBSSuite = bbs.SuiteNameSchnorr
			err := r.Validate(context.Background(), nil)
			if err == nil {
				t.Fatalf("accepted %q", tc.value)
			}
			// The description is what a wallet developer reads, so it has
			// to name the member they sent - `bbs_commitment` - rather than
			// pass bbs.DecodeCommitment's wording through. That message is
			// written for Go callers, says "commitment", and would tie this
			// endpoint's response text to an internal package.
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("want *Error, got %T", err)
			}
			description, _ := e.ErrorDescription.(string)
			if !strings.Contains(description, "bbs_commitment") {
				t.Fatalf("error_description must name the wire member, got %q", description)
			}
			if strings.Contains(description, "bbs:") {
				t.Fatalf("internal package wording reached the wire: %q", description)
			}
		})
	}
}

// A commitment with no committed claims is legitimate rather than a mistake:
// it is what a wallet sends when it binds a credential to a device key
// without hiding any of its own values. BBSCommittedClaims' doc comment used
// to call it "required with" the commitment, which said the opposite of what
// this has always validated.
func TestCredentialRequestAcceptsACommitmentWithNoCommittedClaims(t *testing.T) {
	r := &CredentialRequest{
		Authorization:             "Bearer x",
		CredentialConfigurationID: "cfg",
		BBSCommitment:             "AQIDBAU",
		BBSSuite:                  bbs.SuiteNameSchnorr,
		BBSKeyBinding:             true,
	}
	if err := r.Validate(context.Background(), nil); err != nil {
		t.Fatalf("a commitment carrying only key binding keys must validate: %v", err)
	}
}

// The blind-BBS request members carry things the issuer cannot derive and
// cannot check later. A commitment names messages the issuer never sees; the
// pointers say where they go; the key binding flag selects the message
// layout. Each is rejected at the request boundary, where the error can name
// the member, rather than deeper in where all three surface identically as
// "does not verify".
func TestCredentialRequestValidatesBBSMembers(t *testing.T) {
	base := func() *CredentialRequest {
		return &CredentialRequest{
			Authorization:             "Bearer x",
			CredentialConfigurationID: "cfg",
		}
	}
	const validCommitment = "AQIDBAU"

	t.Run("committed claims without a commitment", func(t *testing.T) {
		// Pointers alone name claims nothing committed to. Ignoring them
		// would issue a credential whose claim map promises holder claims
		// the signature does not cover.
		r := base()
		r.BBSCommittedClaims = []string{"/device_pin_hash"}
		if err := r.Validate(context.Background(), nil); err == nil {
			t.Fatal("bbs_committed_claims without bbs_commitment must be rejected")
		}
	})

	t.Run("key binding without a commitment", func(t *testing.T) {
		// The flag selects a layout for a commitment that is not there.
		r := base()
		r.BBSKeyBinding = true
		if err := r.Validate(context.Background(), nil); err == nil {
			t.Fatal("bbs_key_binding without bbs_commitment must be rejected")
		}
	})

	t.Run("commitment with pointers accepted", func(t *testing.T) {
		r := base()
		r.BBSCommitment = validCommitment
		r.BBSSuite = bbs.SuiteNameSchnorr
		r.BBSCommittedClaims = []string{"/device_pin_hash", "/recovery_secret"}
		r.BBSKeyBinding = true
		if err := r.Validate(context.Background(), nil); err != nil {
			t.Fatalf("a well-formed blind BBS request was rejected: %v", err)
		}
	})

	t.Run("commitment alone accepted", func(t *testing.T) {
		// An issuance where the holder contributes no claims of its own is
		// still blind issuance - the commitment can carry key binding keys
		// and no messages.
		r := base()
		r.BBSCommitment = validCommitment
		r.BBSSuite = bbs.SuiteNameSchnorr
		if err := r.Validate(context.Background(), nil); err != nil {
			t.Fatalf("a commitment with no holder claims was rejected: %v", err)
		}
	})

	for _, tc := range []struct {
		name    string
		claims  []string
		because string
	}{
		{"empty pointer", []string{""}, "names the whole document, not a claim"},
		{"pointer without a leading slash", []string{"device_pin_hash"}, "is not an RFC 6901 pointer"},
		{"duplicate pointer", []string{"/a", "/a"}, "would put two messages in one claim map position"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			r.BBSCommitment = validCommitment
			r.BBSSuite = bbs.SuiteNameSchnorr
			r.BBSSuite = bbs.SuiteNameSchnorr
			r.BBSCommittedClaims = tc.claims
			if err := r.Validate(context.Background(), nil); err == nil {
				t.Fatalf("%v must be rejected: it %s", tc.claims, tc.because)
			}
		})
	}

	t.Run("more pointers than the message limit", func(t *testing.T) {
		r := base()
		r.BBSCommitment = validCommitment
		r.BBSSuite = bbs.SuiteNameSchnorr
		r.BBSCommittedClaims = make([]string, bbs.MaxMessages+1)
		for i := range r.BBSCommittedClaims {
			r.BBSCommittedClaims[i] = fmt.Sprintf("/claim_%d", i)
		}
		if err := r.Validate(context.Background(), nil); err == nil {
			t.Fatalf("more than %d committed claims must be rejected", bbs.MaxMessages)
		}
	})
}

// The suite selects the domain separation the commitment was built under.
// Holder and issuer must agree or nothing verifies, and a wrong guess is
// indistinguishable from a corrupt commitment, a wrong issuer key, or a
// tampered proof — so it is carried explicitly and required, not defaulted.
func TestCredentialRequestValidatesBBSSuite(t *testing.T) {
	base := func() *CredentialRequest {
		return &CredentialRequest{
			Authorization:             "Bearer x",
			CredentialConfigurationID: "cfg",
			BBSCommitment:             "AQIDBAU",
		}
	}

	t.Run("both suites are accepted", func(t *testing.T) {
		// Plain is a first-class choice, not a legacy value: an issuance
		// with no device binding at all is a real configuration.
		for _, name := range []string{bbs.SuiteNamePlain, bbs.SuiteNameSchnorr} {
			r := base()
			r.BBSSuite = name
			if err := r.Validate(context.Background(), nil); err != nil {
				t.Fatalf("suite %q was rejected: %v", name, err)
			}
		}
	})

	t.Run("a commitment without a suite is rejected", func(t *testing.T) {
		if err := base().Validate(context.Background(), nil); err == nil {
			t.Fatal("bbs_commitment without bbs_suite must be rejected rather than defaulted")
		}
	})

	t.Run("a suite without a commitment is rejected", func(t *testing.T) {
		r := base()
		r.BBSCommitment = ""
		r.BBSSuite = bbs.SuiteNameSchnorr
		if err := r.Validate(context.Background(), nil); err == nil {
			t.Fatal("bbs_suite alone names the domain separation of nothing")
		}
	})

	for _, name := range []string{"", "SCHNORR", "Plain", "bbs", "1"} {
		t.Run("unknown suite "+strconv.Quote(name), func(t *testing.T) {
			r := base()
			r.BBSSuite = name
			if err := r.Validate(context.Background(), nil); err == nil {
				t.Fatalf("%q is not a suite this issuer knows", name)
			}
		})
	}

	// "plain" is the suite with no device binding, so a request asking for
	// both is describing two different things. The native side would refuse
	// it anyway, but from deeper in and about the commitment rather than
	// about the two members that disagree.
	t.Run("plain with key binding is a contradiction", func(t *testing.T) {
		r := base()
		r.BBSSuite = bbs.SuiteNamePlain
		r.BBSKeyBinding = true
		if err := r.Validate(context.Background(), nil); err == nil {
			t.Fatal("bbs_suite plain with bbs_key_binding must be rejected")
		}
	})

	// The pairing that looks wrong and is not: an unbound issuance under
	// the schnorr suite is what the wallet does today, and deriving the
	// suite from key binding would break exactly this case.
	t.Run("schnorr without key binding is the ordinary unbound issuance", func(t *testing.T) {
		r := base()
		r.BBSSuite = bbs.SuiteNameSchnorr
		r.BBSKeyBinding = false
		if err := r.Validate(context.Background(), nil); err != nil {
			t.Fatalf("schnorr with no key binding keys must be allowed: %v", err)
		}
	})
}

func TestParseSuiteRoundTrips(t *testing.T) {
	for _, s := range []bbs.Suite{bbs.SuitePlain, bbs.SuiteSchnorr} {
		got, err := bbs.ParseSuite(s.String())
		if err != nil || got != s {
			t.Fatalf("%v did not round-trip through its wire name: %v %v", s, got, err)
		}
	}
}
