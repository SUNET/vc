package openid4vci

import (
	"testing"
	"vc/internal/gen/issuer/apiv1_issuer"

	"github.com/stretchr/testify/assert"
)

var mockProofJWT ProofJWTToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9wZW5pZDR2Y2ktcHJvb2Yrand0IiwiandrIjp7ImNydiI6IlAtMjU2IiwiZXh0Ijp0cnVlLCJrZXlfb3BzIjpbInZlcmlmeSJdLCJrdHkiOiJFQyIsIngiOiJ1aGZ3M3pyOWJBWTlERDV0QkN0RVVfOVdNaFdvTWFlYVVSNGY3U2dKQzlvIiwieSI6ImJZR2JlV2xWYlJrNktxT1hRX0VUeWxaZ3NKMDR0Nld5UTZiZFhYMHUxV0UifX0.eyJub25jZSI6IiIsImF1ZCI6Imh0dHBzOi8vdmMtaW50ZXJvcC0zLnN1bmV0LnNlIiwiaXNzIjoiMTAwMyIsImlhdCI6MTc1MTM2ODI1NX0.ri7zfnClkmVYFPRxV5IWiatmXHjmDNcd9FGJJNngUFjvDkVIfeYKr-bb_aUXU0DgkesIi8XvyKM149tlP-e6gA"

func TestCredentialValidation(t *testing.T) {
	tts := []struct {
		name              string
		credentialRequest *CredentialRequest
		tokenResponse     *TokenResponse
		want              error
	}{
		{
			name: "test",
			credentialRequest: &CredentialRequest{
				CredentialConfigurationID: "vc+ldp",
			},
			tokenResponse: &TokenResponse{
				AccessToken:     "",
				TokenType:       "",
				ExpiresIn:       0,
				Scope:           "",
				State:           "",
				CNonce:          "",
				CNonceExpiresIn: 0,
				AuthorizationDetails: []AuthorizationDetailsParameter{
					{
						Type:                      "",
						CredentialConfigurationID: "vc+ldp",
						Format:                    "",
						VCT:                       "",
						Claims:                    map[string]any{},
					},
				},
			},
			want: nil,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			got := tt.credentialRequest.Validate(ctx, tt.tokenResponse)
			assert.NoError(t, got)
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
