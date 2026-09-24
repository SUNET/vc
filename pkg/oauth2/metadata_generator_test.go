package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateMetadata(t *testing.T) {
	tests := []struct {
		name   string
		cfg    *MetadataConfig
		verify func(*testing.T, *AuthorizationServerMetadata)
	}{
		{
			name: "basic metadata generation",
			cfg: &MetadataConfig{ // #nosec G101
				IssuerURL:     "https://issuer.example.com",
				TokenEndpoint: "https://issuer.example.com/token",
			},
			verify: func(t *testing.T, metadata *AuthorizationServerMetadata) {
				assert.Equal(t, "https://issuer.example.com", metadata.Issuer)
				assert.Equal(t, "https://issuer.example.com/token", metadata.TokenEndpoint)
				assert.Equal(t, "https://issuer.example.com/authorize", metadata.AuthorizationEndpoint)
				assert.Equal(t, "https://issuer.example.com/op/par", metadata.PushedAuthorizationRequestEndpoint)
				assert.Equal(t, "https://issuer.example.com/jwks", metadata.JWKSURI)
				assert.True(t, metadata.RequiredPushedAuthorizationRequests)
				assert.NotContains(t, metadata.TokenEndpointAuthMethodsSupported, "attest_jwt_client_auth")
				assert.Contains(t, metadata.TokenEndpointAuthMethodsSupported, "none")
				assert.Empty(t, metadata.ClientAttestationSigningALGValuesSupported)
				assert.Empty(t, metadata.ClientAttestationPoPSigningALGValuesSupported)
				assert.Contains(t, metadata.ResponseTypesSupported, "code")
				assert.Contains(t, metadata.CodeChallengeMethodsSupported, "S256")
				assert.Contains(t, metadata.DPOPSigningALGValuesSupported, "ES256")
			},
		},
		{
			name: "different issuer URL",
			cfg: &MetadataConfig{ // #nosec G101
				IssuerURL:     "https://auth.company.com",
				TokenEndpoint: "https://auth.company.com/oauth/token",
			},
			verify: func(t *testing.T, metadata *AuthorizationServerMetadata) {
				assert.Equal(t, "https://auth.company.com", metadata.Issuer)
				assert.Equal(t, "https://auth.company.com/oauth/token", metadata.TokenEndpoint)
				assert.Equal(t, "https://auth.company.com/authorize", metadata.AuthorizationEndpoint)
			},
		},
		{
			name: "wallet attestation enabled advertises attest_jwt_client_auth",
			cfg: &MetadataConfig{ // #nosec G101
				IssuerURL:                "https://issuer.example.com",
				TokenEndpoint:            "https://issuer.example.com/token",
				WalletAttestationEnabled: true,
			},
			verify: func(t *testing.T, metadata *AuthorizationServerMetadata) {
				assert.Contains(t, metadata.TokenEndpointAuthMethodsSupported, "attest_jwt_client_auth")
				assert.Contains(t, metadata.TokenEndpointAuthMethodsSupported, "none")
				assert.Contains(t, metadata.ClientAttestationSigningALGValuesSupported, "ES256")
				assert.Contains(t, metadata.ClientAttestationPoPSigningALGValuesSupported, "ES256")
			},
		},
		{
			name: "wallet attestation disabled omits attest_jwt_client_auth",
			cfg: &MetadataConfig{ // #nosec G101
				IssuerURL:                "https://issuer.example.com",
				TokenEndpoint:            "https://issuer.example.com/token",
				WalletAttestationEnabled: false,
			},
			verify: func(t *testing.T, metadata *AuthorizationServerMetadata) {
				assert.NotContains(t, metadata.TokenEndpointAuthMethodsSupported, "attest_jwt_client_auth")
				assert.Equal(t, []string{"none"}, metadata.TokenEndpointAuthMethodsSupported)
				assert.Empty(t, metadata.ClientAttestationSigningALGValuesSupported)
				assert.Empty(t, metadata.ClientAttestationPoPSigningALGValuesSupported)
			},
		},
		{
			name: "wallet attestation narrowed by AllowedSignatureAlgorithms",
			cfg: &MetadataConfig{ // #nosec G101
				IssuerURL:                  "https://issuer.example.com",
				TokenEndpoint:              "https://issuer.example.com/token",
				WalletAttestationEnabled:   true,
				AllowedSignatureAlgorithms: []string{"ES256", "RS256"},
			},
			verify: func(t *testing.T, metadata *AuthorizationServerMetadata) {
				assert.Equal(t, []string{"ES256"}, metadata.ClientAttestationSigningALGValuesSupported)
				assert.Equal(t, []string{"ES256"}, metadata.ClientAttestationPoPSigningALGValuesSupported)
			},
		},
		{
			name: "wallet attestation with empty AllowedSignatureAlgorithms keeps full base set",
			cfg: &MetadataConfig{ // #nosec G101
				IssuerURL:                "https://issuer.example.com",
				TokenEndpoint:            "https://issuer.example.com/token",
				WalletAttestationEnabled: true,
			},
			verify: func(t *testing.T, metadata *AuthorizationServerMetadata) {
				assert.Equal(t, []string{"ES256", "ES384", "ES512"}, metadata.ClientAttestationSigningALGValuesSupported)
				assert.Equal(t, []string{"ES256", "ES384", "ES512"}, metadata.ClientAttestationPoPSigningALGValuesSupported)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := GenerateMetadata(tt.cfg)
			require.NotNil(t, metadata)
			tt.verify(t, metadata)
		})
	}
}
