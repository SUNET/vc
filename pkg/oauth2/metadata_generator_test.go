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
			cfg: &MetadataConfig{
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
				assert.Contains(t, metadata.TokenEndpointAuthMethodsSupported, "none")
				assert.Contains(t, metadata.ResponseTypesSupported, "code")
				assert.Contains(t, metadata.CodeChallengeMethodsSupported, "S256")
				assert.Contains(t, metadata.DPOPSigningALGValuesSupported, "ES256")
			},
		},
		{
			name: "different issuer URL",
			cfg: &MetadataConfig{
				IssuerURL:     "https://auth.company.com",
				TokenEndpoint: "https://auth.company.com/oauth/token",
			},
			verify: func(t *testing.T, metadata *AuthorizationServerMetadata) {
				assert.Equal(t, "https://auth.company.com", metadata.Issuer)
				assert.Equal(t, "https://auth.company.com/oauth/token", metadata.TokenEndpoint)
				assert.Equal(t, "https://auth.company.com/authorize", metadata.AuthorizationEndpoint)
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
