package apiv1

import (
	"testing"
	"vc/pkg/jose"
	"vc/pkg/model"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetDiscoveryMetadata tests the OIDC discovery metadata endpoint
func TestGetDiscoveryMetadata(t *testing.T) {
	ctx := t.Context()

	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			PublicURL: "https://verifier.example.com",
			OIDC: model.OIDCConfig{
				Issuer:      "https://verifier.example.com",
				SubjectType: "public",
				SubjectSalt: "test-salt",
			},
			OpenID4VP: model.OpenID4VPConfig{
				SupportedCredentials: []model.SupportedCredentialConfig{
					{
						VCT:    "https://credentials.example.com/person_id",
						Scopes: []string{"pid"},
					},
					{
						VCT:    "https://credentials.example.com/diploma",
						Scopes: []string{"edu_diploma"},
					},
				},
			},
		},
	}

	client, _ := CreateTestClientWithMock(cfg)

	// Test getting discovery metadata
	metadata, err := client.GetDiscoveryMetadata(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, metadata)

	// Verify basic OIDC fields
	assert.Equal(t, "https://verifier.example.com", metadata.Issuer)
	assert.Equal(t, "https://verifier.example.com/authorize", metadata.AuthorizationEndpoint)
	assert.Equal(t, "https://verifier.example.com/token", metadata.TokenEndpoint)
	assert.Equal(t, "https://verifier.example.com/userinfo", metadata.UserInfoEndpoint)
	assert.Equal(t, "https://verifier.example.com/jwks", metadata.JwksURI)

	// Verify supported features
	assert.Contains(t, metadata.ResponseTypesSupported, "code")
	assert.Contains(t, metadata.SubjectTypesSupported, "public")
	assert.Contains(t, metadata.SubjectTypesSupported, "pairwise")
	assert.Contains(t, metadata.IDTokenSigningAlgValuesSupported, "RS256")
	assert.Contains(t, metadata.IDTokenSigningAlgValuesSupported, "ES256")

	// Verify standard scopes
	assert.Contains(t, metadata.ScopesSupported, "openid")
	assert.Contains(t, metadata.ScopesSupported, "profile")
	assert.Contains(t, metadata.ScopesSupported, "email")

	// Verify configured credential scopes
	assert.Contains(t, metadata.ScopesSupported, "pid")
	assert.Contains(t, metadata.ScopesSupported, "edu_diploma")

	// Verify standard claims
	assert.Contains(t, metadata.ClaimsSupported, "sub")
	assert.Contains(t, metadata.ClaimsSupported, "name")
	assert.Contains(t, metadata.ClaimsSupported, "email")

	// Verify grant types
	assert.Contains(t, metadata.GrantTypesSupported, "authorization_code")
	assert.Contains(t, metadata.GrantTypesSupported, "refresh_token")

	// Verify PKCE support
	assert.Contains(t, metadata.CodeChallengeMethodsSupported, "S256")

	// Verify authentication methods
	assert.Contains(t, metadata.TokenEndpointAuthMethodsSupported, "client_secret_basic")
	assert.Contains(t, metadata.TokenEndpointAuthMethodsSupported, "client_secret_post")
	assert.Contains(t, metadata.TokenEndpointAuthMethodsSupported, "none")
}

// TestGetDiscoveryMetadata_NoCredentials tests discovery metadata with no configured credentials
func TestGetDiscoveryMetadata_NoCredentials(t *testing.T) {
	ctx := t.Context()

	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			PublicURL: "https://verifier.example.com",
			OIDC: model.OIDCConfig{
				Issuer:      "https://verifier.example.com",
				SubjectType: "public",
				SubjectSalt: "test-salt",
			},
			OpenID4VP: model.OpenID4VPConfig{
				SupportedCredentials: []model.SupportedCredentialConfig{},
			},
		},
	}

	client, _ := CreateTestClientWithMock(cfg)

	metadata, err := client.GetDiscoveryMetadata(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, metadata)

	// Should still have standard scopes
	assert.Contains(t, metadata.ScopesSupported, "openid")
	assert.Contains(t, metadata.ScopesSupported, "profile")
	assert.Contains(t, metadata.ScopesSupported, "email")
}

// TestGetDiscoveryMetadata_CustomExternalURL tests with different base URLs
func TestGetDiscoveryMetadata_CustomExternalURL(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name           string
		externalURL    string
		expectedPrefix string
	}{
		{
			name:           "HTTPS URL",
			externalURL:    "https://custom.example.com",
			expectedPrefix: "https://custom.example.com",
		},
		{
			name:           "HTTP localhost",
			externalURL:    "http://localhost:8080",
			expectedPrefix: "http://localhost:8080",
		},
		{
			name:           "URL with path",
			externalURL:    "https://example.com/verifier",
			expectedPrefix: "https://example.com/verifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &model.Cfg{
				Verifier: &model.Verifier{
					PublicURL: tt.externalURL,
					OIDC: model.OIDCConfig{
						Issuer:      tt.externalURL,
						SubjectType: "public",
						SubjectSalt: "test-salt",
					},
					OpenID4VP: model.OpenID4VPConfig{
						SupportedCredentials: []model.SupportedCredentialConfig{},
					},
				},
			}

			client, _ := CreateTestClientWithMock(cfg)

			metadata, err := client.GetDiscoveryMetadata(ctx)
			assert.NoError(t, err)

			assert.Equal(t, tt.expectedPrefix+"/authorize", metadata.AuthorizationEndpoint)
			assert.Equal(t, tt.expectedPrefix+"/token", metadata.TokenEndpoint)
			assert.Equal(t, tt.expectedPrefix+"/userinfo", metadata.UserInfoEndpoint)
			assert.Equal(t, tt.expectedPrefix+"/jwks", metadata.JwksURI)
		})
	}
}

// TestGetJWKS tests the JWKS endpoint
func TestGetJWKS(t *testing.T) {
	ctx := t.Context()

	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			PublicURL: "https://verifier.example.com",
			OIDC: model.OIDCConfig{
				Issuer:      "https://verifier.example.com",
				SubjectType: "public",
				SubjectSalt: "test-salt",
			},
		},
	}

	t.Run("RSA key", func(t *testing.T) {
		client, _ := CreateTestClientWithMock(cfg)

		// Set signing key for testing
		privateKey := generateTestRSAKey(t)
		require.NoError(t, client.SetSigningKeyForTesting(privateKey))

		// Test getting JWKS
		jwks, err := jose.CreateJWKSFromSigner(client.pkiSigner, "")
		assert.NoError(t, err)
		assert.NotNil(t, jwks)

		// Verify JWKS structure
		assert.NotNil(t, jwks.Keys)
		assert.Greater(t, len(jwks.Keys), 0, "JWKS should contain at least one key")

		// Verify first key properties
		key := jwks.Keys[0]
		assert.Equal(t, "RSA", key.Kty, "Key type should be RSA")
		assert.Equal(t, "sig", key.Use, "Key use should be sig")
		assert.Equal(t, "default", key.Kid, "Kid should be default")
		assert.Equal(t, "RS256", key.Alg, "Algorithm should be RS256")
	})

	t.Run("ECDSA key", func(t *testing.T) {
		client, _ := CreateTestClientWithMock(cfg)

		// Set ECDSA signing key for testing
		privateKey := generateTestECDSAKey(t)
		require.NoError(t, client.SetSigningKeyForTesting(privateKey))

		// Test getting JWKS
		jwks, err := client.GetJWKS(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, jwks)

		// Verify JWKS structure
		assert.NotNil(t, jwks.Keys)
		assert.Greater(t, len(jwks.Keys), 0, "JWKS should contain at least one key")

		// Verify first key properties
		key := jwks.Keys[0]
		assert.Equal(t, "EC", key.Kty, "Key type should be EC")
		assert.Equal(t, "sig", key.Use, "Key use should be sig")
		assert.Equal(t, "default", key.Kid, "Kid should be default")
		assert.Equal(t, "ES256", key.Alg, "Algorithm should be ES256")
	})

	t.Run("unsupported key type", func(t *testing.T) {
		client, _ := CreateTestClientWithMock(cfg)

		// Set an unsupported key type (string instead of crypto key)
		err := client.SetSigningKeyForTesting("not-a-crypto-key")

		// Should error on setting invalid key
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported key type")
	})

	t.Run("no signing key set", func(t *testing.T) {
		client, _ := CreateTestClientWithMock(cfg)

		// Don't set any signing key - signingKey will be nil

		// Test getting JWKS should error
		jwks, err := client.GetJWKS(ctx)
		assert.Error(t, err)
		assert.Nil(t, jwks)
	})
}

// BenchmarkGetDiscoveryMetadata benchmarks discovery metadata generation
func BenchmarkGetDiscoveryMetadata(b *testing.B) {
	ctx := b.Context()

	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			PublicURL: "https://verifier.example.com",
			OIDC: model.OIDCConfig{
				Issuer:      "https://verifier.example.com",
				SubjectType: "public",
				SubjectSalt: "test-salt",
			},
			OpenID4VP: model.OpenID4VPConfig{
				SupportedCredentials: []model.SupportedCredentialConfig{
					{VCT: "cred1", Scopes: []string{"scope1"}},
					{VCT: "cred2", Scopes: []string{"scope2"}},
					{VCT: "cred3", Scopes: []string{"scope3"}},
				},
			},
		},
	}

	client, _ := CreateTestClientWithMock(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.GetDiscoveryMetadata(ctx)
	}
}

// BenchmarkGetJWKS benchmarks JWKS generation
func BenchmarkGetJWKS(b *testing.B) {
	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			PublicURL: "https://verifier.example.com",
			OIDC: model.OIDCConfig{
				Issuer:      "https://verifier.example.com",
				SubjectType: "public",
				SubjectSalt: "test-salt",
			},
		},
	}

	client, _ := CreateTestClientWithMock(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := b.Context()
		_, _ = client.GetJWKS(ctx)
	}
}
