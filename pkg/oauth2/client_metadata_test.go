package oauth2

import (
	"context"
	"testing"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientMetadata_Marshal(t *testing.T) {
	tests := []struct {
		name     string
		metadata *ClientMetadata
		wantErr  bool
	}{
		{
			name: "basic client metadata",
			metadata: &ClientMetadata{
				ClientID:      "test-client-123",
				ClientName:    "Test Client",
				ClientURI:     "https://example.com",
				RedirectURIs:  []string{"https://example.com/callback"},
				ResponseTypes: []string{"code"},
				GrantTypes:    []string{"authorization_code"},
				Scope:         "openid profile",
			},
			wantErr: false,
		},
		{
			name: "client with vp_formats_supported",
			metadata: &ClientMetadata{
				ClientID:     "verifier-client",
				ClientName:   "Verifier Client",
				RedirectURIs: []string{"https://verifier.example.com/callback"},
				VPFormatsSupported: &openid4vp.VPFormatsSupported{
					JWTVCJson: &openid4vp.JWTVCFormat{
						AlgValues: []string{"ES256", "ES384"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "minimal client metadata",
			metadata: &ClientMetadata{
				ClientID: "minimal-client",
			},
			wantErr: false,
		},
		{
			name: "client with contacts and logo",
			metadata: &ClientMetadata{
				ClientID: "full-client",
				LogoURI:  "https://example.com/logo.png",
				Contacts: []string{"admin@example.com", "support@example.com"},
				Scope:    "openid email profile",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := tt.metadata.Marshal()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, claims)

			// Verify client_id is in claims
			assert.Equal(t, tt.metadata.ClientID, claims["client_id"])

			// Verify iat (issued at) is set
			assert.NotNil(t, claims["iat"])

			// Verify other fields if set
			if tt.metadata.ClientName != "" {
				assert.Equal(t, tt.metadata.ClientName, claims["client_name"])
			}
			if tt.metadata.ClientURI != "" {
				assert.Equal(t, tt.metadata.ClientURI, claims["client_uri"])
			}
			if tt.metadata.LogoURI != "" {
				assert.Equal(t, tt.metadata.LogoURI, claims["logo_uri"])
			}
			if tt.metadata.Scope != "" {
				assert.Equal(t, tt.metadata.Scope, claims["scope"])
			}
		})
	}
}

func TestClientMetadata_Sign(t *testing.T) {
	ecPrivateKey, ecCert := mockGenerateECDSAKeyDeterministic(t)
	rsaPrivateKey, rsaCert := mockGenerateRSAKeyDeterministic(t)

	tests := []struct {
		name       string
		metadata   *ClientMetadata
		privateKey any
		chain      []string
		wantErr    bool
	}{
		{
			name: "sign with ECDSA key",
			metadata: &ClientMetadata{
				ClientID:     "test-client",
				ClientName:   "Test Client",
				RedirectURIs: []string{"https://example.com/callback"},
			},
			privateKey: ecPrivateKey,
			chain:      []string{},
			wantErr:    false,
		},
		{
			name: "sign ECDSA with x5c chain",
			metadata: &ClientMetadata{
				ClientID:     "test-client-with-chain",
				ClientName:   "Test Client with Chain",
				RedirectURIs: []string{"https://example.com/callback"},
			},
			privateKey: ecPrivateKey,
			chain:      []string{ecCert},
			wantErr:    false,
		},
		{
			name: "sign minimal metadata",
			metadata: &ClientMetadata{
				ClientID: "minimal-client",
			},
			privateKey: ecPrivateKey,
			chain:      []string{},
			wantErr:    false,
		},
		{
			name: "sign with RSA key",
			metadata: &ClientMetadata{
				ClientID:     "test-client-rsa",
				ClientName:   "Test Client RSA",
				RedirectURIs: []string{"https://example.com/callback"},
			},
			privateKey: rsaPrivateKey,
			chain:      []string{},
			wantErr:    false,
		},
		{
			name: "sign RSA with x5c chain",
			metadata: &ClientMetadata{
				ClientID:     "test-client-rsa-chain",
				ClientName:   "Test Client RSA with Chain",
				RedirectURIs: []string{"https://example.com/callback"},
			},
			privateKey: rsaPrivateKey,
			chain:      []string{rsaCert},
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Wrap signing key in pki.SoftwareSigner
			signer, err := pki.NewSoftwareSigner(tt.privateKey, "test-key-id")
			require.NoError(t, err)

			signedToken, err := tt.metadata.Sign(context.Background(), signer, tt.chain)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.NotEmpty(t, signedToken)

			// Verify the token can be parsed
			parser := jwt.NewParser()
			token, _, err := parser.ParseUnverified(signedToken, jwt.MapClaims{})
			require.NoError(t, err)
			assert.NotNil(t, token)

			claims, ok := token.Claims.(jwt.MapClaims)
			require.True(t, ok)
			assert.Equal(t, tt.metadata.ClientID, claims["client_id"])

			// Verify x5c header if chain provided
			if len(tt.chain) > 0 {
				// Note: ParseUnverified returns x5c as []any due to JSON unmarshaling,
				// even though we set it as []string when signing
				x5c, ok := token.Header["x5c"].([]any)
				require.True(t, ok, "x5c should be present in header")
				require.Len(t, x5c, len(tt.chain))
				for i, cert := range tt.chain {
					assert.Equal(t, cert, x5c[i].(string))
				}
			}
		})
	}
}
