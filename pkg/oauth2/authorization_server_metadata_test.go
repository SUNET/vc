package oauth2

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"github.com/SUNET/vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"gotest.tools/v3/golden"
)

var mockAuthorizationServerMetadata = &AuthorizationServerMetadata{
	Issuer:                                     "http://vc_dev_apigw:8080",
	AuthorizationEndpoint:                      "http://vc_dev_apigw:8080/authorize",
	TokenEndpoint:                              "http://vc_dev_apigw:8080/token",
	ResponseTypesSupported:                     []string{"code"},
	TokenEndpointAuthMethodsSupported:          []string{"none"},
	CodeChallengeMethodsSupported:              []string{"S256"},
	PushedAuthorizationRequestEndpoint:         "http://vc_dev_apigw:8080/par",
	RequiredPushedAuthorizationRequests:        true,
	DPOPSigningALGValuesSupported:              []string{"ES256"},
	PreAuthorizedGrantAnonymousAccessSupported: false,
}

func TestMarshalMetadata(t *testing.T) {
	tts := []struct {
		name           string
		goldenFileName string
		signedMetadata string
		want           *AuthorizationServerMetadata
	}{
		{
			name:           "test",
			goldenFileName: "metadata_json.golden",
			want:           mockAuthorizationServerMetadata,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			fileByte := golden.Get(t, tt.goldenFileName)

			got := &AuthorizationServerMetadata{}
			err := json.Unmarshal(fileByte, got)
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthorizationServerMetadata_Marshal(t *testing.T) {
	tests := []struct {
		name string
		metadata *AuthorizationServerMetadata
		wantErr bool
	}{
		{
			name: "complete metadata",
			metadata: mockAuthorizationServerMetadata,
			wantErr: false,
		},
		{
			name: "minimal metadata",
			metadata: &AuthorizationServerMetadata{
				Issuer: "https://issuer.example.com",
				TokenEndpoint: "https://issuer.example.com/token",
			},
			wantErr: false,
		},
		{
			name: "with all optional fields",
			metadata: &AuthorizationServerMetadata{
				Issuer: "https://full.example.com",
				AuthorizationEndpoint: "https://full.example.com/authorize",
				TokenEndpoint: "https://full.example.com/token",
				ResponseTypesSupported: []string{"code", "token"},
				TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "none"},
				CodeChallengeMethodsSupported: []string{"S256", "plain"},
				PushedAuthorizationRequestEndpoint: "https://full.example.com/par",
				RequiredPushedAuthorizationRequests: true,
				DPOPSigningALGValuesSupported: []string{"ES256", "RS256"},
				PreAuthorizedGrantAnonymousAccessSupported: true,
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
			assert.NoError(t, err)
			assert.NotNil(t, claims)
			
			// Verify issuer is in claims
			assert.Equal(t, tt.metadata.Issuer, claims["issuer"])
			
			// Verify token endpoint
			if tt.metadata.TokenEndpoint != "" {
				assert.Equal(t, tt.metadata.TokenEndpoint, claims["token_endpoint"])
			}
		})
	}
}

func TestSignMetadata(t *testing.T) {
	ecKey, ecCert := mockGenerateECDSAKeyDeterministic(t)
	rsaKey, rsaCert := mockGenerateRSAKeyDeterministic(t)

	tts := []struct {
		name           string
		issuerMetadata *AuthorizationServerMetadata
		signingKey     any
		cert           string
		wantErr        bool
	}{
		{
			name:           "sign with ECDSA key",
			issuerMetadata: mockAuthorizationServerMetadata,
			signingKey:     ecKey,
			cert:           ecCert,
			wantErr:        false,
		},
		{
			name:           "sign with RSA key",
			issuerMetadata: mockAuthorizationServerMetadata,
			signingKey:     rsaKey,
			cert:           rsaCert,
			wantErr:        false,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			metadata := tt.issuerMetadata

			// Wrap signing key in pki.SoftwareSigner
			signer, err := pki.NewSoftwareSigner(tt.signingKey, "test-key-id")
			assert.NoError(t, err)

			metadataWithSignature, err := metadata.Sign(context.Background(), signer, []string{tt.cert})
			
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			
			assert.NoError(t, err)
			assert.NotEmpty(t, metadataWithSignature)

			claims := jwt.MapClaims{}

			token, err := jwt.ParseWithClaims(metadataWithSignature.SignedMetadata, claims, func(token *jwt.Token) (any, error) {
				// Extract public key using type assertion
				switch key := tt.signingKey.(type) {
				case *rsa.PrivateKey:
					return &key.PublicKey, nil
				case *ecdsa.PrivateKey:
					return key.Public(), nil
				default:
					t.Fatalf("unsupported key type: %T", key)
					return nil, nil
				}
			})
			assert.NoError(t, err)

			assert.True(t, token.Valid)

			// ensure the singed claim does not have signed_metadata in it self
			assert.Empty(t, claims["signed_metadata"])

			assert.Len(t, token.Header["x5c"], 1)
		})
	}
}
