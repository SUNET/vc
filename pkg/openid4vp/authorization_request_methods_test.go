package openid4vp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"

	"vc/pkg/pki"
)

func mockRSAPrivateKey(t *testing.T, bits int) crypto.PrivateKey {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	assert.NoError(t, err)

	return privKey
}

func mockECPrivateKey(t *testing.T, curve elliptic.Curve) crypto.PrivateKey {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	assert.NoError(t, err)

	return privKey
}

func mockSigner(t *testing.T, privateKey crypto.PrivateKey) pki.Signer {
	t.Helper()

	signer, err := pki.NewSoftwareSigner(privateKey, "")
	assert.NoError(t, err)

	return signer
}

func TestAuthorizationRequestSign(t *testing.T) {
	rsaKey := mockRSAPrivateKey(t, 2048)
	ecP256Key := mockECPrivateKey(t, elliptic.P256())
	ecP384Key := mockECPrivateKey(t, elliptic.P384())
	ecP521Key := mockECPrivateKey(t, elliptic.P521())

	tts := []struct {
		name          string
		authorization *RequestObject
		signer        pki.Signer
		x5c           []string
		expectError   bool
		errorContains string
		expectedAlg   string
	}{
		{
			name: "valid RS256 with x5c",
			authorization: &RequestObject{
				ISS:          "https://verifier.example.com",
				AUD:          "https://wallet.example.com",
				ResponseType: "code",
				ClientID:     "client123",
				Nonce:        "n-0S6_WzA2Mj",
				ResponseURI:  "https://verifier.example.com/response",
			},
			signer:      mockSigner(t, rsaKey),
			x5c:         []string{"MIICertificateData..."},
			expectError: false,
			expectedAlg: "RS256",
		},
		{
			name: "valid RS256 without x5c",
			authorization: &RequestObject{
				ISS:          "https://verifier.example.com",
				AUD:          "https://wallet.example.com",
				ResponseType: "code",
				ClientID:     "client123",
				Nonce:        "n-0S6_WzA2Mj",
				ResponseURI:  "https://verifier.example.com/response",
			},
			signer:      mockSigner(t, rsaKey),
			x5c:         nil,
			expectError: false,
			expectedAlg: "RS256",
		},
		{
			name: "valid ES256 (P-256) - recommended for OpenID4VP",
			authorization: &RequestObject{
				ISS:          "https://verifier.example.com",
				AUD:          "https://wallet.example.com",
				ResponseType: "code",
				ClientID:     "client123",
				Nonce:        "n-0S6_WzA2Mj",
				ResponseURI:  "https://verifier.example.com/response",
				DCQLQuery: &DCQL{
					Credentials: []CredentialQuery{
						{
							ID:     "pid_credential",
							Format: "vc+sd-jwt",
						},
					},
				},
			},
			signer:      mockSigner(t, ecP256Key),
			x5c:         []string{"MIIB...EC256Cert"},
			expectError: false,
			expectedAlg: "ES256",
		},
		{
			name: "valid ES384 (P-384)",
			authorization: &RequestObject{
				ISS:          "https://verifier.example.com",
				AUD:          "https://wallet.example.com",
				ResponseType: "code",
				ClientID:     "client123",
				Nonce:        "n-0S6_WzA2Mj",
				ResponseURI:  "https://verifier.example.com/response",
			},
			signer:      mockSigner(t, ecP384Key),
			x5c:         []string{"MIIB...EC384Cert"},
			expectError: false,
			expectedAlg: "ES384",
		},
		{
			name: "valid ES512 (P-521) with DCQL",
			authorization: &RequestObject{
				ISS:          "https://verifier.example.com",
				AUD:          "https://wallet.example.com",
				ResponseType: "code",
				ClientID:     "client123",
				Nonce:        "n-0S6_WzA2Mj",
				ResponseURI:  "https://verifier.example.com/response",
				DCQLQuery: &DCQL{
					Credentials: []CredentialQuery{
						{
							ID:     "pid_credential",
							Format: "vc+sd-jwt",
							Meta: MetaQuery{
								VCTValues: []string{"urn:eudi:pid:1"},
							},
						},
					},
				},
			},
			signer:      mockSigner(t, ecP521Key),
			x5c:         nil,
			expectError: false,
			expectedAlg: "ES512",
		},
		{
			name: "valid RS256 (RSA)",
			authorization: &RequestObject{
				ISS:          "https://verifier.example.com",
				AUD:          "https://wallet.example.com",
				ResponseType: "code",
				ClientID:     "client123",
				Nonce:        "n-0S6_WzA2Mj",
				ResponseURI:  "https://verifier.example.com/response",
			},
			signer:      mockSigner(t, rsaKey),
			x5c:         []string{"MIIC...RS256Cert"},
			expectError: false,
			expectedAlg: "RS256",
		},
		{
			name:          "nil request object",
			authorization: nil,
			signer:        mockSigner(t, rsaKey),
			x5c:           []string{"cert"},
			expectError:   true,
			errorContains: "request object cannot be nil",
		},
		{
			name: "nil signer",
			authorization: &RequestObject{
				ISS:   "https://verifier.example.com",
				Nonce: "n-0S6_WzA2Mj",
			},
			signer:        nil,
			x5c:           []string{"cert"},
			expectError:   true,
			errorContains: "signer cannot be nil",
		},
		{
			name: "empty x5c array should not include x5c in header",
			authorization: &RequestObject{
				ISS:          "https://verifier.example.com",
				AUD:          "https://wallet.example.com",
				ResponseType: "code",
				ClientID:     "client123",
				Nonce:        "n-0S6_WzA2Mj",
				ResponseURI:  "https://verifier.example.com/response",
			},
			signer:      mockSigner(t, ecP256Key),
			x5c:         []string{},
			expectError: false,
			expectedAlg: "ES256",
		},

	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			signed, err := tt.authorization.Sign(context.Background(), tt.signer, tt.x5c)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Empty(t, signed)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, signed)

				// Verify the JWT can be parsed and has correct header
				token, _, err := jwt.NewParser().ParseUnverified(signed, jwt.MapClaims{})
				assert.NoError(t, err)
				assert.Equal(t, "oauth-authz-req+jwt", token.Header["typ"])
				assert.Equal(t, tt.expectedAlg, token.Header["alg"])

				// Verify x5c is only present when provided and non-empty
				if len(tt.x5c) > 0 {
					x5cHeader, exists := token.Header["x5c"]
					assert.True(t, exists, "x5c should be present in header")
					// JWT library returns x5c as []any
					x5cSlice, ok := x5cHeader.([]any)
					assert.True(t, ok, "x5c should be a slice")
					assert.Len(t, x5cSlice, len(tt.x5c))
					for i, cert := range tt.x5c {
						assert.Equal(t, cert, x5cSlice[i])
					}
				} else {
					assert.NotContains(t, token.Header, "x5c")
				}

				// Verify claims are properly marshaled
				claims, ok := token.Claims.(jwt.MapClaims)
				assert.True(t, ok, "claims should be MapClaims")
				assert.Equal(t, tt.authorization.ISS, claims["iss"])
				assert.Equal(t, tt.authorization.Nonce, claims["nonce"])

				// Verify optional fields are included when present
				if tt.authorization.DCQLQuery != nil {
					assert.Contains(t, claims, "dcql_query")
				}
			}
		})
	}
}
