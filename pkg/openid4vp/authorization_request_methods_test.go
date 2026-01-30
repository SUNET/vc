package openid4vp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
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

func TestAuthorizationRequestSign(t *testing.T) {
	rsaKey := mockRSAPrivateKey(t, 2048)
	ecP256Key := mockECPrivateKey(t, elliptic.P256())
	ecP384Key := mockECPrivateKey(t, elliptic.P384())
	ecP521Key := mockECPrivateKey(t, elliptic.P521())

	tts := []struct {
		name          string
		authorization *RequestObject
		signingMethod jwt.SigningMethod
		signingKey    any
		x5c           []string
		expectError   bool
		errorContains string
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
			signingMethod: jwt.GetSigningMethod("RS256"),
			signingKey:    rsaKey,
			x5c:           []string{"MIICertificateData..."},
			expectError:   false,
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
			signingMethod: jwt.GetSigningMethod("RS256"),
			signingKey:    rsaKey,
			x5c:           nil,
			expectError:   false,
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
			signingMethod: jwt.GetSigningMethod("ES256"),
			signingKey:    ecP256Key,
			x5c:           []string{"MIIB...EC256Cert"},
			expectError:   false,
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
			signingMethod: jwt.GetSigningMethod("ES384"),
			signingKey:    ecP384Key,
			x5c:           []string{"MIIB...EC384Cert"},
			expectError:   false,
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
			signingMethod: jwt.GetSigningMethod("ES512"),
			signingKey:    ecP521Key,
			x5c:           nil,
			expectError:   false,
		},
		{
			name: "valid PS256 (RSA-PSS)",
			authorization: &RequestObject{
				ISS:          "https://verifier.example.com",
				AUD:          "https://wallet.example.com",
				ResponseType: "code",
				ClientID:     "client123",
				Nonce:        "n-0S6_WzA2Mj",
				ResponseURI:  "https://verifier.example.com/response",
			},
			signingMethod: jwt.GetSigningMethod("PS256"),
			signingKey:    rsaKey,
			x5c:           []string{"MIIC...PS256Cert"},
			expectError:   false,
		},
		{
			name:          "nil request object",
			authorization: nil,
			signingMethod: jwt.GetSigningMethod("RS256"),
			signingKey:    rsaKey,
			x5c:           []string{"cert"},
			expectError:   true,
			errorContains: "request object cannot be nil",
		},
		{
			name: "nil signing method",
			authorization: &RequestObject{
				ISS:   "https://verifier.example.com",
				Nonce: "n-0S6_WzA2Mj",
			},
			signingMethod: nil,
			signingKey:    rsaKey,
			x5c:           []string{"cert"},
			expectError:   true,
			errorContains: "signing method cannot be nil",
		},
		{
			name: "nil signing key",
			authorization: &RequestObject{
				ISS:   "https://verifier.example.com",
				Nonce: "n-0S6_WzA2Mj",
			},
			signingMethod: jwt.GetSigningMethod("ES256"),
			signingKey:    nil,
			x5c:           []string{"cert"},
			expectError:   true,
			errorContains: "signing key cannot be nil",
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
			signingMethod: jwt.GetSigningMethod("ES256"),
			signingKey:    ecP256Key,
			x5c:           []string{},
			expectError:   false,
		},
		{
			name: "mismatched key type - RSA key with ES256",
			authorization: &RequestObject{
				ISS:          "https://verifier.example.com",
				AUD:          "https://wallet.example.com",
				ResponseType: "code",
				ClientID:     "client123",
				Nonce:        "n-0S6_WzA2Mj",
				ResponseURI:  "https://verifier.example.com/response",
			},
			signingMethod: jwt.GetSigningMethod("ES256"),
			signingKey:    rsaKey,
			x5c:           []string{"cert"},
			expectError:   true,
			errorContains: "failed to sign JWT",
		},
		{
			name: "mismatched key type - EC key with RS256",
			authorization: &RequestObject{
				ISS:          "https://verifier.example.com",
				AUD:          "https://wallet.example.com",
				ResponseType: "code",
				ClientID:     "client123",
				Nonce:        "n-0S6_WzA2Mj",
				ResponseURI:  "https://verifier.example.com/response",
			},
			signingMethod: jwt.GetSigningMethod("RS256"),
			signingKey:    ecP256Key,
			x5c:           []string{"cert"},
			expectError:   true,
			errorContains: "failed to sign JWT",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			signed, err := tt.authorization.Sign(tt.signingMethod, tt.signingKey, tt.x5c)

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
				assert.Equal(t, tt.signingMethod.Alg(), token.Header["alg"])

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
