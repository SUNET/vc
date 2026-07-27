package openid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestEC256Key generates an EC P-256 key pair for testing
func generateTestEC256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC256 key: %v", err)
	}
	return privateKey
}

// createValidJWTProof creates a valid JWT proof for testing
func createValidJWTProof(t *testing.T, privateKey *ecdsa.PrivateKey, aud string) string {
	t.Helper()

	// Create claims
	claims := jwtv5.MapClaims{
		"aud":   aud,
		"iat":   time.Now().Unix(),
		"nonce": "test-nonce",
	}

	// Create token with proper headers
	token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, claims)
	token.Header["typ"] = "openid4vci-proof+jwt"
	token.Header["jwk"] = map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   "test-x",
		"y":   "test-y",
	}

	// Sign the token
	signedToken, err := token.SignedString(privateKey)
	require.NoError(t, err)

	return signedToken
}

// createJWTProofWithIat creates a JWT proof with an explicit iat, to test clock-skew tolerance.
func createJWTProofWithIat(t *testing.T, privateKey *ecdsa.PrivateKey, aud string, iat time.Time) string {
	t.Helper()

	claims := jwtv5.MapClaims{
		"aud":   aud,
		"iat":   iat.Unix(),
		"nonce": "test-nonce",
	}
	token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, claims)
	token.Header["typ"] = "openid4vci-proof+jwt"
	token.Header["jwk"] = map[string]any{
		"kty": "EC", "crv": "P-256", "x": "test-x", "y": "test-y",
	}
	signedToken, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return signedToken
}

func TestProofTypes(t *testing.T) {
	tts := []struct {
		name   string
		cr     *CredentialRequest
		errStr string
	}{
		{
			name: "jwt",
			cr: &CredentialRequest{
				Proofs: &Proofs{
					JWT: []ProofJWTToken{mockJWTWithKidAndJwk},
				},
			},
			errStr: "invalid_credential_request",
		},
		{
			name: "jwt_missing",
			cr: &CredentialRequest{
				Proofs: &Proofs{
					JWT: []ProofJWTToken{},
				},
			},
			errStr: "invalid_credential_request",
		},
		{
			name: "di_vp",
			cr: &CredentialRequest{
				Proofs: &Proofs{
					DIVP: []ProofDIVP{
						{
							Context: []string{"https://www.w3.org/ns/credentials/v2"},
							Type:    []string{"VerifiablePresentation"},
							Proof: &DIVPProof{
								Type:               "DataIntegrityProof",
								Cryptosuite:        "eddsa-rdfc-2022",
								ProofPurpose:       "authentication",
								VerificationMethod: "did:key:z6MkvrFpBNCoYewiaeBLgjUDvLxUtnK5R6mqh5XPvLsrPsro",
								Domain:             "https://example.com",
								ProofValue:         "z5Y9cYzRxFd3C1qL5Z",
							},
						},
					},
				},
			},
			errStr: "",
		},
		{
			name: "di_vp_missing",
			cr: &CredentialRequest{
				Proofs: &Proofs{
					DIVP: []ProofDIVP{},
				},
			},
			errStr: "invalid_credential_request",
		},
		{
			name: "attestation",
			cr: &CredentialRequest{
				Proofs: &Proofs{
					Attestation: mockKeyAttestation,
				},
			},
			errStr: "",
		},
		{
			name: "attestation_missing",
			cr: &CredentialRequest{
				Proofs: &Proofs{
					Attestation: "",
				},
			},
			errStr: "invalid_credential_request",
		},
		{
			name: "nil_proofs",
			cr: &CredentialRequest{
				Proofs: nil,
			},
			errStr: "invalid_credential_request",
		},
		{
			name: "empty_proofs",
			cr: &CredentialRequest{
				Proofs: &Proofs{},
			},
			errStr: "invalid_credential_request",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			privateKey := generateTestEC256Key(t)

			err := tt.cr.VerifyProof(privateKey.Public())
			if tt.errStr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errStr)
			}
		})
	}
}

// Mock JWT with both kid and jwk (invalid per spec)
var mockJWTWithKidAndJwk ProofJWTToken = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleS0xIiwidHlwIjoib3BlbmlkNHZjaS1wcm9vZitqd3QiLCJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJ0ZXN0IiwieSI6InRlc3QifX0.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tIiwiaWF0IjoxMzAwODE5MzgwfQ.invalid"

// Mock key attestation JWT
var mockKeyAttestation ProofAttestation = "eyJhbGciOiJFUzI1NiIsInR5cCI6ImtleS1hdHRlc3RhdGlvbitqd3QifQ.eyJpYXQiOjEzMDA4MTkzODAsImF0dGVzdGVkX2tleXMiOlt7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoidGVzdCIsInkiOiJ0ZXN0In1dfQ.invalid"

func TestVerifyProof(t *testing.T) {
	tts := []struct {
		name              string
		credentialRequest *CredentialRequest
		errStr            string
	}{
		{
			name: "valid jwt",
			credentialRequest: &CredentialRequest{
				CredentialIdentifier: "ci_123",
				Proofs: &Proofs{
					JWT: []ProofJWTToken{mockJWTWithKidAndJwk},
				},
				CredentialResponseEncryption: &CredentialResponseEncryption{},
			},
			errStr: "invalid_credential_request",
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			privateKey := generateTestEC256Key(t)

			if err := tt.credentialRequest.VerifyProof(privateKey.Public()); err != nil {
				assert.Contains(t, err.Error(), tt.errStr)
			}
		})
	}
}

func TestVerifyJWTProof(t *testing.T) {
	privateKey := generateTestEC256Key(t)

	t.Run("valid JWT proof", func(t *testing.T) {
		jwt := ProofJWTToken(createValidJWTProof(t, privateKey, "https://issuer.example.com"))
		opts := &VerifyProofOptions{
			Audience: "https://issuer.example.com",
			CNonce:   "test-nonce",
		}
		err := jwt.Verify(&privateKey.PublicKey, opts)
		assert.NoError(t, err)
	})

	t.Run("alg none rejected", func(t *testing.T) {
		// Create a token with alg=none
		claims := jwtv5.MapClaims{"aud": "test", "iat": time.Now().Unix()}
		token := jwtv5.NewWithClaims(jwtv5.SigningMethodNone, claims)
		token.Header["typ"] = "openid4vci-proof+jwt"
		token.Header["jwk"] = map[string]any{"kty": "EC"}
		jwtStr, _ := token.SignedString(jwtv5.UnsafeAllowNoneSignatureType)
		jwt := ProofJWTToken(jwtStr)

		err := jwt.Verify(&privateKey.PublicKey, nil)
		assert.Error(t, err)
		// The error type should indicate invalid credential request
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})

	t.Run("missing typ rejected", func(t *testing.T) {
		claims := jwtv5.MapClaims{"aud": "test", "iat": time.Now().Unix()}
		token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, claims)
		// Not setting typ header
		token.Header["jwk"] = map[string]any{"kty": "EC"}
		jwtStr, _ := token.SignedString(privateKey)
		jwt := ProofJWTToken(jwtStr)

		err := jwt.Verify(&privateKey.PublicKey, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})

	t.Run("wrong typ rejected", func(t *testing.T) {
		claims := jwtv5.MapClaims{"aud": "test", "iat": time.Now().Unix()}
		token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, claims)
		token.Header["typ"] = "wrong-type"
		token.Header["jwk"] = map[string]any{"kty": "EC"}
		jwtStr, _ := token.SignedString(privateKey)
		jwt := ProofJWTToken(jwtStr)

		err := jwt.Verify(&privateKey.PublicKey, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})

	t.Run("private key in jwk rejected", func(t *testing.T) {
		claims := jwtv5.MapClaims{"aud": "test", "iat": time.Now().Unix()}
		token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, claims)
		token.Header["typ"] = "openid4vci-proof+jwt"
		token.Header["jwk"] = map[string]any{
			"kty": "EC",
			"crv": "P-256",
			"x":   "test",
			"y":   "test",
			"d":   "private-key-material", // This should be rejected
		}
		jwtStr, _ := token.SignedString(privateKey)
		jwt := ProofJWTToken(jwtStr)

		err := jwt.Verify(&privateKey.PublicKey, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})

	t.Run("iat slightly ahead of server clock is tolerated", func(t *testing.T) {
		// A wallet's clock running a few seconds ahead of the server (routine
		// NTP jitter between two independent systems) must not fail every
		// credential request outright - see proofIatClockSkew.
		jwtStr := createJWTProofWithIat(t, privateKey, "https://issuer.example.com", time.Now().Add(10*time.Second))
		jwt := ProofJWTToken(jwtStr)
		opts := &VerifyProofOptions{Audience: "https://issuer.example.com", CNonce: "test-nonce"}
		err := jwt.Verify(&privateKey.PublicKey, opts)
		assert.NoError(t, err)
	})

	t.Run("iat far in the future is rejected", func(t *testing.T) {
		jwtStr := createJWTProofWithIat(t, privateKey, "https://issuer.example.com", time.Now().Add(5*time.Minute))
		jwt := ProofJWTToken(jwtStr)
		opts := &VerifyProofOptions{Audience: "https://issuer.example.com", CNonce: "test-nonce"}
		err := jwt.Verify(&privateKey.PublicKey, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "iat claim value is in the future")
	})

	t.Run("nonce validation", func(t *testing.T) {
		claims := jwtv5.MapClaims{
			"aud":   "https://issuer.example.com",
			"iat":   time.Now().Unix(),
			"nonce": "correct-nonce",
		}
		token := jwtv5.NewWithClaims(jwtv5.SigningMethodES256, claims)
		token.Header["typ"] = "openid4vci-proof+jwt"
		token.Header["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": "test", "y": "test"}
		jwtStr, _ := token.SignedString(privateKey)
		jwt := ProofJWTToken(jwtStr)

		// Test with matching nonce
		opts := &VerifyProofOptions{CNonce: "correct-nonce"}
		err := jwt.Verify(&privateKey.PublicKey, opts)
		assert.NoError(t, err)

		// Test with wrong nonce
		opts = &VerifyProofOptions{CNonce: "wrong-nonce"}
		err = jwt.Verify(&privateKey.PublicKey, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_nonce")
	})
}

func TestDIVPVerify(t *testing.T) {
	t.Run("valid di_vp proof", func(t *testing.T) {
		divp := &ProofDIVP{
			Context: []string{"https://www.w3.org/ns/credentials/v2"},
			Type:    []string{"VerifiablePresentation"},
			Proof: &DIVPProof{
				Type:               "DataIntegrityProof",
				Cryptosuite:        "eddsa-rdfc-2022",
				ProofPurpose:       "authentication",
				VerificationMethod: "did:key:test",
				Domain:             "https://issuer.example.com",
				Challenge:          "test-nonce",
				ProofValue:         "z5Y9cYzRxFd3C1qL5Z",
			},
		}
		opts := &VerifyProofOptions{
			Audience: "https://issuer.example.com",
			CNonce:   "test-nonce",
		}
		err := divp.Verify(opts)
		assert.NoError(t, err)
	})

	t.Run("missing @context rejected", func(t *testing.T) {
		divp := &ProofDIVP{
			Type: []string{"VerifiablePresentation"},
		}
		err := divp.Verify(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})

	t.Run("missing VerifiablePresentation type rejected", func(t *testing.T) {
		divp := &ProofDIVP{
			Context: []string{"https://www.w3.org/ns/credentials/v2"},
			Type:    []string{"SomeOtherType"},
		}
		err := divp.Verify(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})

	t.Run("wrong proofPurpose rejected", func(t *testing.T) {
		divp := &ProofDIVP{
			Context: []string{"https://www.w3.org/ns/credentials/v2"},
			Type:    []string{"VerifiablePresentation"},
			Proof: &DIVPProof{
				Type:               "DataIntegrityProof",
				ProofPurpose:       "assertionMethod", // Should be "authentication"
				Domain:             "https://issuer.example.com",
				Cryptosuite:        "eddsa-rdfc-2022",
				VerificationMethod: "did:key:test",
				ProofValue:         "z5Y9cYzRxFd3C1qL5Z",
			},
		}
		err := divp.Verify(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})
}

func TestVerifyAttestationProof(t *testing.T) {
	t.Run("valid attestation", func(t *testing.T) {
		// This mock attestation has all required claims
		err := mockKeyAttestation.Verify(nil)
		assert.NoError(t, err)
	})

	t.Run("invalid attestation format", func(t *testing.T) {
		invalidAttestation := ProofAttestation("not-a-jwt")
		err := invalidAttestation.Verify(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})
}

func TestVerifyProofWithOptions(t *testing.T) {
	privateKey := generateTestEC256Key(t)

	t.Run("with audience validation", func(t *testing.T) {
		jwt := ProofJWTToken(createValidJWTProof(t, privateKey, "https://correct-issuer.com"))
		cr := &CredentialRequest{
			Proofs: &Proofs{
				JWT: []ProofJWTToken{jwt},
			},
		}
		opts := &VerifyProofOptions{
			Audience: "https://correct-issuer.com",
			CNonce:   "test-nonce",
		}
		err := cr.VerifyProofWithOptions(&privateKey.PublicKey, opts)
		assert.NoError(t, err)
	})

	t.Run("audience mismatch", func(t *testing.T) {
		jwt := ProofJWTToken(createValidJWTProof(t, privateKey, "https://wrong-issuer.com"))
		cr := &CredentialRequest{
			Proofs: &Proofs{
				JWT: []ProofJWTToken{jwt},
			},
		}
		opts := &VerifyProofOptions{
			Audience: "https://correct-issuer.com",
			CNonce:   "test-nonce",
		}
		err := cr.VerifyProofWithOptions(&privateKey.PublicKey, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_credential_request")
	})
}

func TestVerifyProofErrorDescriptions(t *testing.T) {
	privateKey := generateTestEC256Key(t)

	t.Run("nil proofs returns proper error description", func(t *testing.T) {
		cr := &CredentialRequest{Proofs: nil}
		err := cr.VerifyProof(privateKey.Public())
		assert.Error(t, err)
		openidErr, ok := err.(*Error)
		assert.True(t, ok)
		assert.Equal(t, ErrInvalidCredentialRequest, openidErr.Err)
		assert.Equal(t, "proofs is required", openidErr.ErrorDescription)
	})

	t.Run("empty proofs returns proper error description", func(t *testing.T) {
		cr := &CredentialRequest{Proofs: &Proofs{}}
		err := cr.VerifyProof(privateKey.Public())
		assert.Error(t, err)
		openidErr, ok := err.(*Error)
		assert.True(t, ok)
		assert.Equal(t, ErrInvalidCredentialRequest, openidErr.Err)
		assert.Equal(t, "at least one proof type (jwt, di_vp, or attestation) is required in proofs", openidErr.ErrorDescription)
	})

	t.Run("empty jwt array returns proper error description", func(t *testing.T) {
		cr := &CredentialRequest{Proofs: &Proofs{JWT: []ProofJWTToken{}}}
		err := cr.VerifyProof(privateKey.Public())
		assert.Error(t, err)
		openidErr, ok := err.(*Error)
		assert.True(t, ok)
		assert.Equal(t, ErrInvalidCredentialRequest, openidErr.Err)
		assert.Equal(t, "at least one proof type (jwt, di_vp, or attestation) is required in proofs", openidErr.ErrorDescription)
	})

	t.Run("empty di_vp array returns proper error description", func(t *testing.T) {
		cr := &CredentialRequest{Proofs: &Proofs{DIVP: []ProofDIVP{}}}
		err := cr.VerifyProof(privateKey.Public())
		assert.Error(t, err)
		openidErr, ok := err.(*Error)
		assert.True(t, ok)
		assert.Equal(t, ErrInvalidCredentialRequest, openidErr.Err)
		assert.Equal(t, "at least one proof type (jwt, di_vp, or attestation) is required in proofs", openidErr.ErrorDescription)
	})

	t.Run("empty attestation returns proper error description", func(t *testing.T) {
		cr := &CredentialRequest{Proofs: &Proofs{Attestation: ""}}
		err := cr.VerifyProof(privateKey.Public())
		assert.Error(t, err)
		openidErr, ok := err.(*Error)
		assert.True(t, ok)
		assert.Equal(t, ErrInvalidCredentialRequest, openidErr.Err)
		assert.Equal(t, "at least one proof type (jwt, di_vp, or attestation) is required in proofs", openidErr.ErrorDescription)
	})
}
