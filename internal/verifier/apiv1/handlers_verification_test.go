package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/internal/verifier/cache"
	"github.com/SUNET/vc/internal/verifier/notify"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/openid4vp"
	"github.com/SUNET/vc/pkg/sdjwtvc"
	"github.com/SUNET/vc/pkg/trust"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testScope = "test-scope"

// TestGetKID tests the GetKID method on VerificationDirectPostRequest
func TestGetKID(t *testing.T) {
	tests := []struct {
		name        string
		response    string
		expectedKID string
		expectError bool
	}{
		{
			name:        "valid JWT with KID",
			response:    createTestJWEWithKID("test-kid-123"),
			expectedKID: "test-kid-123",
			expectError: false,
		},
		{
			name:        "JWT with different KID",
			response:    createTestJWEWithKID("another-kid-456"),
			expectedKID: "another-kid-456",
			expectError: false,
		},
		{
			name:        "JWT without KID",
			response:    createTestJWEWithoutKID(),
			expectedKID: "",
			expectError: true,
		},
		{
			name:        "malformed base64 header",
			response:    "!!!invalid-base64!!!.payload.signature",
			expectedKID: "",
			expectError: true,
		},
		{
			name:        "malformed JSON header",
			response:    base64.RawStdEncoding.EncodeToString([]byte("not-json")) + ".payload.signature",
			expectedKID: "",
			expectError: true,
		},
		{
			name:        "KID is not a string",
			response:    createTestJWEWithNonStringKID(),
			expectedKID: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &VerificationDirectPostRequest{
				Response: tt.response,
			}

			kid, err := req.GetKID()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedKID, kid)
			}
		})
	}
}

// Helper functions for GetKID tests

func createTestJWEWithKID(kid string) string {
	header := map[string]any{
		"alg": "ECDH-ES",
		"enc": "A256GCM",
		"kid": kid,
	}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawStdEncoding.EncodeToString(headerBytes)
	return headerB64 + ".encrypted_payload.tag"
}

func createTestJWEWithoutKID() string {
	header := map[string]any{
		"alg": "ECDH-ES",
		"enc": "A256GCM",
	}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawStdEncoding.EncodeToString(headerBytes)
	return headerB64 + ".encrypted_payload.tag"
}

func createTestJWEWithNonStringKID() string {
	header := map[string]any{
		"alg": "ECDH-ES",
		"enc": "A256GCM",
		"kid": 12345, // Integer instead of string
	}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawStdEncoding.EncodeToString(headerBytes)
	return headerB64 + ".encrypted_payload.tag"
}

// TestVerificationCallback tests the VerificationCallback handler
func TestVerificationCallback(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name              string
		responseCode      string
		setupCache        bool
		expectedCredCount int
		expectError       bool
	}{
		{
			name:              "successful callback with cached credential",
			responseCode:      "valid-response-code",
			setupCache:        true,
			expectedCredCount: 1,
			expectError:       false,
		},
		{
			name:         "response code not found in cache",
			responseCode: "non-existent-code",
			setupCache:   false,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := CreateTestClientWithMock(nil)

			// Setup credential cache if needed
			if tt.setupCache {
				credentials := []sdjwtvc.CredentialCache{
					{
						Credential: map[string]any{
							"vct": "urn:credential:diploma",
						},
						Claims: []sdjwtvc.Discloser{
							{ClaimName: "given_name", Value: "John"},
							{ClaimName: "family_name", Value: "Doe"},
						},
					},
				}
				client.cacheService.Credential.Set(ctx, tt.responseCode, credentials)
			}

			req := &VerificationCallbackRequest{
				ResponseCode: tt.responseCode,
			}

			resp, err := client.VerificationCallback(ctx, req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, resp)
				assert.Len(t, resp.CredentialData, tt.expectedCredCount)
			}
		})
	}
}

// TestVerifyJWTSignatureInvalidSignature tests that invalid signatures are rejected via JWTTrustVerifier
func TestVerifyJWTSignatureInvalidSignature(t *testing.T) {
	// Generate two different keys
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Sign with key1, embed key2 in jwk header (mismatch)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "test-issuer",
	})
	// Embed key2's public key as jwk so extractJWTKeyMaterial uses key2
	key2X, key2Y := ecCoordinates(t, &key2.PublicKey)
	token.Header["jwk"] = map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(key2X),
		"y":   base64.RawURLEncoding.EncodeToString(key2Y),
	}
	signedJWT, err := token.SignedString(key1)
	require.NoError(t, err)

	verifier := trust.NewJWTTrustVerifier(trust.JWTTrustVerifierConfig{
		TrustEvaluator: trust.NewAllowAllEvaluator(),
		JWKSResolver:   trust.NewJWKSKeyResolver(trust.JWKSResolverConfig{}),
		ParseX5C:       func(x5cRaw any) ([]*x509.Certificate, error) { return jose.ParseX5CHeader(x5cRaw) },
		ParseJWK:       jose.ParseJWKToPublicKey,
		Log:            logger.NewSimple("test"),
	})

	ctx := context.Background()
	err = verifier.EvaluateIssuerTrust(ctx, signedJWT+"~", testScope)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "JWT signature verification failed")
}

// TestVerificationDirectPost tests the VerificationDirectPost handler
// focusing on per-scope credential caching and validation application.
func TestVerificationDirectPost(t *testing.T) {
	ctx := t.Context()

	// Generate signing key for SD-JWT creation
	sigKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tests := []struct {
		name        string
		scopes      []string
		validations map[string][]openid4vp.ClaimValidation
		claims      map[string]map[string]any // scope -> claims
		wantErr     bool
		errContains string
	}{
		{
			name:   "single scope no validations",
			scopes: []string{"pid"},
			claims: map[string]map[string]any{
				"pid": {"given_name": "John", "birthdate": "1990-01-01"},
			},
			wantErr: false,
		},
		{
			name:   "single scope validation passes",
			scopes: []string{"pid"},
			validations: map[string][]openid4vp.ClaimValidation{
				"pid": {{Rule: "age_over", Path: []string{"birthdate"}, Value: 18}},
			},
			claims: map[string]map[string]any{
				"pid": {"given_name": "John", "birthdate": time.Now().UTC().AddDate(-25, 0, 0).Format("2006-01-02")},
			},
			wantErr: false,
		},
		{
			name:   "single scope validation fails",
			scopes: []string{"pid"},
			validations: map[string][]openid4vp.ClaimValidation{
				"pid": {{Rule: "age_over", Path: []string{"birthdate"}, Value: 18}},
			},
			claims: map[string]map[string]any{
				"pid": {"given_name": "John", "birthdate": time.Now().UTC().AddDate(-16, 0, 0).Format("2006-01-02")},
			},
			wantErr:     true,
			errContains: "claim validation failed for scope pid",
		},
		{
			name:   "multi scope validation only applies to target",
			scopes: []string{"pid", "ehic"},
			validations: map[string][]openid4vp.ClaimValidation{
				"pid": {{Rule: "age_over", Path: []string{"birthdate"}, Value: 18}},
			},
			claims: map[string]map[string]any{
				"pid":  {"given_name": "John", "birthdate": time.Now().UTC().AddDate(-25, 0, 0).Format("2006-01-02")},
				"ehic": {"card_number": "12345"}, // no birthdate — would fail if validated
			},
			wantErr: false,
		},
		{
			name:   "multi scope validation on second scope fails",
			scopes: []string{"pid", "ehic"},
			validations: map[string][]openid4vp.ClaimValidation{
				"ehic": {{Rule: "age_over", Path: []string{"birthdate"}, Value: 18}},
			},
			claims: map[string]map[string]any{
				"pid":  {"given_name": "John", "birthdate": time.Now().UTC().AddDate(-25, 0, 0).Format("2006-01-02")},
				"ehic": {"card_number": "12345"}, // missing birthdate -> fails
			},
			wantErr:     true,
			errContains: "claim validation failed for scope ehic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := CreateTestClientWithMock(nil)

			// Set up notify service
			log := logger.NewSimple("test")
			notifyService, _ := notify.New(ctx, client.cfg, log)
			client.notify = notifyService

			// Set up OpenID4VP client with ephemeral key cache
			openid4vpClient, _ := openid4vp.New(ctx, &openid4vp.Config{})
			client.openid4vp = openid4vpClient

			// Set up trust verifier (allow all for testing)
			client.jwtTrustVerifier = trust.NewJWTTrustVerifier(trust.JWTTrustVerifierConfig{
				TrustEvaluator: trust.NewAllowAllEvaluator(),
				JWKSResolver:   trust.NewJWKSKeyResolver(trust.JWKSResolverConfig{}),
				ParseX5C:       func(x5cRaw any) ([]*x509.Certificate, error) { return jose.ParseX5CHeader(x5cRaw) },
				ParseJWK:       jose.ParseJWKToPublicKey,
				Log:            log,
			})

			// Generate ephemeral key and store it
			kid := "test-ephemeral-kid"
			_, ephemeralPubJWK, err := client.openid4vp.EphemeralKeyCache.GenerateAndStore(kid)
			require.NoError(t, err)

			// Create auth context
			state := "test-state-123"
			nonce := "test-nonce-456"
			authCtx := &cache.AuthorizationContext{
				SessionID:                "test-session",
				State:                    state,
				Nonce:                    nonce,
				ClientID:                 "x509_san_dns:verifier.example.com",
				Scopes:                   tt.scopes,
				EphemeralEncryptionKeyID: kid,
				Validations:              tt.validations,
			}
			require.NoError(t, client.cacheService.AuthContext.Save(ctx, authCtx))

			// Build VP tokens per scope
			vpTokenMap := make(map[string][]string, len(tt.scopes))
			for _, scope := range tt.scopes {
				claims := tt.claims[scope]
				vpToken := createTestSDJWT(t, sigKey, claims, nonce, authCtx.ClientID)
				vpTokenMap[scope] = []string{vpToken}
			}

			// Create VP response and encrypt as JWE
			vpResponse := openid4vp.VPResponse{
				VPToken: vpTokenMap,
				State:   state,
			}
			vpResponseBytes, err := json.Marshal(vpResponse)
			require.NoError(t, err)

			// Encrypt with ephemeral public key
			encrypted, err := jwe.Encrypt(vpResponseBytes,
				jwe.WithKey(jwa.ECDH_ES(), ephemeralPubJWK),
				jwe.WithContentEncryption(jwa.A256GCM()),
			)
			require.NoError(t, err)

			req := &VerificationDirectPostRequest{
				Response: string(encrypted),
			}

			resp, err := client.VerificationDirectPost(ctx, req)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)
			}
		})
	}
}

// TestVerificationDirectPostDecoyDisclosure verifies that a decoy disclosure
// (not referenced in _sd) is ignored during claim validation. A fake birthdate
// decoy should NOT satisfy age_over validation when the real credential lacks it.
func TestVerificationDirectPostDecoyDisclosure(t *testing.T) {
	ctx := t.Context()

	sigKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	client, _ := CreateTestClientWithMock(nil)
	log := logger.NewSimple("test")
	notifyService, _ := notify.New(ctx, client.cfg, log)
	client.notify = notifyService

	openid4vpClient, _ := openid4vp.New(ctx, &openid4vp.Config{})
	client.openid4vp = openid4vpClient

	client.jwtTrustVerifier = trust.NewJWTTrustVerifier(trust.JWTTrustVerifierConfig{
		TrustEvaluator: trust.NewAllowAllEvaluator(),
		JWKSResolver:   trust.NewJWKSKeyResolver(trust.JWKSResolverConfig{}),
		ParseX5C:       func(x5cRaw any) ([]*x509.Certificate, error) { return jose.ParseX5CHeader(x5cRaw) },
		ParseJWK:       jose.ParseJWKToPublicKey,
		Log:            log,
	})

	kid := "test-ephemeral-kid"
	_, ephemeralPubJWK, err := client.openid4vp.EphemeralKeyCache.GenerateAndStore(kid)
	require.NoError(t, err)

	state := "test-state-decoy"
	nonce := "test-nonce-decoy"
	authCtx := &cache.AuthorizationContext{
		SessionID:                "test-session-decoy",
		State:                    state,
		Nonce:                    nonce,
		ClientID:                 "x509_san_dns:verifier.example.com",
		Scopes:                   []string{"pid"},
		EphemeralEncryptionKeyID: kid,
		Validations: map[string][]openid4vp.ClaimValidation{
			"pid": {{Rule: "age_over", Path: []string{"birthdate"}, Value: 18}},
		},
	}
	require.NoError(t, client.cacheService.AuthContext.Save(ctx, authCtx))

	// Real claims do NOT include birthdate; decoy disclosure provides a fake one.
	// If decoys are incorrectly used for validation, this would pass.
	realClaims := map[string]any{"given_name": "John"}
	decoyClaims := map[string]any{"birthdate": time.Now().UTC().AddDate(-30, 0, 0).Format("2006-01-02")}

	vpToken := createTestSDJWTWithDecoys(t, sigKey, realClaims, decoyClaims, nonce, authCtx.ClientID)

	vpResponse := openid4vp.VPResponse{
		VPToken: map[string][]string{"pid": {vpToken}},
		State:   state,
	}
	vpResponseBytes, err := json.Marshal(vpResponse)
	require.NoError(t, err)

	encrypted, err := jwe.Encrypt(vpResponseBytes,
		jwe.WithKey(jwa.ECDH_ES(), ephemeralPubJWK),
		jwe.WithContentEncryption(jwa.A256GCM()),
	)
	require.NoError(t, err)

	req := &VerificationDirectPostRequest{Response: string(encrypted)}
	_, err = client.VerificationDirectPost(ctx, req)

	// Validation must fail: the real credential has no birthdate,
	// the decoy disclosure is unbound and must be ignored.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "claim validation failed for scope pid")
	assert.Contains(t, err.Error(), "birthdate")
}

// createTestSDJWT creates a minimal SD-JWT VP token for testing.
// Format: <issuer-jwt>~<disclosure1>~...~<kb-jwt>
func createTestSDJWT(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any, nonce, audience string) string {
	t.Helper()
	return createTestSDJWTWithDecoys(t, key, claims, nil, nonce, audience)
}

// createTestSDJWTWithDecoys creates an SD-JWT VP token that includes decoy disclosures
// (disclosures not referenced in the _sd array). These should be ignored during validation.
func createTestSDJWTWithDecoys(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any, decoys map[string]any, nonce, audience string) string {
	t.Helper()

	// Build selective disclosures: [salt, claim_name, value]
	// and compute their hashes for the _sd array
	var disclosures []string
	var sdHashes []string
	for name, value := range claims {
		disclosure := []any{"salt_" + name, name, value}
		discBytes, _ := json.Marshal(disclosure)
		encoded := base64.RawURLEncoding.EncodeToString(discBytes)
		disclosures = append(disclosures, encoded)

		// Compute SHA-256 hash of the raw encoded disclosure (before decoding)
		hash := sha256.Sum256([]byte(encoded))
		sdHashes = append(sdHashes, base64.RawURLEncoding.EncodeToString(hash[:]))
	}

	// Add decoy disclosures (not referenced in _sd)
	for name, value := range decoys {
		disclosure := []any{"decoy_salt_" + name, name, value}
		discBytes, _ := json.Marshal(disclosure)
		encoded := base64.RawURLEncoding.EncodeToString(discBytes)
		disclosures = append(disclosures, encoded)
		// Intentionally NOT adding hash to sdHashes — this is a decoy
	}

	// Build issuer JWT with embedded JWK for trust verification
	issuerClaims := jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"iat": time.Now().Unix(),
		"vct": "urn:test:credential",
		"_sd": sdHashes,
	}

	issuerToken := jwt.NewWithClaims(jwt.SigningMethodES256, issuerClaims)
	// Embed public key as JWK so the trust verifier can extract it
	keyX, keyY := ecCoordinates(t, &key.PublicKey)
	issuerToken.Header["jwk"] = map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(keyX),
		"y":   base64.RawURLEncoding.EncodeToString(keyY),
	}
	signedIssuerJWT, err := issuerToken.SignedString(key)
	require.NoError(t, err)

	// Build key binding JWT (proves holder controls the wallet)
	kbClaims := jwt.MapClaims{
		"nonce": nonce,
		"aud":   audience,
		"iat":   time.Now().Unix(),
	}
	kbToken := jwt.NewWithClaims(jwt.SigningMethodES256, kbClaims)
	signedKBJWT, err := kbToken.SignedString(key)
	require.NoError(t, err)

	// Assemble: <issuer-jwt>~<disc1>~<disc2>~...~<kb-jwt>
	parts := signedIssuerJWT + "~"
	for _, d := range disclosures {
		parts += d + "~"
	}
	parts += signedKBJWT

	return parts
}

// ecCoordinates extracts the X and Y coordinates from a P-256 public key
// using ECDH(), avoiding the deprecated X/Y big.Int fields.
func ecCoordinates(t *testing.T, pub *ecdsa.PublicKey) (x, y []byte) {
	t.Helper()
	ecdhKey, err := pub.ECDH()
	require.NoError(t, err)
	// Uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes)
	raw := ecdhKey.Bytes()
	require.Equal(t, 65, len(raw), "unexpected uncompressed P-256 point length")
	return raw[1:33], raw[33:65]
}


