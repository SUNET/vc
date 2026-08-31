package apiv1

import (
	"crypto"

	"crypto/rand"
	"crypto/rsa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateRequestObject tests the CreateRequestObject handler
func TestCreateRequestObject(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name                 string
		sessionID            string
		dcqlQuery            *openid4vp.DCQL
		nonce                string
		dcEnabled            bool
		dcResponseMode       string
		dcPreferredFormats   []string
		expectError          bool
		expectedResponseMode string
	}{
		{
			name:                 "basic request object creation",
			sessionID:            "test-session-123",
			dcqlQuery:            createTestDCQLForVP(t),
			nonce:                "test-nonce-abc",
			dcEnabled:            false,
			expectError:          false,
			expectedResponseMode: "direct_post",
		},
		{
			name:                 "request object with Digital Credentials API enabled",
			sessionID:            "test-session-dc-1",
			dcqlQuery:            createTestDCQLForVP(t),
			nonce:                "test-nonce-dc",
			dcEnabled:            true,
			dcResponseMode:       "",
			expectError:          false,
			expectedResponseMode: "dc_api.jwt", // Default when DC enabled
		},
		{
			name:                 "request object with custom DC response mode",
			sessionID:            "test-session-dc-2",
			dcqlQuery:            createTestDCQLForVP(t),
			nonce:                "test-nonce-dc2",
			dcEnabled:            true,
			dcResponseMode:       "w3c_dc_api.jwt",
			expectError:          false,
			expectedResponseMode: "w3c_dc_api.jwt",
		},
		{
			name:                 "request object with DC preferred formats",
			sessionID:            "test-session-dc-3",
			dcqlQuery:            createTestDCQLForVP(t),
			nonce:                "test-nonce-dc3",
			dcEnabled:            true,
			dcPreferredFormats:   []string{"vc+sd-jwt", "mso_mdoc"},
			expectError:          false,
			expectedResponseMode: "dc_api.jwt", // Default when DC enabled
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newSigningTestClient(t)

			// Configure Digital Credentials API
			client.cfg.Verifier.DigitalCredentials.Enable = tt.dcEnabled
			if tt.dcResponseMode != "" {
				client.cfg.Verifier.DigitalCredentials.ResponseMode = tt.dcResponseMode
			}
			if tt.dcPreferredFormats != nil {
				client.cfg.Verifier.DigitalCredentials.PreferredFormats = tt.dcPreferredFormats
				// Setup VP formats configuration
				client.cfg.Verifier.PreferredVPFormats = &openid4vp.VPFormatsSupported{
					SDJWT: &openid4vp.SDJWTVCFormat{
						SDJWTAlgValues: []string{"ES256", "ES384", "ES512", "RS256"},
						KBJWTAlgValues: []string{"ES256", "ES384", "ES512", "RS256"},
					},
				}
			}

			signedJWT, err := client.CreateRequestObject(ctx, tt.sessionID, tt.dcqlQuery, tt.nonce, nil)

			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, signedJWT)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, signedJWT)

				// Verify request object was cached
				cachedObj, err := client.GetRequestObject(ctx, tt.sessionID)
				assert.NoError(t, err)
				require.NotNil(t, cachedObj)
				assert.Equal(t, tt.nonce, cachedObj.Nonce)
				assert.Equal(t, tt.expectedResponseMode, cachedObj.ResponseMode)
				assert.Equal(t, tt.sessionID, cachedObj.State)

				// Verify client metadata for DC API
				if tt.dcEnabled && tt.dcPreferredFormats != nil {
					assert.NotNil(t, cachedObj.ClientMetadata)
					assert.NotEmpty(t, cachedObj.ClientMetadata.VPFormatsSupported)
				}
			}
		})
	}
}

// TestGetRequestObject tests the GetRequestObject handler
func TestGetRequestObject(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name        string
		sessionID   string
		setupCache  bool
		expectError bool
	}{
		{
			name:        "successful retrieval",
			sessionID:   "cached-session-123",
			setupCache:  true,
			expectError: false,
		},
		{
			name:        "not found",
			sessionID:   "non-existent-session",
			setupCache:  false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := CreateTestClientWithMock(t, nil)

			// Setup cache if needed
			if tt.setupCache {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				require.NoError(t, client.SetSigningKeyForTesting(key))
				_, err = client.CreateRequestObject(ctx, tt.sessionID, createTestDCQLForVP(t), "test-nonce", nil)
				require.NoError(t, err)
			}

			requestObj, err := client.GetRequestObject(ctx, tt.sessionID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, requestObj)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, requestObj)
				assert.Equal(t, tt.sessionID, requestObj.State)
			}
		})
	}
}

// TestHandleDirectPost tests the HandleDirectPost handler
func TestHandleDirectPost(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name                   string
		sessionID              string
		vpToken                string
		presentationSubmission any
		authCtxSetup           func(*cache.AuthorizationContext)
		expectError            bool
	}{
		{ // #nosec G101
			name:                   "successful direct post",
			sessionID:              "test-session-dp-1",
			vpToken:                "eyJhbGciOiJFUzI1NiJ9.test.signature",
			presentationSubmission: map[string]any{"id": "submission-1"},
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusPending
			},
			expectError: false,
		},
		{ // #nosec G101
			name:                   "session not found",
			sessionID:              "non-existent-session",
			vpToken:                "eyJhbGciOiJFUzI1NiJ9.test.signature",
			presentationSubmission: map[string]any{"id": "submission-1"},
			authCtxSetup:           nil,
			expectError:            true,
		},
		{ // #nosec G101
			name:                   "direct post with scope",
			sessionID:              "test-session-dp-2",
			vpToken:                "eyJhbGciOiJFUzI1NiJ9.payload.signature",
			presentationSubmission: nil,
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusPending
				s.Scopes = []string{"openid", "profile"}
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := CreateTestClientWithMock(t, nil)

			// Setup session if needed
			if tt.authCtxSetup != nil {
				authCtx := createTestDBSession(tt.sessionID)
				tt.authCtxSetup(authCtx)
				err := client.cacheService.AuthContext.Create(ctx, authCtx)
				require.NoError(t, err)
			}

			err := client.HandleDirectPost(ctx, tt.sessionID, tt.vpToken, tt.presentationSubmission)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify session was updated
				authCtx, _ := client.cacheService.AuthContext.GetByID(ctx, tt.sessionID)
				assert.NotNil(t, authCtx)
				assert.Equal(t, tt.vpToken, authCtx.VPToken)
				assert.Equal(t, cache.SessionStatusCodeIssued, authCtx.Status)
				assert.NotEmpty(t, authCtx.Code)
			}
		})
	}
}

// TestGetPollStatus tests the GetPollStatus handler
func TestGetPollStatus(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name         string
		sessionID    string
		authCtxSetup func(*cache.AuthorizationContext)
		expectError  bool
		expectedCode bool
	}{
		{
			name:      "pending session",
			sessionID: "pending-session-1",
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusPending
			},
			expectError:  false,
			expectedCode: false,
		},
		{
			name:      "code issued session",
			sessionID: "code-session-1",
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusCodeIssued
				s.Code = "test-auth-code"
				s.State = "client-state"
				s.RedirectURI = "https://client.example.com/callback"
			},
			expectError:  false,
			expectedCode: true,
		},
		{
			name:         "session not found",
			sessionID:    "non-existent-session",
			authCtxSetup: nil,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := CreateTestClientWithMock(t, nil)

			// Setup session if needed
			if tt.authCtxSetup != nil {
				authCtx := createTestDBSession(tt.sessionID)
				tt.authCtxSetup(authCtx)
				err := client.cacheService.AuthContext.Create(ctx, authCtx)
				require.NoError(t, err)
			}

			response, err := client.GetPollStatus(ctx, tt.sessionID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, response)
				assert.Equal(t, tt.sessionID, response.SessionID)

				if tt.expectedCode {
					assert.NotEmpty(t, response.AuthorizationCode)
					assert.NotEmpty(t, response.RedirectURI)
					assert.NotEmpty(t, response.State)
				} else {
					assert.Empty(t, response.AuthorizationCode)
				}
			}
		})
	}
}

// Helper functions for OpenID4VP tests

// createTestDCQLForVP creates a test DCQL query
func createTestDCQLForVP(t *testing.T) *openid4vp.DCQL {
	t.Helper()
	return &openid4vp.DCQL{
		Credentials: []openid4vp.CredentialQuery{
			{
				ID:     "test_credential",
				Format: "vc+sd-jwt",
				Meta: openid4vp.MetaQuery{
					VCTValues: []string{"https://example.com/credential/test"},
				},
			},
		},
	}
}

// TestExtractAndMapClaimsEmpty tests the extractAndMapClaims helper with nil extractor
func TestExtractAndMapClaimsEmpty(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name           string
		vpToken        string
		expectedClaims int
		expectError    bool
	}{
		{
			name:           "nil claims extractor returns empty claims",
			vpToken:        "test.vp.token",
			expectedClaims: 0,
			expectError:    false,
		},
		{ // #nosec G101
			name:           "nil claims extractor with valid token",
			vpToken:        "eyJhbGciOiJFUzI1NiJ9.test-payload.signature",
			expectedClaims: 0,
			expectError:    false,
		},
		{ // #nosec G101
			name:           "nil claims extractor with another token",
			vpToken:        "eyJhbGciOiJFUzI1NiJ9.payload.sig",
			expectedClaims: 0,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := CreateTestClientWithMock(t, nil)

			// Test with nil claims extractor (which is the default for test client)
			claims, err := client.extractAndMapClaims(ctx, tt.vpToken, "")

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, claims)
				assert.Len(t, claims, tt.expectedClaims)
			}
		})
	}
}

// createTestDBSession creates a test session for testing
func createTestDBSession(sessionID string) *cache.AuthorizationContext {
	authCtx := &cache.AuthorizationContext{
		SessionID:    sessionID,
		Status:       cache.SessionStatusPending,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(10 * time.Minute).Unix(),
		ClientID:     "test-client",
		RedirectURI:  "https://client.example.com/callback",
		ResponseType: "code",
		Scopes:       []string{"openid"},
		State:        "client-state",
	}

	return authCtx
}

// TestCreateRequestObject_EncryptedModeCarriesAKey covers what an external
// wallet actually validates. A response_mode ending in .jwt asks the wallet
// to encrypt its response; this path previously sent client_metadata with
// only vp_formats_supported, so there was no key to encrypt to and no
// encryption parameters, and a conformant wallet rejected the request before
// reading the credential query.
func TestCreateRequestObject_EncryptedModeCarriesAKey(t *testing.T) {
	ctx := t.Context()
	client := newSigningTestClient(t)

	client.cfg.Verifier.DigitalCredentials.Enable = true // response_mode defaults to dc_api.jwt

	_, err := client.CreateRequestObject(ctx, "session-enc", createTestDCQLForVP(t), "nonce-enc", nil)
	require.NoError(t, err)

	cached, err := client.GetRequestObject(ctx, "session-enc")
	require.NoError(t, err)
	require.NotNil(t, cached.ClientMetadata, "client_metadata is required for an encrypted response mode")

	md := cached.ClientMetadata
	require.NotNil(t, md.JWKS, "the wallet needs a key to encrypt to")
	require.Len(t, md.JWKS.Keys, 1)

	assert.Equal(t, []string{"A256GCM"}, md.EncryptedResponseEncValuesSupported,
		"OpenID4VP 1.0 expects an array under this name")
	assert.Equal(t, "ECDH-ES", md.AuthorizationEncryptedResponseALG)
	assert.Equal(t, "A256GCM", md.AuthorizationEncryptedResponseENC)

	// The private half must be findable by the advertised kid, or the wallet
	// encrypts to a key we cannot decrypt with.
	kid, ok := md.JWKS.Keys[0].KeyID()
	require.True(t, ok)
	_, found := client.openid4vp.EphemeralKeyCache.Get(kid)
	assert.True(t, found, "the ephemeral private key must be retrievable by the advertised kid")
}

// TestCreateRequestObject_UnencryptedModeSendsNoKey is the other side: with
// DC API off the response mode is direct_post, which is not encrypted, so
// there is no reason to mint or advertise a key.
func TestCreateRequestObject_UnencryptedModeSendsNoKey(t *testing.T) {
	ctx := t.Context()
	client := newSigningTestClient(t)

	client.cfg.Verifier.DigitalCredentials.Enable = false

	_, err := client.CreateRequestObject(ctx, "session-plain", createTestDCQLForVP(t), "nonce-plain", nil)
	require.NoError(t, err)

	cached, err := client.GetRequestObject(ctx, "session-plain")
	require.NoError(t, err)
	assert.Equal(t, "direct_post", cached.ResponseMode)
	if cached.ClientMetadata != nil {
		assert.Nil(t, cached.ClientMetadata.JWKS)
		assert.Empty(t, cached.ClientMetadata.EncryptedResponseEncValuesSupported)
	}
}

// newSigningTestClient returns a mock-backed client with a signing key
// installed, which every CreateRequestObject test needs before it can sign a
// request object.
func newSigningTestClient(t *testing.T) *Client {
	t.Helper()

	client, _ := CreateTestClientWithMock(t, nil)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.NoError(t, client.SetSigningKeyForTesting(key))

	return client
}

// TestCreateRequestObject_ReusesTheSessionKey covers a wallet fetching the
// request object twice. GetOIDCRequestObject rebuilds and re-signs on every
// call, so regenerating the key would replace the private half under an
// unchanged kid: a wallet still holding the first request object would
// encrypt to a public key whose private half no longer exists, and the
// response would fail to decrypt for no visible reason.
func TestCreateRequestObject_ReusesTheSessionKey(t *testing.T) {
	ctx := t.Context()
	client := newSigningTestClient(t)
	client.cfg.Verifier.DigitalCredentials.Enable = true

	firstKey := func(t *testing.T, sessionID string) jwk.Key {
		t.Helper()
		cached, err := client.GetRequestObject(ctx, sessionID)
		require.NoError(t, err)
		require.NotNil(t, cached.ClientMetadata)
		require.NotNil(t, cached.ClientMetadata.JWKS)
		require.Len(t, cached.ClientMetadata.JWKS.Keys, 1)
		return cached.ClientMetadata.JWKS.Keys[0]
	}

	_, err := client.CreateRequestObject(ctx, "same-session", createTestDCQLForVP(t), "nonce-1", nil)
	require.NoError(t, err)
	before := firstKey(t, "same-session")

	// Second fetch of the same session, as a wallet retry or reload would do.
	_, err = client.CreateRequestObject(ctx, "same-session", createTestDCQLForVP(t), "nonce-2", nil)
	require.NoError(t, err)
	after := firstKey(t, "same-session")

	beforeThumb, err := before.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	afterThumb, err := after.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, beforeThumb, afterThumb,
		"the advertised public key must not change between fetches of the same session")

	// And the private half must still match what is advertised.
	kid, ok := after.KeyID()
	require.True(t, ok)
	priv, found := client.openid4vp.EphemeralKeyCache.Get(kid)
	require.True(t, found)
	privPub, err := priv.PublicKey()
	require.NoError(t, err)
	privThumb, err := privPub.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, afterThumb, privThumb,
		"the cached private key must be the pair of the advertised public key")
}
