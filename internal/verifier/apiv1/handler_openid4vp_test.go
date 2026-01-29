package apiv1

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
	"vc/internal/verifier/db"
	"vc/pkg/openid4vp"

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
			client, _ := CreateTestClientWithMock(nil)

			// Generate RSA key for signing
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			client.SetSigningKeyForTesting(key, "RS256")

			// Configure Digital Credentials API
			client.cfg.VerifierProxy.DigitalCredentials.Enabled = tt.dcEnabled
			if tt.dcResponseMode != "" {
				client.cfg.VerifierProxy.DigitalCredentials.ResponseMode = tt.dcResponseMode
			}
			if tt.dcPreferredFormats != nil {
				client.cfg.VerifierProxy.DigitalCredentials.PreferredFormats = tt.dcPreferredFormats
			}

			signedJWT, err := client.CreateRequestObject(ctx, tt.sessionID, tt.dcqlQuery, tt.nonce)

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
					assert.NotEmpty(t, cachedObj.ClientMetadata.VPFormats)
				}
			}
		})
	}
}

// TestBuildVPFormats tests the buildVPFormats helper
func TestBuildVPFormats(t *testing.T) {
	tests := []struct {
		name             string
		preferredFormats []string
		expectedFormats  []string
	}{
		{
			name:             "default formats (empty)",
			preferredFormats: nil,
			expectedFormats:  []string{"vc+sd-jwt"},
		},
		{
			name:             "single SD-JWT format",
			preferredFormats: []string{"vc+sd-jwt"},
			expectedFormats:  []string{"vc+sd-jwt"},
		},
		{
			name:             "multiple formats",
			preferredFormats: []string{"vc+sd-jwt", "mso_mdoc"},
			expectedFormats:  []string{"vc+sd-jwt", "mso_mdoc"},
		},
		{
			name:             "DC SD-JWT format",
			preferredFormats: []string{"dc+sd-jwt"},
			expectedFormats:  []string{"dc+sd-jwt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := CreateTestClientWithMock(nil)
			client.cfg.VerifierProxy.DigitalCredentials.PreferredFormats = tt.preferredFormats

			vpFormats := client.buildVPFormats()

			assert.NotNil(t, vpFormats)
			for _, format := range tt.expectedFormats {
				assert.Contains(t, vpFormats, format)
				assert.Contains(t, vpFormats[format], "alg")
				assert.NotEmpty(t, vpFormats[format]["alg"])
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
			client, _ := CreateTestClientWithMock(nil)

			// Setup cache if needed
			if tt.setupCache {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				client.SetSigningKeyForTesting(key, "RS256")
				_, err = client.CreateRequestObject(ctx, tt.sessionID, createTestDCQLForVP(t), "test-nonce")
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
		sessionSetup           func(*db.Session)
		expectError            bool
	}{
		{
			name:                   "successful direct post",
			sessionID:              "test-session-dp-1",
			vpToken:                "eyJhbGciOiJFUzI1NiJ9.test.signature",
			presentationSubmission: map[string]any{"id": "submission-1"},
			sessionSetup: func(s *db.Session) {
				s.Status = db.SessionStatusPending
			},
			expectError: false,
		},
		{
			name:                   "session not found",
			sessionID:              "non-existent-session",
			vpToken:                "eyJhbGciOiJFUzI1NiJ9.test.signature",
			presentationSubmission: map[string]any{"id": "submission-1"},
			sessionSetup:           nil,
			expectError:            true,
		},
		{
			name:                   "direct post with scope",
			sessionID:              "test-session-dp-2",
			vpToken:                "eyJhbGciOiJFUzI1NiJ9.payload.signature",
			presentationSubmission: nil,
			sessionSetup: func(s *db.Session) {
				s.Status = db.SessionStatusPending
				s.OIDCRequest.Scope = "openid profile"
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, mockDB := CreateTestClientWithMock(nil)

			// Setup session if needed
			if tt.sessionSetup != nil {
				session := createTestDBSession(tt.sessionID)
				tt.sessionSetup(session)
				err := mockDB.Sessions.Create(ctx, session)
				require.NoError(t, err)
			}

			err := client.HandleDirectPost(ctx, tt.sessionID, tt.vpToken, tt.presentationSubmission)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify session was updated
				session, _ := mockDB.Sessions.GetByID(ctx, tt.sessionID)
				assert.NotNil(t, session)
				assert.Equal(t, tt.vpToken, session.OpenID4VP.VPToken)
				assert.Equal(t, db.SessionStatusCodeIssued, session.Status)
				assert.NotEmpty(t, session.Tokens.AuthorizationCode)
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
		sessionSetup func(*db.Session)
		expectError  bool
		expectedCode bool
	}{
		{
			name:      "pending session",
			sessionID: "pending-session-1",
			sessionSetup: func(s *db.Session) {
				s.Status = db.SessionStatusPending
			},
			expectError:  false,
			expectedCode: false,
		},
		{
			name:      "code issued session",
			sessionID: "code-session-1",
			sessionSetup: func(s *db.Session) {
				s.Status = db.SessionStatusCodeIssued
				s.Tokens.AuthorizationCode = "test-auth-code"
				s.OIDCRequest.State = "client-state"
				s.OIDCRequest.RedirectURI = "https://client.example.com/callback"
			},
			expectError:  false,
			expectedCode: true,
		},
		{
			name:         "session not found",
			sessionID:    "non-existent-session",
			sessionSetup: nil,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, mockDB := CreateTestClientWithMock(nil)

			// Setup session if needed
			if tt.sessionSetup != nil {
				session := createTestDBSession(tt.sessionID)
				tt.sessionSetup(session)
				err := mockDB.Sessions.Create(ctx, session)
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

// TestExtractClaimsFromVPToken tests the extractClaimsFromVPToken helper
func TestExtractClaimsFromVPToken(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name           string
		vpToken        string
		scope          string
		expectedClaims int
		expectError    bool
	}{
		{
			name:           "nil claims extractor returns empty claims",
			vpToken:        "test.vp.token",
			scope:          "openid",
			expectedClaims: 0,
			expectError:    false,
		},
		{
			name:           "nil claims extractor with profile scope",
			vpToken:        "eyJhbGciOiJFUzI1NiJ9.test-payload.signature",
			scope:          "openid profile",
			expectedClaims: 0,
			expectError:    false,
		},
		{
			name:           "nil claims extractor with empty scope",
			vpToken:        "eyJhbGciOiJFUzI1NiJ9.payload.sig",
			scope:          "",
			expectedClaims: 0,
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := CreateTestClientWithMock(nil)

			// Test with nil claims extractor (which is the default for test client)
			claims, err := client.extractClaimsFromVPToken(ctx, tt.vpToken, tt.scope)

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
func createTestDBSession(sessionID string) *db.Session {
	return &db.Session{
		ID:        sessionID,
		Status:    db.SessionStatusPending,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(10 * time.Minute),
		OIDCRequest: db.OIDCRequest{
			ClientID:     "test-client",
			RedirectURI:  "https://client.example.com/callback",
			ResponseType: "code",
			Scope:        "openid",
			State:        "client-state",
		},
		OpenID4VP: db.OpenID4VPSession{},
		Tokens:    db.TokenSet{},
	}
}
