package apiv1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
	"vc/pkg/cache"
	"vc/pkg/crypto"
	"vc/pkg/openid4vp"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetQRCode tests QR code generation
func TestGetQRCode(t *testing.T) {
	ctx := t.Context()
	client, _ := CreateTestClientWithMock(nil)

	// Create a test session
	authCtx := &cache.AuthorizationContext{
		SessionID: "test-session-123",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Status:    cache.SessionStatusPending,
	}
	err := client.authContextCache.Create(ctx, authCtx)
	require.NoError(t, err)

	tests := []struct {
		name      string
		req       *GetQRCodeRequest
		wantErr   error
		checkResp func(t *testing.T, resp *GetQRCodeResponse)
	}{
		{
			name: "valid session",
			req: &GetQRCodeRequest{
				SessionID: "test-session-123",
			},
			wantErr: nil,
			checkResp: func(t *testing.T, resp *GetQRCodeResponse) {
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.ImageData)
				// QR code image should be PNG format
				assert.True(t, len(resp.ImageData) > 0)
			},
		},
		{
			name: "session not found",
			req: &GetQRCodeRequest{
				SessionID: "nonexistent-session",
			},
			wantErr: ErrSessionNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.GetQRCode(ctx, tt.req)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				if tt.checkResp != nil {
					tt.checkResp(t, resp)
				}
			}
		})
	}
}

// TestPollSession tests session polling
func TestPollSession(t *testing.T) {
	ctx := t.Context()
	client, _ := CreateTestClientWithMock(nil)

	// Create test sessions with different statuses
	pendingSession := &cache.AuthorizationContext{
		SessionID: "pending-session",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Status:    cache.SessionStatusPending,
	}
	err := client.authContextCache.Create(ctx, pendingSession)
	require.NoError(t, err)

	codeIssuedSession := &cache.AuthorizationContext{
		SessionID:   "code-issued-session",
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
		Status:      cache.SessionStatusCodeIssued,
		RedirectURI: "https://example.com/callback",
		State:       "test-state-123",
		Code:        "auth-code-xyz",
	}
	err = client.authContextCache.Create(ctx, codeIssuedSession)
	require.NoError(t, err)

	tests := []struct {
		name      string
		req       *PollSessionRequest
		wantErr   error
		checkResp func(t *testing.T, resp *PollSessionResponse)
	}{
		{
			name: "pending session",
			req: &PollSessionRequest{
				SessionID: "pending-session",
			},
			wantErr: nil,
			checkResp: func(t *testing.T, resp *PollSessionResponse) {
				assert.Equal(t, string(cache.SessionStatusPending), resp.Status)
				assert.Empty(t, resp.RedirectURI)
			},
		},
		{
			name: "code issued session",
			req: &PollSessionRequest{
				SessionID: "code-issued-session",
			},
			wantErr: nil,
			checkResp: func(t *testing.T, resp *PollSessionResponse) {
				assert.Equal(t, string(cache.SessionStatusCodeIssued), resp.Status)
				assert.NotEmpty(t, resp.RedirectURI)
				assert.Contains(t, resp.RedirectURI, "code=auth-code-xyz")
				assert.Contains(t, resp.RedirectURI, "state=test-state-123")
			},
		},
		{
			name: "session not found",
			req: &PollSessionRequest{
				SessionID: "nonexistent-session",
			},
			wantErr: ErrSessionNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.PollSession(ctx, tt.req)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				if tt.checkResp != nil {
					tt.checkResp(t, resp)
				}
			}
		})
	}
}

// TestGetUserInfo tests the UserInfo endpoint
func TestGetUserInfo(t *testing.T) {
	ctx := t.Context()
	client, _ := CreateTestClientWithMock(nil)

	// Create a session with verified claims
	authCtx := &cache.AuthorizationContext{
		SessionID:            "userinfo-session",
		CreatedAt:            time.Now(),
		ExpiresAt:            time.Now().Add(1 * time.Hour).Unix(),
		Status:               cache.SessionStatusTokenIssued,
		ClientID:             "test-client",
		Scopes:               []string{"openid", "profile", "email"},
		AccessToken:          "test-access-token-123",
		AccessTokenExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		VerifiedClaims: map[string]any{
			"sub":   "user-123",
			"name":  "John Doe",
			"email": "john@example.com",
		},
	}
	err := client.authContextCache.Create(ctx, authCtx)
	require.NoError(t, err)

	// Create a session with expired token
	expiredSession := &cache.AuthorizationContext{
		SessionID:            "expired-session",
		CreatedAt:            time.Now().Add(-2 * time.Hour),
		ExpiresAt:            time.Now().Add(-1 * time.Hour).Unix(),
		Status:               cache.SessionStatusTokenIssued,
		AccessToken:          "expired-token",
		AccessTokenExpiresAt: time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
	}
	err = client.authContextCache.Create(ctx, expiredSession)
	require.NoError(t, err)

	// Create a session without 'sub' claim
	sessionNoSub := &cache.AuthorizationContext{
		SessionID:            "session-no-sub",
		CreatedAt:            time.Now(),
		ExpiresAt:            time.Now().Add(1 * time.Hour).Unix(),
		Status:               cache.SessionStatusTokenIssued,
		ClientID:             "test-client",
		AccessToken:          "token-no-sub",
		AccessTokenExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		VerifiedClaims: map[string]any{
			"name":  "Jane Doe",
			"email": "jane@example.com",
		},
	}
	err = client.authContextCache.Create(ctx, sessionNoSub)
	require.NoError(t, err)

	// Create a session with non-string 'sub' claim
	sessionNonStringSub := &cache.AuthorizationContext{
		SessionID:            "session-non-string-sub",
		CreatedAt:            time.Now(),
		ExpiresAt:            time.Now().Add(1 * time.Hour).Unix(),
		Status:               cache.SessionStatusTokenIssued,
		ClientID:             "test-client",
		AccessToken:          "token-non-string-sub",
		AccessTokenExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		VerifiedClaims: map[string]any{
			"sub":  12345, // Non-string sub
			"name": "Bob Smith",
		},
	}
	err = client.authContextCache.Create(ctx, sessionNonStringSub)
	require.NoError(t, err)

	tests := []struct {
		name      string
		req       *UserInfoRequest
		wantErr   error
		checkResp func(t *testing.T, resp UserInfoResponse)
	}{
		{
			name: "valid access token",
			req: &UserInfoRequest{
				AccessToken: "test-access-token-123",
			},
			wantErr: nil,
			checkResp: func(t *testing.T, resp UserInfoResponse) {
				assert.Equal(t, "user-123", resp["sub"])
				assert.Equal(t, "John Doe", resp["name"])
				assert.Equal(t, "john@example.com", resp["email"])
			},
		},
		{
			name: "invalid access token",
			req: &UserInfoRequest{
				AccessToken: "invalid-token",
			},
			wantErr: ErrInvalidGrant,
		},
		{
			name: "expired access token",
			req: &UserInfoRequest{
				AccessToken: "expired-token",
			},
			wantErr: ErrInvalidGrant,
		},
		{
			name: "valid token without sub claim",
			req: &UserInfoRequest{
				AccessToken: "token-no-sub",
			},
			wantErr: nil,
			checkResp: func(t *testing.T, resp UserInfoResponse) {
				// Should still return a response, just with generated subject
				assert.NotEmpty(t, resp["sub"])
				assert.Equal(t, "Jane Doe", resp["name"])
				assert.Equal(t, "jane@example.com", resp["email"])
			},
		},
		{
			name: "valid token with non-string sub claim",
			req: &UserInfoRequest{
				AccessToken: "token-non-string-sub",
			},
			wantErr: nil,
			checkResp: func(t *testing.T, resp UserInfoResponse) {
				// Should still return a response with generated subject (non-string sub is ignored)
				assert.NotEmpty(t, resp["sub"])
				assert.Equal(t, "Bob Smith", resp["name"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.GetUserInfo(ctx, tt.req)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
				if tt.checkResp != nil {
					tt.checkResp(t, resp)
				}
			}
		})
	}
}

// TestGenerateNonce tests nonce generation
func TestGenerateNonce(t *testing.T) {
	// Generate multiple nonces and verify they're unique
	nonces := make(map[string]bool)
	for i := 0; i < 100; i++ {
		nonce, err := crypto.GenerateSecureToken(32, 0)
		assert.NoError(t, err)
		assert.NotEmpty(t, nonce)
		assert.False(t, nonces[nonce], "nonce should be unique")
		nonces[nonce] = true

		// Base64 URL encoded 32 bytes should be 43 characters
		assert.Len(t, nonce, 43, "nonce should be 43 base64url characters")
	}
}

// TestGetOIDCRequestObject tests the GetOIDCRequestObject handler
func TestGetOIDCRequestObject(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name         string
		sessionID    string
		authCtxSetup func(*cache.AuthorizationContext)
		expectError  bool
	}{
		{
			name:      "successful request object generation",
			sessionID: "session-ro-1",
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusPending
				s.ExpiresAt = time.Now().Add(10 * time.Minute).Unix()
				s.DCQLQuery = &openid4vp.DCQL{
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
			},
			expectError: false,
		},
		{
			name:      "expired session",
			sessionID: "session-expired",
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusPending
				s.ExpiresAt = time.Now().Add(-10 * time.Minute).Unix() // Already expired
			},
			expectError: true,
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
			client, _ := CreateTestClientWithMock(nil)

			// Generate RSA key for signing
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			require.NoError(t, client.SetSigningKeyForTesting(key))

			// Setup session if needed
			if tt.authCtxSetup != nil {
				authCtx := &cache.AuthorizationContext{
					SessionID:   tt.sessionID,
					Status:      cache.SessionStatusPending,
					CreatedAt:   time.Now(),
					ExpiresAt:   time.Now().Add(10 * time.Minute).Unix(),
					ClientID:    "test-client",
					RedirectURI: "https://client.example.com/callback",
					Scopes:      []string{"openid"},
				}
				tt.authCtxSetup(authCtx)
				err := client.authContextCache.Create(ctx, authCtx)
				require.NoError(t, err)
			}

			req := &GetRequestObjectRequest{
				SessionID: tt.sessionID,
			}

			resp, err := client.GetOIDCRequestObject(ctx, req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, resp)
				assert.NotEmpty(t, resp.RequestObject)

				// Verify nonce was stored in session
				authCtx, _ := client.authContextCache.GetByID(ctx, tt.sessionID)
				assert.NotEmpty(t, authCtx.RequestObjectNonce)
			}
		})
	}
}

// TestProcessCallback tests the ProcessCallback handler
func TestProcessCallback(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name             string
		sessionID        string
		code             string
		errorParam       string
		authCtxSetup     func(*cache.AuthorizationContext)
		expectError      bool
		expectErrorInURI bool
	}{
		{
			name:      "successful callback with code",
			sessionID: "session-callback-1",
			code:      "auth-code-123",
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusCodeIssued
				s.RedirectURI = "https://client.example.com/callback"
				s.State = "client-state"
			},
			expectError: false,
		},
		{
			name:       "callback with error",
			sessionID:  "session-callback-error",
			errorParam: "access_denied",
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusPending
				s.RedirectURI = "https://client.example.com/callback"
				s.State = "client-state"
			},
			expectError:      false,
			expectErrorInURI: true,
		},
		{
			name:         "session not found",
			sessionID:    "non-existent-session",
			code:         "some-code",
			authCtxSetup: nil,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := CreateTestClientWithMock(nil)

			// Setup session if needed
			if tt.authCtxSetup != nil {
				authCtx := &cache.AuthorizationContext{
					SessionID:   tt.sessionID,
					Status:      cache.SessionStatusPending,
					CreatedAt:   time.Now(),
					ExpiresAt:   time.Now().Add(10 * time.Minute).Unix(),
					ClientID:    "test-client",
					RedirectURI: "https://client.example.com/callback",
					Scopes:      []string{"openid"},
					State:       "client-state",
				}
				tt.authCtxSetup(authCtx)
				err := client.authContextCache.Create(ctx, authCtx)
				require.NoError(t, err)
			}

			req := &CallbackRequest{
				State: tt.sessionID,
				Code:  tt.code,
				Error: tt.errorParam,
			}

			resp, err := client.ProcessCallback(ctx, req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, resp)
				assert.NotEmpty(t, resp.RedirectURI)

				if tt.expectErrorInURI {
					assert.Contains(t, resp.RedirectURI, "error=")
				} else {
					assert.Contains(t, resp.RedirectURI, "code=")
				}
				assert.Contains(t, resp.RedirectURI, "state=")
			}
		})
	}
}

// TestGetJWKS_KeyTypes tests the GetJWKS handler with different key types
func TestGetJWKS_KeyTypes(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name        string
		setupKey    func() any
		expectError bool
		expectKty   string
		expectAlg   string
	}{
		{
			name: "RSA key",
			setupKey: func() any {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return key
			},
			expectError: false,
			expectKty:   "RSA",
			expectAlg:   "RS256",
		},
		{
			name: "EC P-256 key",
			setupKey: func() any {
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				return key
			},
			expectError: false,
			expectKty:   "EC",
			expectAlg:   "ES256",
		},
		{
			name: "EC P-384 key",
			setupKey: func() any {
				key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				return key
			},
			expectError: false,
			expectKty:   "EC",
			expectAlg:   "ES384",
		},
		{
			name: "EC P-521 key",
			setupKey: func() any {
				key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				return key
			},
			expectError: false,
			expectKty:   "EC",
			expectAlg:   "ES512",
		},
		{
			name: "no key configured",
			setupKey: func() any {
				return nil
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := CreateTestClientWithMock(nil)

			// Setup key
			key := tt.setupKey()
			if key != nil {
				require.NoError(t, client.SetSigningKeyForTesting(key))
			}

			jwks, err := client.GetJWKS(ctx)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, jwks)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, jwks)
				require.Len(t, jwks.Keys, 1)
				assert.Equal(t, tt.expectKty, jwks.Keys[0].Kty)
				assert.Equal(t, tt.expectAlg, jwks.Keys[0].Alg)
			}
		})
	}
}

// TestProcessDirectPost tests the ProcessDirectPost handler
func TestProcessDirectPost(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name                   string
		sessionID              string
		vpToken                string
		response               string
		presentationSubmission string
		authCtxSetup           func(*cache.AuthorizationContext)
		expectError            bool
		expectedErrorType      error
		expectShowCredentials  bool
		expectedStatus         cache.SessionStatus
	}{
		{
			name:      "successful direct post with VP token",
			sessionID: "session-dp-1",
			vpToken:   "eyJhbGciOiJFUzI1NiJ9.test-payload.signature",
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusPending
				s.RedirectURI = "https://client.example.com/callback"
				s.State = "client-state"
				s.Scopes = []string{"openid", "profile"}
			},
			expectError:    false,
			expectedStatus: cache.SessionStatusCodeIssued,
		},
		{
			name:      "direct post with DC API response parameter",
			sessionID: "session-dp-2",
			response:  "encrypted.jwt.token",
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusPending
				s.RedirectURI = "https://client.example.com/callback"
				s.State = "client-state"
			},
			expectError:    false,
			expectedStatus: cache.SessionStatusCodeIssued,
		},
		{
			name:                   "direct post with presentation submission",
			sessionID:              "session-dp-3",
			vpToken:                "eyJhbGciOiJFUzI1NiJ9.test-payload.signature",
			presentationSubmission: `{"id":"submission-1","definition_id":"def-1"}`,
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusPending
				s.RedirectURI = "https://client.example.com/callback"
				s.State = "client-state"
			},
			expectError:    false,
			expectedStatus: cache.SessionStatusCodeIssued,
		},
		{
			name:                   "direct post with invalid presentation submission JSON",
			sessionID:              "session-dp-4",
			vpToken:                "eyJhbGciOiJFUzI1NiJ9.test-payload.signature",
			presentationSubmission: `{invalid json}`,
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusPending
				s.RedirectURI = "https://client.example.com/callback"
				s.State = "client-state"
			},
			expectError:    false, // Should continue even with invalid presentation submission
			expectedStatus: cache.SessionStatusCodeIssued,
		},
		{
			name:      "direct post with show credentials enabled",
			sessionID: "session-dp-5",
			vpToken:   "eyJhbGciOiJFUzI1NiJ9.test-payload.signature",
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusPending
				s.RedirectURI = "https://client.example.com/callback"
				s.State = "client-state"
				s.ShowCredentialDetails = true
			},
			expectError:           false,
			expectShowCredentials: true,
			expectedStatus:        cache.SessionStatusAwaitingPresentation,
		},
		{
			name:              "session not found",
			sessionID:         "non-existent-session",
			vpToken:           "some.token.here",
			expectError:       true,
			expectedErrorType: ErrSessionNotFound,
		},
		{
			name:      "no vp_token or response provided",
			sessionID: "session-dp-6",
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusPending
			},
			expectError:       true,
			expectedErrorType: ErrInvalidRequest,
		},
		{
			name:      "direct post without redirect URI",
			sessionID: "session-dp-7",
			vpToken:   "eyJhbGciOiJFUzI1NiJ9.test-payload.signature",
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusPending
				s.RedirectURI = "" // No redirect URI
				s.State = "client-state"
			},
			expectError:    false,
			expectedStatus: cache.SessionStatusCodeIssued,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := CreateTestClientWithMock(nil)

			// Setup session if needed
			if tt.authCtxSetup != nil {
				authCtx := &cache.AuthorizationContext{
					SessionID:   tt.sessionID,
					Status:      cache.SessionStatusPending,
					CreatedAt:   time.Now(),
					ExpiresAt:   time.Now().Add(10 * time.Minute).Unix(),
					ClientID:    "test-client",
					RedirectURI: "https://client.example.com/callback",
					Scopes:      []string{"openid"},
					State:       "client-state",
				}
				tt.authCtxSetup(authCtx)
				err := client.authContextCache.Create(ctx, authCtx)
				require.NoError(t, err)
			}

			req := &DirectPostRequest{
				State:                  tt.sessionID,
				VPToken:                tt.vpToken,
				Response:               tt.response,
				PresentationSubmission: tt.presentationSubmission,
			}

			resp, err := client.ProcessDirectPost(ctx, req)

			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedErrorType != nil {
					assert.ErrorIs(t, err, tt.expectedErrorType)
				}
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, resp)

				// Verify session was updated
				authCtx, _ := client.authContextCache.GetByID(ctx, tt.sessionID)
				assert.Equal(t, tt.expectedStatus, authCtx.Status)

				if tt.expectShowCredentials {
					// Should redirect to display page
					assert.Contains(t, resp.RedirectURI, "/verification/display/")
				} else if authCtx.RedirectURI != "" {
					// Should have authorization code in redirect
					assert.Contains(t, resp.RedirectURI, "code=")
					assert.Contains(t, resp.RedirectURI, "state=")
				}
			}
		})
	}
}

// TestContainsOIDC tests the containsOIDC helper method
func TestContainsOIDC(t *testing.T) {
	client, _ := CreateTestClientWithMock(nil)

	tests := []struct {
		name     string
		slice    []string
		value    string
		expected bool
	}{
		{
			name:     "value found",
			slice:    []string{"openid", "profile", "email"},
			value:    "openid",
			expected: true,
		},
		{
			name:     "value not found",
			slice:    []string{"profile", "email"},
			value:    "openid",
			expected: false,
		},
		{
			name:     "empty slice",
			slice:    []string{},
			value:    "openid",
			expected: false,
		},
		{
			name:     "value at end",
			slice:    []string{"profile", "email", "openid"},
			value:    "openid",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.containsOIDC(tt.slice, tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}
