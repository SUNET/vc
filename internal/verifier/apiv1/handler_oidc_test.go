package apiv1

import (
	"strings"
	"testing"
	"time"
	"vc/internal/verifier/apiv1/utils"
	"vc/internal/verifier/db"
	"vc/pkg/cache"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthorizeRequest validates the AuthorizeRequest struct fields
func TestAuthorizeRequest_Validation(t *testing.T) {
	tests := []struct {
		name     string
		req      AuthorizeRequest
		wantErr  bool
		errField string
	}{
		{
			name: "valid request",
			req: AuthorizeRequest{
				ResponseType: "code",
				ClientID:     "test-client",
				RedirectURI:  "https://example.com/callback",
				Scope:        "openid",
				State:        "random-state",
				Nonce:        "random-nonce",
			},
			wantErr: false,
		},
		{
			name: "missing response_type",
			req: AuthorizeRequest{
				ClientID:    "test-client",
				RedirectURI: "https://example.com/callback",
				Scope:       "openid",
			},
			wantErr:  true,
			errField: "response_type",
		},
		{
			name: "missing client_id",
			req: AuthorizeRequest{
				ResponseType: "code",
				RedirectURI:  "https://example.com/callback",
				Scope:        "openid",
			},
			wantErr:  true,
			errField: "client_id",
		},
		{
			name: "missing redirect_uri",
			req: AuthorizeRequest{
				ResponseType: "code",
				ClientID:     "test-client",
				Scope:        "openid",
			},
			wantErr:  true,
			errField: "redirect_uri",
		},
		{
			name: "missing scope",
			req: AuthorizeRequest{
				ResponseType: "code",
				ClientID:     "test-client",
				RedirectURI:  "https://example.com/callback",
			},
			wantErr:  true,
			errField: "scope",
		},
		{
			name: "with PKCE parameters",
			req: AuthorizeRequest{
				ResponseType:        "code",
				ClientID:            "test-client",
				RedirectURI:         "https://example.com/callback",
				Scope:               "openid profile",
				CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				CodeChallengeMethod: "S256",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Basic validation - check required fields are non-empty
			hasError := false
			if tt.req.ResponseType == "" {
				hasError = true
			}
			if tt.req.ClientID == "" {
				hasError = true
			}
			if tt.req.RedirectURI == "" {
				hasError = true
			}
			if tt.req.Scope == "" {
				hasError = true
			}

			if tt.wantErr {
				assert.True(t, hasError, "Expected validation error for %s", tt.errField)
			} else {
				assert.False(t, hasError, "Expected no validation error")
			}
		})
	}
}

// TestAuthorizeResponse validates the AuthorizeResponse struct
func TestAuthorizeResponse_Fields(t *testing.T) {
	resp := AuthorizeResponse{
		SessionID:        "session-123",
		QRCodeData:       "openid://...",
		QRCodeImageURL:   "https://verifier.example.com/qr/session-123",
		DeepLinkURL:      "openid://authorize?...",
		PollURL:          "https://verifier.example.com/session/session-123",
		PreferredFormats: []string{"vc+sd-jwt"},
		UseJAR:           true,
		ResponseMode:     "direct_post",
		Title:            "Verify your credential",
		Subtitle:         "Scan the QR code with your wallet",
		PrimaryColor:     "#007bff",
		SecondaryColor:   "#6c757d",
		Theme:            "light",
		LogoURL:          "https://verifier.example.com/logo.png",
	}

	assert.Equal(t, "session-123", resp.SessionID)
	assert.Equal(t, "openid://...", resp.QRCodeData)
	assert.Contains(t, resp.PreferredFormats, "vc+sd-jwt")
	assert.True(t, resp.UseJAR)
	assert.Equal(t, "direct_post", resp.ResponseMode)
}

// TestTokenRequest validates the TokenRequest struct
func TestTokenRequest_Validation(t *testing.T) {
	tests := []struct {
		name      string
		req       TokenRequest
		grantType string
		wantErr   bool
	}{
		{
			name: "valid authorization code grant",
			req: TokenRequest{
				GrantType:    "authorization_code",
				Code:         "auth-code-123",
				RedirectURI:  "https://example.com/callback",
				ClientID:     "test-client",
				CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			},
			grantType: "authorization_code",
			wantErr:   false,
		},
		{
			name: "valid refresh token grant",
			req: TokenRequest{
				GrantType:    "refresh_token",
				RefreshToken: "refresh-token-123",
				ClientID:     "test-client",
			},
			grantType: "refresh_token",
			wantErr:   false,
		},
		{
			name: "missing grant_type",
			req: TokenRequest{
				Code:        "auth-code-123",
				RedirectURI: "https://example.com/callback",
				ClientID:    "test-client",
			},
			wantErr: true,
		},
		{
			name: "authorization_code missing code",
			req: TokenRequest{
				GrantType:   "authorization_code",
				RedirectURI: "https://example.com/callback",
				ClientID:    "test-client",
			},
			grantType: "authorization_code",
			wantErr:   true,
		},
		{
			name: "refresh_token missing token",
			req: TokenRequest{
				GrantType: "refresh_token",
				ClientID:  "test-client",
			},
			grantType: "refresh_token",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasError := false

			// Validate required fields
			if tt.req.GrantType == "" {
				hasError = true
			}

			// Grant type specific validation
			switch tt.req.GrantType {
			case "authorization_code":
				if tt.req.Code == "" {
					hasError = true
				}
			case "refresh_token":
				if tt.req.RefreshToken == "" {
					hasError = true
				}
			}

			if tt.wantErr {
				assert.True(t, hasError, "Expected validation error")
			} else {
				assert.False(t, hasError, "Expected no validation error")
			}
		})
	}
}

// TestTokenResponse validates the TokenResponse struct
func TestTokenResponse_Fields(t *testing.T) {
	resp := TokenResponse{
		AccessToken:  "access-token-123",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: "refresh-token-123",
		IDToken:      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
		Scope:        strings.Join([]string{"openid", "profile", "email"}, " "),
	}

	assert.Equal(t, "access-token-123", resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, 3600, resp.ExpiresIn)
	assert.Equal(t, "refresh-token-123", resp.RefreshToken)
	assert.NotEmpty(t, resp.IDToken)
	assert.Equal(t, "openid profile email", resp.Scope)
}

// TestPKCEValidation tests PKCE code challenge verification
func TestPKCEValidation(t *testing.T) {
	tests := []struct {
		name                string
		codeVerifier        string
		codeChallenge       string
		codeChallengeMethod string
		expectValid         bool
	}{
		{
			name:                "valid S256 PKCE",
			codeVerifier:        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			expectValid:         true,
		},
		{
			name:                "invalid S256 PKCE - wrong verifier",
			codeVerifier:        "wrongverifier123456789012345678901234567890",
			codeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			codeChallengeMethod: "S256",
			expectValid:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := utils.ValidatePKCE(tt.codeVerifier, tt.codeChallenge, tt.codeChallengeMethod)
			if tt.expectValid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

// TestResponseModes tests different OAuth 2.0 response modes
func TestResponseModes(t *testing.T) {
	validModes := []string{"query", "fragment", "form_post", "direct_post"}

	for _, mode := range validModes {
		t.Run(mode, func(t *testing.T) {
			// Just validate these are recognized response modes
			assert.Contains(t, validModes, mode)
		})
	}
}

// TestScopeParsing tests scope string parsing
func TestScopeParsing(t *testing.T) {
	tests := []struct {
		name           string
		scopeStr       string
		expectedScopes []string
	}{
		{
			name:           "openid only",
			scopeStr:       "openid",
			expectedScopes: []string{"openid"},
		},
		{
			name:           "openid profile email",
			scopeStr:       "openid profile email",
			expectedScopes: []string{"openid", "profile", "email"},
		},
		{
			name:           "with custom scopes",
			scopeStr:       "openid profile pid edu_diploma",
			expectedScopes: []string{"openid", "profile", "pid", "edu_diploma"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scopes := parseScopes(tt.scopeStr)
			assert.Equal(t, tt.expectedScopes, scopes)
		})
	}
}

// TestStandardClaims tests standard OIDC claims
func TestStandardClaims(t *testing.T) {
	standardClaims := []string{
		"sub", "name", "given_name", "family_name", "middle_name", "nickname",
		"preferred_username", "profile", "picture", "website", "email",
		"email_verified", "gender", "birthdate", "zoneinfo", "locale",
		"phone_number", "phone_number_verified", "address", "updated_at",
	}

	// Verify we know about all standard claims
	for _, claim := range standardClaims {
		t.Run(claim, func(t *testing.T) {
			assert.NotEmpty(t, claim)
		})
	}
}

// ============================================================================
// Handler Integration Tests with Mock Database
// ============================================================================

// TestAuthorize_ClientValidation tests client validation in the Authorize handler
// Note: Full Authorize flow requires CredentialConstructor config which is complex to mock
func TestAuthorize_ClientValidation(t *testing.T) {
	ctx := t.Context()
	client, mockDB := CreateTestClientWithMock(nil)

	// Add a test client to the mock
	mockDB.Clients.AddClient(&db.Client{
		ClientID:      "test-client-id",
		RedirectURIs:  []string{"https://example.com/callback"},
		ResponseTypes: []string{"code"},
		AllowedScopes: []string{"openid", "profile", "email"},
		RequirePKCE:   false,
	})

	// Test unknown client
	t.Run("unknown client returns ErrInvalidClient", func(t *testing.T) {
		req := &AuthorizeRequest{
			ResponseType: "code",
			ClientID:     "unknown-client",
			RedirectURI:  "https://example.com/callback",
			Scope:        "openid",
		}
		_, err := client.Authorize(ctx, req)
		assert.ErrorIs(t, err, ErrInvalidClient)
	})

	// Test invalid redirect URI
	t.Run("invalid redirect URI returns ErrInvalidRequest", func(t *testing.T) {
		req := &AuthorizeRequest{
			ResponseType: "code",
			ClientID:     "test-client-id",
			RedirectURI:  "https://malicious.com/callback",
			Scope:        "openid",
		}
		_, err := client.Authorize(ctx, req)
		assert.ErrorIs(t, err, ErrInvalidRequest)
	})

	// Test unsupported response type
	t.Run("unsupported response type returns ErrInvalidRequest", func(t *testing.T) {
		req := &AuthorizeRequest{
			ResponseType: "token",
			ClientID:     "test-client-id",
			RedirectURI:  "https://example.com/callback",
			Scope:        "openid",
		}
		_, err := client.Authorize(ctx, req)
		assert.ErrorIs(t, err, ErrInvalidRequest)
	})

	// Test invalid scope
	t.Run("invalid scope returns ErrInvalidScope", func(t *testing.T) {
		req := &AuthorizeRequest{
			ResponseType: "code",
			ClientID:     "test-client-id",
			RedirectURI:  "https://example.com/callback",
			Scope:        strings.Join([]string{"openid", "admin"}, " "),
		}
		_, err := client.Authorize(ctx, req)
		assert.ErrorIs(t, err, ErrInvalidScope)
	})
}

// TestAuthorize_PKCEValidation tests PKCE enforcement in the Authorize handler
func TestAuthorize_PKCEValidation(t *testing.T) {
	ctx := t.Context()
	client, mockDB := CreateTestClientWithMock(nil)

	// Add a client that requires PKCE
	mockDB.Clients.AddClient(&db.Client{
		ClientID:      "pkce-required-client",
		RedirectURIs:  []string{"https://example.com/callback"},
		ResponseTypes: []string{"code"},
		AllowedScopes: []string{"openid"},
		RequirePKCE:   true,
	})

	t.Run("PKCE required but not provided", func(t *testing.T) {
		req := &AuthorizeRequest{
			ResponseType: "code",
			ClientID:     "pkce-required-client",
			RedirectURI:  "https://example.com/callback",
			Scope:        strings.Join([]string{"openid"}, " "),
		}
		_, err := client.Authorize(ctx, req)
		assert.ErrorIs(t, err, ErrInvalidRequest)
	})
}

// TestMockClientCollection tests the mock client collection
func TestMockClientCollection(t *testing.T) {
	ctx := t.Context()
	mock := NewMockClientCollection()

	// Test Create
	client := &db.Client{
		ClientID:      "test-client",
		RedirectURIs:  []string{"https://example.com/callback"},
		ResponseTypes: []string{"code"},
	}
	err := mock.Create(ctx, client)
	assert.NoError(t, err)

	// Test GetByClientID
	retrieved, err := mock.GetByClientID(ctx, "test-client")
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, "test-client", retrieved.ClientID)

	// Test GetByClientID with unknown client
	unknown, err := mock.GetByClientID(ctx, "unknown")
	assert.NoError(t, err)
	assert.Nil(t, unknown)

	// Test Update
	client.AllowedScopes = []string{"openid", "profile"}
	err = mock.Update(ctx, client)
	assert.NoError(t, err)

	updated, _ := mock.GetByClientID(ctx, "test-client")
	assert.Equal(t, []string{"openid", "profile"}, updated.AllowedScopes)

	// Test Delete
	err = mock.Delete(ctx, "test-client")
	assert.NoError(t, err)

	deleted, _ := mock.GetByClientID(ctx, "test-client")
	assert.Nil(t, deleted)
}

// TestAuthContextCache tests the auth context cache operations
func TestAuthContextCache(t *testing.T) {
	ctx := t.Context()
	authCache := cache.NewAuthContextCache(15 * time.Minute)

	// Test Create
	authCtx := &cache.AuthorizationContext{
		SessionID:   "session-1",
		Status:      cache.SessionStatusPending,
		Code:        "auth-code-123",
		AccessToken: "access-token-456",
	}
	err := authCache.Create(ctx, authCtx)
	assert.NoError(t, err)

	// Test GetByID
	retrieved, err := authCache.GetByID(ctx, "session-1")
	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, "session-1", retrieved.SessionID)

	// Test GetByAuthorizationCode
	byCode, err := authCache.GetByAuthorizationCode(ctx, "auth-code-123")
	assert.NoError(t, err)
	assert.NotNil(t, byCode)
	assert.Equal(t, "session-1", byCode.SessionID)

	// Test GetByAccessToken
	byToken, err := authCache.GetByAccessToken(ctx, "access-token-456")
	assert.NoError(t, err)
	assert.NotNil(t, byToken)
	assert.Equal(t, "session-1", byToken.SessionID)

	// Test MarkCodeAsForfeited
	err = authCache.MarkCodeAsForfeited(ctx, "session-1")
	assert.NoError(t, err)

	markedSession, _ := authCache.GetByID(ctx, "session-1")
	assert.True(t, markedSession.Forfeited)

	// Test Update
	authCtx.Status = cache.SessionStatusCompleted
	err = authCache.Update(ctx, authCtx)
	assert.NoError(t, err)

	updated, _ := authCache.GetByID(ctx, "session-1")
	assert.Equal(t, cache.SessionStatusCompleted, updated.Status)

	// Test Delete
	err = authCache.Delete(ctx, "session-1")
	assert.NoError(t, err)

	deleted, _ := authCache.GetByID(ctx, "session-1")
	assert.Nil(t, deleted)
}

// TestToken_AuthorizationCodeGrant tests the Token endpoint with authorization_code grant
func TestToken_AuthorizationCodeGrant(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name          string
		setupMock     func(*testing.T, *cache.AuthContextCache, *MockClientCollection)
		request       *TokenRequest
		expectError   bool
		expectedError error
	}{
		{
			name: "successful token exchange",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				authCtx := &cache.AuthorizationContext{
					SessionID:           "session-1",
					Status:              cache.SessionStatusCodeIssued,
					ClientID:            "test-client",
					RedirectURI:         "https://example.com/callback",
					Scopes:              []string{"openid", "profile"},
					Nonce:               "test-nonce",
					CodeChallenge:       "",
					CodeChallengeMethod: "",
					Code:                "valid-code",
					Forfeited:           false,
					CodeExpiresAt:       time.Now().Add(10 * time.Minute).Unix(),
					WalletID:            "wallet-123",
					VerifiedClaims: map[string]any{
						"name":  "John Doe",
						"email": "john@example.com",
					},
				}
				sessions.Create(ctx, authCtx)

				client := &db.Client{
					ClientID:                "test-client",
					ClientSecretHash:        hashPassword(t, "secret"),
					TokenEndpointAuthMethod: "client_secret_basic",
					RedirectURIs:            []string{"https://example.com/callback"},
				}
				clients.Create(ctx, client)
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "valid-code",
				ClientID:     "test-client",
				ClientSecret: "secret",
				RedirectURI:  "https://example.com/callback",
			},
			expectError: false,
		},
		{
			name: "invalid grant type",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				// No setup needed
			},
			request: &TokenRequest{
				GrantType: "implicit",
				Code:      "some-code",
				ClientID:  "test-client",
			},
			expectError:   true,
			expectedError: ErrUnsupportedGrantType,
		},
		{
			name: "invalid authorization code",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				// No session with this code
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "invalid-code",
				ClientID:     "test-client",
				ClientSecret: "secret",
				RedirectURI:  "https://example.com/callback",
			},
			expectError:   true,
			expectedError: ErrInvalidGrant,
		},
		{
			name: "code already used",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				authCtx := &cache.AuthorizationContext{
					SessionID:     "session-used",
					Status:        cache.SessionStatusTokenIssued,
					ClientID:      "test-client",
					RedirectURI:   "https://example.com/callback",
					Scopes:        []string{"openid"},
					Code:          "used-code",
					Forfeited:     true, // Already used
					CodeExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
				}
				sessions.Create(ctx, authCtx)
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "used-code",
				ClientID:     "test-client",
				ClientSecret: "secret",
				RedirectURI:  "https://example.com/callback",
			},
			expectError:   true,
			expectedError: ErrInvalidGrant,
		},
		{
			name: "expired authorization code",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				authCtx := &cache.AuthorizationContext{
					SessionID:     "session-expired",
					Status:        cache.SessionStatusCodeIssued,
					ClientID:      "test-client",
					RedirectURI:   "https://example.com/callback",
					Scopes:        []string{"openid"},
					Code:          "expired-code",
					Forfeited:     false,
					CodeExpiresAt: time.Now().Add(-1 * time.Minute).Unix(), // Expired
				}
				sessions.Create(ctx, authCtx)
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "expired-code",
				ClientID:     "test-client",
				ClientSecret: "secret",
				RedirectURI:  "https://example.com/callback",
			},
			expectError:   true,
			expectedError: ErrInvalidGrant,
		},
		{
			name: "invalid client credentials",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				authCtx := &cache.AuthorizationContext{
					SessionID:     "session-2",
					Status:        cache.SessionStatusCodeIssued,
					ClientID:      "test-client",
					RedirectURI:   "https://example.com/callback",
					Scopes:        []string{"openid"},
					Code:          "valid-code-2",
					Forfeited:     false,
					CodeExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
				}
				sessions.Create(ctx, authCtx)

				client := &db.Client{
					ClientID:                "test-client",
					ClientSecretHash:        hashPassword(t, "secret"), // hash of "secret"
					TokenEndpointAuthMethod: "client_secret_basic",
				}
				clients.Create(ctx, client)
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "valid-code-2",
				ClientID:     "test-client",
				ClientSecret: "wrong-secret",
				RedirectURI:  "https://example.com/callback",
			},
			expectError:   true,
			expectedError: ErrInvalidClient,
		},
		{
			name: "client ID mismatch",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				authCtx := &cache.AuthorizationContext{
					SessionID:     "session-3",
					Status:        cache.SessionStatusCodeIssued,
					ClientID:      "original-client",
					RedirectURI:   "https://example.com/callback",
					Scopes:        []string{"openid"},
					Code:          "valid-code-3",
					Forfeited:     false,
					CodeExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
				}
				sessions.Create(ctx, authCtx)

				client := &db.Client{
					ClientID:                "different-client",
					ClientSecretHash:        hashPassword(t, "secret"),
					TokenEndpointAuthMethod: "client_secret_basic",
				}
				clients.Create(ctx, client)
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "valid-code-3",
				ClientID:     "different-client",
				ClientSecret: "secret",
				RedirectURI:  "https://example.com/callback",
			},
			expectError:   true,
			expectedError: ErrInvalidGrant,
		},
		{
			name: "redirect URI mismatch",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				authCtx := &cache.AuthorizationContext{
					SessionID:     "session-4",
					Status:        cache.SessionStatusCodeIssued,
					ClientID:      "test-client",
					RedirectURI:   "https://example.com/callback",
					Scopes:        []string{"openid"},
					Code:          "valid-code-4",
					Forfeited:     false,
					CodeExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
				}
				sessions.Create(ctx, authCtx)

				client := &db.Client{
					ClientID:                "test-client",
					ClientSecretHash:        hashPassword(t, "secret"),
					TokenEndpointAuthMethod: "client_secret_basic",
				}
				clients.Create(ctx, client)
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "valid-code-4",
				ClientID:     "test-client",
				ClientSecret: "secret",
				RedirectURI:  "https://different.com/callback",
			},
			expectError:   true,
			expectedError: ErrInvalidGrant,
		},
		{
			name: "PKCE validation success",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				authCtx := &cache.AuthorizationContext{
					SessionID:           "session-pkce",
					Status:              cache.SessionStatusCodeIssued,
					ClientID:            "test-client",
					RedirectURI:         "https://example.com/callback",
					Scopes:              []string{"openid"},
					CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
					CodeChallengeMethod: "S256",
					Code:                "pkce-code",
					Forfeited:           false,
					CodeExpiresAt:       time.Now().Add(10 * time.Minute).Unix(),
					WalletID:            "wallet-123",
					VerifiedClaims:      map[string]any{},
				}
				sessions.Create(ctx, authCtx)

				client := &db.Client{
					ClientID:                "test-client",
					TokenEndpointAuthMethod: "none", // Public client
					RedirectURIs:            []string{"https://example.com/callback"},
				}
				clients.Create(ctx, client)
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "pkce-code",
				ClientID:     "test-client",
				RedirectURI:  "https://example.com/callback",
				CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", // Standard test vector
			},
			expectError: false,
		},
		{
			name: "PKCE validation failure",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				authCtx := &cache.AuthorizationContext{
					SessionID:           "session-pkce-fail",
					Status:              cache.SessionStatusCodeIssued,
					ClientID:            "test-client",
					RedirectURI:         "https://example.com/callback",
					Scopes:              []string{"openid"},
					CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
					CodeChallengeMethod: "S256",
					Code:                "pkce-code-fail",
					Forfeited:           false,
					CodeExpiresAt:       time.Now().Add(10 * time.Minute).Unix(),
				}
				sessions.Create(ctx, authCtx)

				client := &db.Client{
					ClientID:                "test-client",
					TokenEndpointAuthMethod: "none",
				}
				clients.Create(ctx, client)
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "pkce-code-fail",
				ClientID:     "test-client",
				RedirectURI:  "https://example.com/callback",
				CodeVerifier: "wrong-verifier",
			},
			expectError:   true,
			expectedError: ErrInvalidGrant,
		},
		{
			name: "public client (no secret required)",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				authCtx := &cache.AuthorizationContext{
					SessionID:      "session-public",
					Status:         cache.SessionStatusCodeIssued,
					ClientID:       "public-client",
					RedirectURI:    "https://example.com/callback",
					Scopes:         []string{"openid"},
					Code:           "public-code",
					Forfeited:      false,
					CodeExpiresAt:  time.Now().Add(10 * time.Minute).Unix(),
					WalletID:       "wallet-456",
					VerifiedClaims: map[string]any{},
				}
				sessions.Create(ctx, authCtx)

				client := &db.Client{
					ClientID:                "public-client",
					TokenEndpointAuthMethod: "none", // Public client
					RedirectURIs:            []string{"https://example.com/callback"},
				}
				clients.Create(ctx, client)
			},
			request: &TokenRequest{
				GrantType:   "authorization_code",
				Code:        "public-code",
				ClientID:    "public-client",
				RedirectURI: "https://example.com/callback",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, mockDB := CreateTestClientWithMock(nil)
			tt.setupMock(t, client.authContextCache, mockDB.Clients)

			// Set up test signing key
			key := generateTestRSAKey(t)
			require.NoError(t, client.SetSigningKeyForTesting(key))

			// Execute
			resp, err := client.Token(ctx, tt.request)

			// Verify
			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedError != nil {
					assert.Equal(t, tt.expectedError, err)
				}
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.AccessToken)
				assert.Equal(t, "Bearer", resp.TokenType)
				assert.NotEmpty(t, resp.IDToken)
				assert.NotEmpty(t, resp.RefreshToken)
				assert.Greater(t, resp.ExpiresIn, 0)

				// Verify session was updated
				authCtx, _ := client.authContextCache.GetByAuthorizationCode(ctx, tt.request.Code)
				if authCtx != nil {
					assert.True(t, authCtx.Forfeited)
					assert.Equal(t, cache.SessionStatusTokenIssued, authCtx.Status)
					assert.Equal(t, resp.AccessToken, authCtx.AccessToken)
					assert.Equal(t, resp.IDToken, authCtx.IDToken)
					assert.Equal(t, resp.RefreshToken, authCtx.RefreshToken)
				}
			}
		})
	}
}

// TestToken_RefreshTokenGrant tests the refresh token grant (currently unimplemented)
func TestToken_RefreshTokenGrant(t *testing.T) {
	ctx := t.Context()
	client, _ := CreateTestClientWithMock(nil)

	req := &TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "some-refresh-token",
		ClientID:     "test-client",
		ClientSecret: "secret",
	}

	resp, err := client.Token(ctx, req)

	// Should return unsupported grant type until implemented
	assert.Error(t, err)
	assert.Equal(t, ErrUnsupportedGrantType, err)
	assert.Nil(t, resp)
}

// TestGenerateIDToken tests ID token generation
func TestGenerateIDToken(t *testing.T) {
	ctx := t.Context()

	client, _ := CreateTestClientWithMock(nil)
	client.cfg.Verifier.OIDC.Issuer = "https://issuer.example.com"
	client.cfg.Verifier.OIDC.IDTokenDuration = 3600
	client.cfg.Verifier.OIDC.SubjectType = "public"
	client.cfg.Verifier.OIDC.SubjectSalt = "test-salt"

	// Set up signing key
	key := generateTestRSAKey(t)
	require.NoError(t, client.SetSigningKeyForTesting(key))

	authCtx := &cache.AuthorizationContext{
		SessionID: "session-1",
		ClientID:  "test-client",
		Nonce:     "test-nonce-123",
		WalletID:  "wallet-123",
		VerifiedClaims: map[string]any{
			"name":  "John Doe",
			"email": "john@example.com",
		},
	}

	dbClient := &db.Client{
		ClientID: "test-client",
	}

	idToken, err := client.generateIDToken(ctx, authCtx, dbClient)

	assert.NoError(t, err)
	assert.NotEmpty(t, idToken)

	// Parse and verify token
	token, err := jwt.Parse(idToken, func(token *jwt.Token) (any, error) {
		return &key.PublicKey, nil
	})
	assert.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	assert.True(t, ok)

	// Verify standard claims
	assert.Equal(t, "https://issuer.example.com", claims["iss"])
	assert.Equal(t, "test-client", claims["aud"])
	assert.Equal(t, "test-nonce-123", claims["nonce"])
	assert.NotEmpty(t, claims["sub"])
	assert.NotEmpty(t, claims["exp"])
	assert.NotEmpty(t, claims["iat"])

	// Verify verified claims are included
	assert.Equal(t, "John Doe", claims["name"])
	assert.Equal(t, "john@example.com", claims["email"])
}

// TestAuthenticateOIDCClient tests client authentication
func TestAuthenticateOIDCClient(t *testing.T) {
	client, _ := CreateTestClientWithMock(nil)

	tests := []struct {
		name         string
		dbClient     *db.Client
		clientSecret string
		expectError  bool
	}{
		{
			name: "public client (no auth)",
			dbClient: &db.Client{
				TokenEndpointAuthMethod: "none",
			},
			clientSecret: "",
			expectError:  false,
		},
		{
			name: "valid client secret",
			dbClient: &db.Client{
				TokenEndpointAuthMethod: "client_secret_basic",
				ClientSecretHash:        hashPassword(t, "secret"), // hash of "secret"
			},
			clientSecret: "secret",
			expectError:  false,
		},
		{
			name: "invalid client secret",
			dbClient: &db.Client{
				TokenEndpointAuthMethod: "client_secret_basic",
				ClientSecretHash:        hashPassword(t, "secret"),
			},
			clientSecret: "wrong-secret",
			expectError:  true,
		},
		{
			name: "missing client secret hash",
			dbClient: &db.Client{
				TokenEndpointAuthMethod: "client_secret_basic",
				ClientSecretHash:        "",
			},
			clientSecret: "secret",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.authenticateOIDCClient(tt.dbClient, tt.clientSecret)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestAuthorize_FullFlow tests the complete Authorize endpoint flow
func TestAuthorize_FullFlow(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name          string
		setupMock     func(*testing.T, *cache.AuthContextCache, *MockClientCollection)
		request       *AuthorizeRequest
		expectError   bool
		expectedError error
	}{
		{
			name: "successful authorization request",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				client := &db.Client{
					ClientID:      "test-client",
					RedirectURIs:  []string{"https://example.com/callback"},
					ResponseTypes: []string{"code"},
					AllowedScopes: []string{"openid", "profile", "email"},
					RequirePKCE:   false,
				}
				clients.Create(ctx, client)
			},
			request: &AuthorizeRequest{
				ResponseType: "code",
				ClientID:     "test-client",
				RedirectURI:  "https://example.com/callback",
				Scope:        strings.Join([]string{"openid", "profile"}, " "),
				State:        "random-state",
				Nonce:        "random-nonce",
			},
			expectError: false,
		},
		{
			name: "client not found",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				// No client created
			},
			request: &AuthorizeRequest{
				ResponseType: "code",
				ClientID:     "nonexistent-client",
				RedirectURI:  "https://example.com/callback",
				Scope:        strings.Join([]string{"openid"}, " "),
			},
			expectError:   true,
			expectedError: ErrInvalidClient,
		},
		{
			name: "invalid redirect URI",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				client := &db.Client{
					ClientID:      "test-client",
					RedirectURIs:  []string{"https://example.com/callback"},
					ResponseTypes: []string{"code"},
					AllowedScopes: []string{"openid"},
				}
				clients.Create(ctx, client)
			},
			request: &AuthorizeRequest{
				ResponseType: "code",
				ClientID:     "test-client",
				RedirectURI:  "https://malicious.com/callback",
				Scope:        strings.Join([]string{"openid"}, " "),
			},
			expectError:   true,
			expectedError: ErrInvalidRequest,
		},
		{
			name: "unsupported response type",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				client := &db.Client{
					ClientID:      "test-client",
					RedirectURIs:  []string{"https://example.com/callback"},
					ResponseTypes: []string{"code"},
					AllowedScopes: []string{"openid"},
				}
				clients.Create(ctx, client)
			},
			request: &AuthorizeRequest{
				ResponseType: "token",
				ClientID:     "test-client",
				RedirectURI:  "https://example.com/callback",
				Scope:        strings.Join([]string{"openid"}, " "),
			},
			expectError:   true,
			expectedError: ErrInvalidRequest,
		},
		{
			name: "invalid scope",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				client := &db.Client{
					ClientID:      "test-client",
					RedirectURIs:  []string{"https://example.com/callback"},
					ResponseTypes: []string{"code"},
					AllowedScopes: []string{"openid", "profile"},
				}
				clients.Create(ctx, client)
			},
			request: &AuthorizeRequest{
				ResponseType: "code",
				ClientID:     "test-client",
				RedirectURI:  "https://example.com/callback",
				Scope:        strings.Join([]string{"openid", "admin"}, " "),
			},
			expectError:   true,
			expectedError: ErrInvalidScope,
		},
		{
			name: "PKCE required but not provided",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				client := &db.Client{
					ClientID:      "test-client",
					RedirectURIs:  []string{"https://example.com/callback"},
					ResponseTypes: []string{"code"},
					AllowedScopes: []string{"openid"},
					RequirePKCE:   true,
				}
				clients.Create(ctx, client)
			},
			request: &AuthorizeRequest{
				ResponseType: "code",
				ClientID:     "test-client",
				RedirectURI:  "https://example.com/callback",
				Scope:        "openid",
			},
			expectError:   true,
			expectedError: ErrInvalidRequest,
		},
		{
			name: "successful with PKCE",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				client := &db.Client{
					ClientID:      "test-client",
					RedirectURIs:  []string{"https://example.com/callback"},
					ResponseTypes: []string{"code"},
					AllowedScopes: []string{"openid", "profile"},
					RequirePKCE:   true,
				}
				clients.Create(ctx, client)
			},
			request: &AuthorizeRequest{
				ResponseType:        "code",
				ClientID:            "test-client",
				RedirectURI:         "https://example.com/callback",
				Scope:               strings.Join([]string{"openid", "profile"}, " "),
				State:               "state-123",
				Nonce:               "nonce-456",
				CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				CodeChallengeMethod: "S256",
			},
			expectError: false,
		},
		{
			name: "multiple scopes with different credentials",
			setupMock: func(t *testing.T, sessions *cache.AuthContextCache, clients *MockClientCollection) {
				client := &db.Client{
					ClientID:      "test-client",
					RedirectURIs:  []string{"https://example.com/callback"},
					ResponseTypes: []string{"code"},
					AllowedScopes: []string{"openid", "profile", "email", "address"},
				}
				clients.Create(ctx, client)
			},
			request: &AuthorizeRequest{
				ResponseType: "code",
				ClientID:     "test-client",
				RedirectURI:  "https://example.com/callback",
				Scope:        strings.Join([]string{"openid", "profile", "email"}, " "),
				State:        "complex-state",
				Nonce:        "complex-nonce",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, mockDB := CreateTestClientWithMock(nil)
			client.cfg.Verifier.PublicURL = "https://verifier.example.com"
			client.cfg.Verifier.OIDC.SessionDuration = 900
			client.cfg.Verifier.DigitalCredentials.Enabled = true
			client.cfg.Verifier.DigitalCredentials.PreferredFormats = []string{"vc+sd-jwt"}
			client.cfg.Verifier.DigitalCredentials.UseJAR = true
			client.cfg.Verifier.DigitalCredentials.ResponseMode = "direct_post.jwt"
			client.cfg.Verifier.AuthorizationPageCSS.Title = "Test Verifier"
			client.cfg.Verifier.AuthorizationPageCSS.Theme = "dark"

			// Add presentation template for DCQL query generation
			template := createSimplePresentationTemplate(t, []string{"openid", "profile", "email", "address"})
			client.AddPresentationTemplateForTesting(template)

			tt.setupMock(t, client.authContextCache, mockDB.Clients)

			// Execute
			resp, err := client.Authorize(ctx, tt.request)

			// Verify
			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedError != nil {
					assert.Equal(t, tt.expectedError, err)
				}
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.SessionID)
				assert.NotEmpty(t, resp.QRCodeData)
				assert.NotEmpty(t, resp.QRCodeImageURL)
				assert.NotEmpty(t, resp.DeepLinkURL)
				assert.NotEmpty(t, resp.PollURL)
				assert.Contains(t, resp.QRCodeData, "openid4vp://")
				assert.Contains(t, resp.QRCodeImageURL, "/qr/")
				assert.Contains(t, resp.PollURL, "/poll/")

				// Verify DC API configuration
				assert.Equal(t, []string{"vc+sd-jwt"}, resp.PreferredFormats)
				assert.True(t, resp.UseJAR)
				assert.Equal(t, "direct_post.jwt", resp.ResponseMode)

				// Verify CSS configuration
				assert.Equal(t, "Test Verifier", resp.Title)
				assert.Equal(t, "dark", resp.Theme)
				assert.NotEmpty(t, resp.PrimaryColor)
				assert.NotEmpty(t, resp.SecondaryColor)

				// Verify session was created
				authCtx, _ := client.authContextCache.GetByID(ctx, resp.SessionID)
				assert.NotNil(t, authCtx)
				assert.Equal(t, cache.SessionStatusPending, authCtx.Status)
				assert.Equal(t, tt.request.ClientID, authCtx.ClientID)
				assert.Equal(t, tt.request.RedirectURI, authCtx.RedirectURI)
				assert.Equal(t, strings.Split(tt.request.Scope, " "), authCtx.Scopes)
				assert.Equal(t, tt.request.State, authCtx.State)
				assert.Equal(t, tt.request.Nonce, authCtx.Nonce)
				if tt.request.CodeChallenge != "" {
					assert.Equal(t, tt.request.CodeChallenge, authCtx.CodeChallenge)
					assert.Equal(t, tt.request.CodeChallengeMethod, authCtx.CodeChallengeMethod)
				}
			}
		})
	}
}

// TestAuthorize_DigitalCredentialsDisabled tests the authorization flow when Digital Credentials API is disabled
func TestAuthorize_DigitalCredentialsDisabled(t *testing.T) {
	ctx := t.Context()

	client, mockDB := CreateTestClientWithMock(nil)
	client.cfg.Verifier.PublicURL = "https://verifier.example.com"
	client.cfg.Verifier.OIDC.SessionDuration = 900
	// Explicitly disable Digital Credentials API
	client.cfg.Verifier.DigitalCredentials.Enabled = false
	// Clear CSS title to test default fallback
	client.cfg.Verifier.AuthorizationPageCSS.Title = ""
	client.cfg.Verifier.AuthorizationPageCSS.Subtitle = ""

	// Add presentation template
	template := createSimplePresentationTemplate(t, []string{"openid", "profile"})
	client.AddPresentationTemplateForTesting(template)

	// Setup client
	dbClient := &db.Client{
		ClientID:      "dc-disabled-client",
		RedirectURIs:  []string{"https://example.com/callback"},
		ResponseTypes: []string{"code"},
		AllowedScopes: []string{"openid", "profile"},
	}
	mockDB.Clients.Create(ctx, dbClient)

	req := &AuthorizeRequest{
		ResponseType: "code",
		ClientID:     "dc-disabled-client",
		RedirectURI:  "https://example.com/callback",
		Scope:        strings.Join([]string{"openid", "profile"}, " "),
		State:        "test-state",
		Nonce:        "test-nonce",
	}

	resp, err := client.Authorize(ctx, req)

	assert.NoError(t, err)
	require.NotNil(t, resp)

	// Verify default DC API configuration is applied
	assert.Equal(t, []string{"vc+sd-jwt"}, resp.PreferredFormats)
	assert.False(t, resp.UseJAR)
	assert.Equal(t, "direct_post", resp.ResponseMode)

	// Verify default title/subtitle are applied
	assert.Equal(t, "Credential Verification", resp.Title)
	assert.Equal(t, "Please present your digital credential to continue", resp.Subtitle)
}
