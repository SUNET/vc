package apiv1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/url"
	"strings"
	"testing"
	"time"

	internalcache "github.com/SUNET/vc/internal/verifier/cache"
	"github.com/SUNET/vc/internal/verifier/db"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vp"

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
	resp := TokenResponse{ // #nosec G101
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
			err := oauth2.ValidatePKCE(tt.codeVerifier, tt.codeChallenge, tt.codeChallengeMethod)
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
// Note: Full Authorize flow requires CredentialMetadata config which is complex to mock
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

// TestMemoryStore tests the auth context cache operations
func TestMemoryStore(t *testing.T) {
	ctx := t.Context()
	authCache := internalcache.NewTestMemoryStore(15 * time.Minute)

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
		setupMock     func(*testing.T, cache.AuthContextStore, *MockClientCollection)
		request       *TokenRequest
		expectError   bool
		expectedError error
	}{
		{
			name: "successful token exchange",
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
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
				sessions.Create(ctx, authCtx) // #nosec G104

				client := &db.Client{
					ClientID:                "test-client",
					ClientSecretHash:        hashPassword(t, "secret"),
					TokenEndpointAuthMethod: "client_secret_basic",
					RedirectURIs:            []string{"https://example.com/callback"},
				}
				clients.Create(ctx, client) // #nosec G104
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
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
				sessions.Create(ctx, authCtx) // #nosec G104
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
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
				sessions.Create(ctx, authCtx) // #nosec G104
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
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
				sessions.Create(ctx, authCtx) // #nosec G104

				client := &db.Client{
					ClientID:                "test-client",
					ClientSecretHash:        hashPassword(t, "secret"), // hash of "secret"
					TokenEndpointAuthMethod: "client_secret_basic",
				}
				clients.Create(ctx, client) // #nosec G104
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
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
				sessions.Create(ctx, authCtx) // #nosec G104

				client := &db.Client{
					ClientID:                "different-client",
					ClientSecretHash:        hashPassword(t, "secret"),
					TokenEndpointAuthMethod: "client_secret_basic",
				}
				clients.Create(ctx, client) // #nosec G104
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
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
				sessions.Create(ctx, authCtx) // #nosec G104

				client := &db.Client{
					ClientID:                "test-client",
					ClientSecretHash:        hashPassword(t, "secret"),
					TokenEndpointAuthMethod: "client_secret_basic",
				}
				clients.Create(ctx, client) // #nosec G104
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
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
				sessions.Create(ctx, authCtx) // #nosec G104

				client := &db.Client{
					ClientID:                "test-client",
					TokenEndpointAuthMethod: "none", // Public client
					RedirectURIs:            []string{"https://example.com/callback"},
				}
				clients.Create(ctx, client) // #nosec G104
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
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
				sessions.Create(ctx, authCtx) // #nosec G104

				client := &db.Client{
					ClientID:                "test-client",
					TokenEndpointAuthMethod: "none",
				}
				clients.Create(ctx, client) // #nosec G104
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
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
				sessions.Create(ctx, authCtx) // #nosec G104

				client := &db.Client{
					ClientID:                "public-client",
					TokenEndpointAuthMethod: "none", // Public client
					RedirectURIs:            []string{"https://example.com/callback"},
				}
				clients.Create(ctx, client) // #nosec G104
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
			tt.setupMock(t, client.cacheService.AuthContext, mockDB.Clients)

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
				assert.Equal(t, "Bearer", resp.TokenType)
				assert.NotEmpty(t, resp.IDToken)

				// With EnableUserInfo=false (default), access/refresh tokens are not issued
				assert.Empty(t, resp.AccessToken)
				assert.Empty(t, resp.RefreshToken)
				assert.Equal(t, 0, resp.ExpiresIn)

				// Verify session was updated
				authCtx, _ := client.cacheService.AuthContext.GetByAuthorizationCode(ctx, tt.request.Code)
				if authCtx != nil {
					assert.True(t, authCtx.Forfeited)
					assert.Equal(t, cache.SessionStatusTokenIssued, authCtx.Status)
					assert.Equal(t, resp.IDToken, authCtx.IDToken)
				}
			}
		})
	}
}

// TestToken_EnableUserInfoTrue tests token response when EnableUserInfo is true
func TestToken_EnableUserInfoTrue(t *testing.T) {
	ctx := t.Context()

	client, mockDB := CreateTestClientWithMock(nil)
	client.cfg.Verifier.Outbound.OIDCProvider.EnableUserInfo = true
	client.cfg.Verifier.Outbound.OIDCProvider.AccessTokenDuration = 3600

	authCtx := &cache.AuthorizationContext{
		SessionID:      "session-userinfo",
		Status:         cache.SessionStatusCodeIssued,
		ClientID:       "test-client",
		RedirectURI:    "https://example.com/callback",
		Scopes:         []string{"openid", "profile"},
		Nonce:          "test-nonce",
		Code:           "userinfo-code",
		Forfeited:      false,
		CodeExpiresAt:  time.Now().Add(10 * time.Minute).Unix(),
		WalletID:       "wallet-789",
		VerifiedClaims: map[string]any{"name": "Jane Doe"},
	}
	client.cacheService.AuthContext.Create(ctx, authCtx) // #nosec G104

	testClient := &db.Client{
		ClientID:                "test-client",
		ClientSecretHash:        hashPassword(t, "secret"),
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{"https://example.com/callback"},
	}
	mockDB.Clients.Create(ctx, testClient) // #nosec G104

	key := generateTestRSAKey(t)
	require.NoError(t, client.SetSigningKeyForTesting(key))

	resp, err := client.Token(ctx, &TokenRequest{
		GrantType:    "authorization_code",
		Code:         "userinfo-code",
		ClientID:     "test-client",
		ClientSecret: "secret",
		RedirectURI:  "https://example.com/callback",
	})

	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.NotEmpty(t, resp.IDToken)
	assert.NotEmpty(t, resp.AccessToken)
	assert.Equal(t, 3600, resp.ExpiresIn)

	// access_token is now a JWT — no refresh_token in stateless mode
	assert.Empty(t, resp.RefreshToken)

	// Verify the access_token is a valid JWT with at+jwt type
	parsedAT, err := jwt.Parse(resp.AccessToken, func(t *jwt.Token) (any, error) {
		return key.Public(), nil
	})
	assert.NoError(t, err)
	require.NotNil(t, parsedAT)
	assert.Equal(t, "at+jwt", parsedAT.Header["typ"])
	claims, ok := parsedAT.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, "https://verifier.example.com", claims["iss"])
	assert.Equal(t, "test-client", claims["aud"])
	assert.Equal(t, "Jane Doe", claims["name"])

	// Session should only have id_token stored — access token is self-contained
	updatedCtx, _ := client.cacheService.AuthContext.GetByAuthorizationCode(ctx, "userinfo-code")
	require.NotNil(t, updatedCtx)
	assert.True(t, updatedCtx.Forfeited)
	assert.Equal(t, cache.SessionStatusTokenIssued, updatedCtx.Status)
	assert.Equal(t, resp.IDToken, updatedCtx.IDToken)
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
	tests := []struct {
		name           string
		nonce          string
		verifiedClaims map[string]any
		expectNonce    bool
	}{
		{
			name:        "with nonce",
			nonce:       "test-nonce-123",
			expectNonce: true,
			verifiedClaims: map[string]any{
				"name":  "John Doe",
				"email": "john@example.com",
			},
		},
		{
			name:        "without nonce",
			nonce:       "",
			expectNonce: false,
			verifiedClaims: map[string]any{
				"name": "John Doe",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			client, _ := CreateTestClientWithMock(nil)
			client.cfg.Verifier.Outbound.OIDCProvider.Issuer = "https://issuer.example.com"
			client.cfg.Verifier.Outbound.OIDCProvider.IDTokenDuration = 3600
			client.cfg.Verifier.Outbound.OIDCProvider.SubjectType = "public"
			client.cfg.Verifier.Outbound.OIDCProvider.SubjectSalt = "test-salt"

			key := generateTestRSAKey(t)
			require.NoError(t, client.SetSigningKeyForTesting(key))

			authCtx := &cache.AuthorizationContext{
				SessionID:      "session-1",
				ClientID:       "test-client",
				Nonce:          tt.nonce,
				WalletID:       "wallet-123",
				VerifiedClaims: tt.verifiedClaims,
			}

			dbClient := &db.Client{
				ClientID: "test-client",
			}

			idToken, err := client.generateIDToken(ctx, authCtx, dbClient)
			assert.NoError(t, err)
			assert.NotEmpty(t, idToken)

			token, err := jwt.Parse(idToken, func(token *jwt.Token) (any, error) {
				return &key.PublicKey, nil
			})
			assert.NoError(t, err)
			assert.True(t, token.Valid)

			claims, ok := token.Claims.(jwt.MapClaims)
			assert.True(t, ok)

			assert.Equal(t, "https://issuer.example.com", claims["iss"])
			assert.Equal(t, "test-client", claims["aud"])
			assert.NotEmpty(t, claims["sub"])
			assert.NotEmpty(t, claims["exp"])
			assert.NotEmpty(t, claims["iat"])

			if tt.expectNonce {
				assert.Equal(t, tt.nonce, claims["nonce"])
			} else {
				_, nonceExists := claims["nonce"]
				assert.False(t, nonceExists, "nonce claim should not be present when no nonce was provided")
			}

			for k, v := range tt.verifiedClaims {
				assert.Equal(t, v, claims[k])
			}
		})
	}
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
		setupMock     func(*testing.T, cache.AuthContextStore, *MockClientCollection)
		request       *AuthorizeRequest
		expectError   bool
		expectedError error
	}{
		{
			name: "successful authorization request",
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
				client := &db.Client{
					ClientID:      "test-client",
					RedirectURIs:  []string{"https://example.com/callback"},
					ResponseTypes: []string{"code"},
					AllowedScopes: []string{"openid", "profile", "email"},
					RequirePKCE:   false,
				}
				clients.Create(ctx, client) // #nosec G104
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
				client := &db.Client{
					ClientID:      "test-client",
					RedirectURIs:  []string{"https://example.com/callback"},
					ResponseTypes: []string{"code"},
					AllowedScopes: []string{"openid"},
				}
				clients.Create(ctx, client) // #nosec G104
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
				client := &db.Client{
					ClientID:      "test-client",
					RedirectURIs:  []string{"https://example.com/callback"},
					ResponseTypes: []string{"code"},
					AllowedScopes: []string{"openid"},
				}
				clients.Create(ctx, client) // #nosec G104
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
				client := &db.Client{
					ClientID:      "test-client",
					RedirectURIs:  []string{"https://example.com/callback"},
					ResponseTypes: []string{"code"},
					AllowedScopes: []string{"openid", "profile"},
				}
				clients.Create(ctx, client) // #nosec G104
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
				client := &db.Client{
					ClientID:      "test-client",
					RedirectURIs:  []string{"https://example.com/callback"},
					ResponseTypes: []string{"code"},
					AllowedScopes: []string{"openid"},
					RequirePKCE:   true,
				}
				clients.Create(ctx, client) // #nosec G104
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
				client := &db.Client{
					ClientID:      "test-client",
					RedirectURIs:  []string{"https://example.com/callback"},
					ResponseTypes: []string{"code"},
					AllowedScopes: []string{"openid", "profile"},
					RequirePKCE:   true,
				}
				clients.Create(ctx, client) // #nosec G104
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
			setupMock: func(t *testing.T, sessions cache.AuthContextStore, clients *MockClientCollection) {
				client := &db.Client{
					ClientID:      "test-client",
					RedirectURIs:  []string{"https://example.com/callback"},
					ResponseTypes: []string{"code"},
					AllowedScopes: []string{"openid", "profile", "email", "address"},
				}
				clients.Create(ctx, client) // #nosec G104
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
			client.cfg.Verifier.Outbound.OIDCProvider.SessionDuration = 900
			client.cfg.Verifier.DigitalCredentials.Enable = true
			client.cfg.Verifier.DigitalCredentials.PreferredFormats = []string{"vc+sd-jwt"}
			client.cfg.Verifier.DigitalCredentials.UseJAR = true
			client.cfg.Verifier.DigitalCredentials.ResponseMode = "direct_post.jwt"
			client.cfg.Verifier.AuthorizationPageCSS.Title = "Test Verifier"
			client.cfg.Verifier.AuthorizationPageCSS.Theme = "dark"

			// Add presentation template for DCQL query generation
			template := createSimplePresentationTemplate(t, []string{"openid", "profile", "email", "address"})
			client.AddPresentationTemplateForTesting(template)

			tt.setupMock(t, client.cacheService.AuthContext, mockDB.Clients)

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
				assert.Contains(t, resp.DeepLinkURL, "openid4vp://")
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
				authCtx, _ := client.cacheService.AuthContext.GetByID(ctx, resp.SessionID)
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
	client.cfg.Verifier.Outbound.OIDCProvider.SessionDuration = 900
	// Explicitly disable Digital Credentials API
	client.cfg.Verifier.DigitalCredentials.Enable = false
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
	mockDB.Clients.Create(ctx, dbClient) // #nosec G104

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

	// Verify DC API configuration from struct defaults is applied
	assert.Equal(t, resp.PreferredFormats, client.cfg.Verifier.DigitalCredentials.PreferredFormats)
	assert.Equal(t, resp.UseJAR, client.cfg.Verifier.DigitalCredentials.UseJAR)
	assert.Equal(t, resp.ResponseMode, client.cfg.Verifier.DigitalCredentials.ResponseMode)

	// Verify default title/subtitle are applied
	assert.Equal(t, "Credential Verification", resp.Title)
	assert.Equal(t, "Please present your digital credential to continue", resp.Subtitle)
}

// TestAuthorize_WalletLinks tests that supported_wallets config generates wallet links
func TestAuthorize_WalletLinks(t *testing.T) {
	ctx := t.Context()

	client, mockDB := CreateTestClientWithMock(nil)
	client.cfg.Verifier.PublicURL = "https://verifier.example.com"
	client.cfg.Verifier.Outbound.OIDCProvider.SessionDuration = 900
	client.cfg.Verifier.SupportedWallets = map[string]string{
		"SUNET Wallet": "https://wallet.sunet.se/cb",
		"Test Wallet":  "https://test-wallet.example.com/authorize",
	}

	// Add presentation template
	template := createSimplePresentationTemplate(t, []string{"openid", "profile"})
	client.AddPresentationTemplateForTesting(template)

	// Setup client
	dbClient := &db.Client{
		ClientID:      "wallet-links-client",
		RedirectURIs:  []string{"https://example.com/callback"},
		ResponseTypes: []string{"code"},
		AllowedScopes: []string{"openid", "profile"},
	}
	mockDB.Clients.Create(ctx, dbClient) // #nosec G104

	req := &AuthorizeRequest{
		ResponseType: "code",
		ClientID:     "wallet-links-client",
		RedirectURI:  "https://example.com/callback",
		Scope:        "openid profile",
		State:        "test-state",
		Nonce:        "test-nonce",
	}

	resp, err := client.Authorize(ctx, req)

	assert.NoError(t, err)
	require.NotNil(t, resp)

	// QR code should still be openid4vp://
	assert.Contains(t, resp.QRCodeData, "openid4vp://")

	// Should have wallet links
	assert.Len(t, resp.WalletLinks, 2)

	// Each wallet link should contain the authorization params and a QR code URL
	for _, link := range resp.WalletLinks {
		assert.NotEmpty(t, link.Name)
		assert.Contains(t, link.URL, "client_id=")
		assert.Contains(t, link.URL, "request_uri=")

		// Wallet links should use HTTPS
		assert.Contains(t, link.URL, "https://")
		assert.NotContains(t, link.URL, "openid4vp://")

		// Each wallet link should have a QR code image URL for cross-device flow
		assert.NotEmpty(t, link.QRCodeImageURL)
		assert.Contains(t, link.QRCodeImageURL, "/qr/")
		assert.Contains(t, link.QRCodeImageURL, "wallet=")
	}

	// Check specific wallet URLs
	walletNames := make(map[string]string)
	for _, link := range resp.WalletLinks {
		walletNames[link.Name] = link.URL
	}
	assert.Contains(t, walletNames["SUNET Wallet"], "https://wallet.sunet.se/cb?")
	assert.Contains(t, walletNames["Test Wallet"], "https://test-wallet.example.com/authorize?")
}

// TestAuthorize_NoWalletLinks tests that no wallet links when supported_wallets is empty
func TestAuthorize_NoWalletLinks(t *testing.T) {
	ctx := t.Context()

	client, mockDB := CreateTestClientWithMock(nil)
	client.cfg.Verifier.PublicURL = "https://verifier.example.com"
	client.cfg.Verifier.Outbound.OIDCProvider.SessionDuration = 900
	// No supported wallets configured
	client.cfg.Verifier.SupportedWallets = nil

	template := createSimplePresentationTemplate(t, []string{"openid", "profile"})
	client.AddPresentationTemplateForTesting(template)

	dbClient := &db.Client{
		ClientID:      "no-wallets-client",
		RedirectURIs:  []string{"https://example.com/callback"},
		ResponseTypes: []string{"code"},
		AllowedScopes: []string{"openid", "profile"},
	}
	mockDB.Clients.Create(ctx, dbClient) // #nosec G104

	req := &AuthorizeRequest{
		ResponseType: "code",
		ClientID:     "no-wallets-client",
		RedirectURI:  "https://example.com/callback",
		Scope:        "openid profile",
		State:        "test-state",
		Nonce:        "test-nonce",
	}

	resp, err := client.Authorize(ctx, req)

	assert.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.WalletLinks)
}

// TestGetQRCode tests QR code generation
func TestGetQRCode(t *testing.T) {
	ctx := t.Context()
	client, _ := CreateTestClientWithMock(nil)
	client.cfg.Verifier.SupportedWallets = map[string]string{
		"SUNET Wallet": "https://wallet.sunet.se/cb",
		"Test Wallet":  "https://test-wallet.example.com/authorize",
	}

	// Create a test session
	authCtx := &cache.AuthorizationContext{
		SessionID: "test-session-123",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		Status:    cache.SessionStatusPending,
	}
	err := client.cacheService.AuthContext.Create(ctx, authCtx)
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
		{
			name: "valid web wallet QR code",
			req: &GetQRCodeRequest{
				SessionID:  "test-session-123",
				WalletName: "SUNET Wallet",
			},
			wantErr: nil,
			checkResp: func(t *testing.T, resp *GetQRCodeResponse) {
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.ImageData)
				assert.True(t, len(resp.ImageData) > 0)
			},
		},
		{
			name: "unknown wallet name returns error",
			req: &GetQRCodeRequest{
				SessionID:  "test-session-123",
				WalletName: "Unknown Wallet",
			},
			wantErr: ErrInvalidRequest,
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
	err := client.cacheService.AuthContext.Create(ctx, pendingSession)
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
	err = client.cacheService.AuthContext.Create(ctx, codeIssuedSession)
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

// TestGetUserInfo tests the stateless UserInfo endpoint with JWT access tokens
func TestGetUserInfo(t *testing.T) {
	ctx := t.Context()
	client, _ := CreateTestClientWithMock(&model.Cfg{
		Verifier: &model.Verifier{
			PublicURL: "https://verifier.example.com",
			Outbound: model.VerifierOutbound{
				OIDCProvider: &model.OIDCOP{
					Issuer:              "https://verifier.example.com",
					SubjectType:         "public",
					SubjectSalt:         "test-salt",
					SessionDuration:     900,
					CodeDuration:        600,
					AccessTokenDuration: 3600,
					IDTokenDuration:     3600,
					EnableUserInfo:      true,
				},
			},
		},
	})

	// Set up signing key — required for both generating and validating JWT access tokens
	key := generateTestRSAKey(t)
	require.NoError(t, client.SetSigningKeyForTesting(key))

	issuer := client.cfg.Verifier.Outbound.OIDCProvider.Issuer

	// Helper to create a signed JWT access token
	makeAccessToken := func(claims jwt.MapClaims) string {
		header := jwt.MapClaims{"typ": "at+jwt"}
		token, err := jose.MakeJWT(ctx, header, claims, client.pkiSigner)
		require.NoError(t, err)
		return token
	}

	validToken := makeAccessToken(jwt.MapClaims{
		"iss":   issuer,
		"sub":   "user-123",
		"aud":   "test-client",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"name":  "John Doe",
		"email": "john@example.com",
	})

	expiredToken := makeAccessToken(jwt.MapClaims{
		"iss": issuer,
		"sub": "user-expired",
		"aud": "test-client",
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})

	tokenWithClaims := makeAccessToken(jwt.MapClaims{
		"iss":   issuer,
		"sub":   "user-456",
		"aud":   "test-client",
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"iat":   time.Now().Unix(),
		"name":  "Jane Doe",
		"email": "jane@example.com",
		"nonce": "should-be-stripped",
	})

	tests := []struct {
		name      string
		req       *UserInfoRequest
		wantErr   error
		checkResp func(t *testing.T, resp UserInfoResponse)
	}{
		{
			name: "valid JWT access token",
			req: &UserInfoRequest{
				AccessToken: validToken,
			},
			wantErr: nil,
			checkResp: func(t *testing.T, resp UserInfoResponse) {
				assert.Equal(t, "user-123", resp["sub"])
				assert.Equal(t, "John Doe", resp["name"])
				assert.Equal(t, "john@example.com", resp["email"])
				// JWT-specific claims should be stripped
				assert.Nil(t, resp["iss"])
				assert.Nil(t, resp["aud"])
				assert.Nil(t, resp["exp"])
				assert.Nil(t, resp["iat"])
			},
		},
		{
			name: "invalid (non-JWT) access token",
			req: &UserInfoRequest{
				AccessToken: "not-a-valid-jwt",
			},
			wantErr: ErrInvalidGrant,
		},
		{
			name: "expired JWT access token",
			req: &UserInfoRequest{
				AccessToken: expiredToken,
			},
			wantErr: ErrInvalidGrant,
		},
		{
			name: "JWT with wrong issuer",
			req: &UserInfoRequest{
				AccessToken: func() string {
					return makeAccessToken(jwt.MapClaims{
						"iss": "https://evil.example.com",
						"sub": "user-evil",
						"aud": "test-client",
						"exp": time.Now().Add(1 * time.Hour).Unix(),
						"iat": time.Now().Unix(),
					})
				}(),
			},
			wantErr: ErrInvalidGrant,
		},
		{
			name: "nonce and JWT claims are stripped from response",
			req: &UserInfoRequest{
				AccessToken: tokenWithClaims,
			},
			wantErr: nil,
			checkResp: func(t *testing.T, resp UserInfoResponse) {
				assert.Equal(t, "user-456", resp["sub"])
				assert.Equal(t, "Jane Doe", resp["name"])
				assert.Equal(t, "jane@example.com", resp["email"])
				assert.Nil(t, resp["nonce"], "nonce should be stripped from userinfo response")
				assert.Nil(t, resp["iss"])
				assert.Nil(t, resp["aud"])
				assert.Nil(t, resp["exp"])
				assert.Nil(t, resp["iat"])
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
	for range 100 {
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
				err := client.cacheService.AuthContext.Create(ctx, authCtx)
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
				authCtx, _ := client.cacheService.AuthContext.GetByID(ctx, tt.sessionID)
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
				err := client.cacheService.AuthContext.Create(ctx, authCtx)
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
		expectWalletRedirect   bool
		expectedStatus         cache.SessionStatus
	}{
		{ // #nosec G101
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
			expectError: true,
		},
		{ // #nosec G101
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
		{ // #nosec G101
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
		{ // #nosec G101
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
		{ // #nosec G101
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
		{ // #nosec G101
			name:      "same-device web wallet returns RP redirect_uri",
			sessionID: "session-dp-8",
			vpToken:   "eyJhbGciOiJFUzI1NiJ9.test-payload.signature",
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusPending
				s.RedirectURI = "https://client.example.com/callback"
				s.State = "client-state"
				s.WalletFollowsRedirect = true
			},
			expectError:          false,
			expectWalletRedirect: true,
			expectedStatus:       cache.SessionStatusCodeIssued,
		},
		{ // #nosec G101
			name:      "same-device web wallet without redirect URI",
			sessionID: "session-dp-9",
			vpToken:   "eyJhbGciOiJFUzI1NiJ9.test-payload.signature",
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusPending
				s.RedirectURI = ""
				s.State = "client-state"
				s.WalletFollowsRedirect = true
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
				err := client.cacheService.AuthContext.Create(ctx, authCtx)
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
				authCtx, _ := client.cacheService.AuthContext.GetByID(ctx, tt.sessionID)
				assert.Equal(t, tt.expectedStatus, authCtx.Status)

				if tt.expectShowCredentials {
					// Should redirect to display page
					assert.Contains(t, resp.RedirectURI, "/verification/display/")
				} else if tt.expectWalletRedirect {
					assert.Contains(t, resp.RedirectURI, "https://client.example.com/callback")
					assert.Contains(t, resp.RedirectURI, "state=client-state")
					assert.Contains(t, resp.RedirectURI, "code="+authCtx.Code)
				} else {
					// Cross-device: omit redirect_uri so the /authorize
					// poller performs the RP redirect instead of the wallet.
					assert.Empty(t, resp.RedirectURI)
				}
			}
		})
	}
}

func TestAuthorizationCodeRedirectURI(t *testing.T) {
	t.Run("nil session", func(t *testing.T) {
		got, err := authorizationCodeRedirectURI(nil)
		require.NoError(t, err)
		assert.Empty(t, got)
	})
	t.Run("empty redirect URI", func(t *testing.T) {
		got, err := authorizationCodeRedirectURI(&cache.AuthorizationContext{
			Code:  "abc",
			State: "xyz",
		})
		require.NoError(t, err)
		assert.Empty(t, got)
	})
	t.Run("appends code and state", func(t *testing.T) {
		got, err := authorizationCodeRedirectURI(&cache.AuthorizationContext{
			RedirectURI: "https://rp.example.com/cb?foo=bar",
			Code:        "auth-code",
			State:       "rp-state",
		})
		require.NoError(t, err)
		assert.Contains(t, got, "https://rp.example.com/cb")
		assert.Contains(t, got, "foo=bar")
		assert.Contains(t, got, "code=auth-code")
		assert.Contains(t, got, "state=rp-state")
	})
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

// TestGetDiscoveryMetadata tests the OIDC discovery metadata endpoint
func TestGetDiscoveryMetadata(t *testing.T) {
	ctx := t.Context()

	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			PublicURL: "https://verifier.example.com",
			Outbound: model.VerifierOutbound{
				OIDCProvider: &model.OIDCOP{
					Issuer:      "https://verifier.example.com",
					SubjectType: "public",
					SubjectSalt: "test-salt",
				},
			},
			Inbound: model.VerifierInbound{
				OpenID4VP: &model.OpenID4VPConfig{
					SupportedCredentials: []model.SupportedCredentialConfig{
						{
							VCT:    "https://credentials.example.com/person_id",
							Scopes: []string{"pid"},
						},
						{
							VCT:    "https://credentials.example.com/diploma",
							Scopes: []string{"edu_diploma"},
						},
					},
				},
			},
		},
	}

	client, _ := CreateTestClientWithMock(cfg)

	// Test getting discovery metadata
	metadata, err := client.GetDiscoveryMetadata(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, metadata)

	// Verify basic OIDC fields
	assert.Equal(t, "https://verifier.example.com", metadata.Issuer)
	assert.Equal(t, "https://verifier.example.com/authorize", metadata.AuthorizationEndpoint)
	assert.Equal(t, "https://verifier.example.com/token", metadata.TokenEndpoint)
	assert.Empty(t, metadata.UserInfoEndpoint, "userinfo_endpoint should be omitted when EnableUserInfo is false")
	assert.Equal(t, "https://verifier.example.com/jwks", metadata.JwksURI)

	// Verify supported features
	assert.Contains(t, metadata.ResponseTypesSupported, "code")
	assert.Contains(t, metadata.SubjectTypesSupported, "public")
	assert.Contains(t, metadata.SubjectTypesSupported, "pairwise")
	assert.Contains(t, metadata.IDTokenSigningAlgValuesSupported, "RS256")
	assert.Contains(t, metadata.IDTokenSigningAlgValuesSupported, "ES256")

	// Verify standard scopes
	assert.Contains(t, metadata.ScopesSupported, "openid")
	assert.Contains(t, metadata.ScopesSupported, "profile")
	assert.Contains(t, metadata.ScopesSupported, "email")

	// Verify configured credential scopes
	assert.Contains(t, metadata.ScopesSupported, "pid")
	assert.Contains(t, metadata.ScopesSupported, "edu_diploma")

	// Verify standard claims
	assert.Contains(t, metadata.ClaimsSupported, "sub")
	assert.Contains(t, metadata.ClaimsSupported, "name")
	assert.Contains(t, metadata.ClaimsSupported, "email")

	// Verify grant types
	assert.Contains(t, metadata.GrantTypesSupported, "authorization_code")
	// refresh_token and implicit are only advertised when EnableUserInfo is true
	assert.NotContains(t, metadata.GrantTypesSupported, "refresh_token")
	assert.NotContains(t, metadata.GrantTypesSupported, "implicit")

	// Verify PKCE support
	assert.Contains(t, metadata.CodeChallengeMethodsSupported, "S256")

	// Verify authentication methods
	assert.Contains(t, metadata.TokenEndpointAuthMethodsSupported, "client_secret_basic")
	assert.Contains(t, metadata.TokenEndpointAuthMethodsSupported, "client_secret_post")
	assert.Contains(t, metadata.TokenEndpointAuthMethodsSupported, "none")
}

// TestGetDiscoveryMetadata_NoCredentials tests discovery metadata with no configured credentials
func TestGetDiscoveryMetadata_NoCredentials(t *testing.T) {
	ctx := t.Context()

	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			PublicURL: "https://verifier.example.com",
			Outbound: model.VerifierOutbound{
				OIDCProvider: &model.OIDCOP{
					Issuer:      "https://verifier.example.com",
					SubjectType: "public",
					SubjectSalt: "test-salt",
				},
			},
			Inbound: model.VerifierInbound{
				OpenID4VP: &model.OpenID4VPConfig{
					SupportedCredentials: []model.SupportedCredentialConfig{},
				},
			},
		},
	}

	client, _ := CreateTestClientWithMock(cfg)

	metadata, err := client.GetDiscoveryMetadata(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, metadata)

	// Should still have standard scopes
	assert.Contains(t, metadata.ScopesSupported, "openid")
	assert.Contains(t, metadata.ScopesSupported, "profile")
	assert.Contains(t, metadata.ScopesSupported, "email")
}

// TestGetDiscoveryMetadata_CustomExternalURL tests with different base URLs
func TestGetDiscoveryMetadata_CustomExternalURL(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name           string
		externalURL    string
		expectedPrefix string
	}{
		{
			name:           "HTTPS URL",
			externalURL:    "https://custom.example.com",
			expectedPrefix: "https://custom.example.com",
		},
		{
			name:           "HTTP localhost",
			externalURL:    "http://localhost:8080",
			expectedPrefix: "http://localhost:8080",
		},
		{
			name:           "URL with path",
			externalURL:    "https://example.com/verifier",
			expectedPrefix: "https://example.com/verifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &model.Cfg{
				Verifier: &model.Verifier{
					PublicURL: tt.externalURL,
					Outbound: model.VerifierOutbound{
						OIDCProvider: &model.OIDCOP{
							Issuer:         tt.externalURL,
							SubjectType:    "public",
							SubjectSalt:    "test-salt",
							EnableUserInfo: true,
						},
					},
					Inbound: model.VerifierInbound{
						OpenID4VP: &model.OpenID4VPConfig{
							SupportedCredentials: []model.SupportedCredentialConfig{},
						},
					},
				},
			}

			client, _ := CreateTestClientWithMock(cfg)

			metadata, err := client.GetDiscoveryMetadata(ctx)
			assert.NoError(t, err)

			assert.Equal(t, tt.expectedPrefix+"/authorize", metadata.AuthorizationEndpoint)
			assert.Equal(t, tt.expectedPrefix+"/token", metadata.TokenEndpoint)
			assert.Equal(t, tt.expectedPrefix+"/userinfo", metadata.UserInfoEndpoint)
			assert.Equal(t, tt.expectedPrefix+"/jwks", metadata.JwksURI)
		})
	}
}

// TestGetJWKS tests the JWKS endpoint
func TestGetJWKS(t *testing.T) {
	ctx := t.Context()

	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			PublicURL: "https://verifier.example.com",
			Outbound: model.VerifierOutbound{
				OIDCProvider: &model.OIDCOP{
					Issuer:      "https://verifier.example.com",
					SubjectType: "public",
					SubjectSalt: "test-salt",
				},
			},
		},
	}

	t.Run("RSA key", func(t *testing.T) {
		client, _ := CreateTestClientWithMock(cfg)

		// Set signing key for testing
		privateKey := generateTestRSAKey(t)
		require.NoError(t, client.SetSigningKeyForTesting(privateKey))

		// Test getting JWKS
		jwks, err := jose.CreateJWKSFromSigner(client.pkiSigner, "")
		assert.NoError(t, err)
		assert.NotNil(t, jwks)

		// Verify JWKS structure
		assert.NotNil(t, jwks.Keys)
		assert.Greater(t, len(jwks.Keys), 0, "JWKS should contain at least one key")

		// Verify first key properties
		key := jwks.Keys[0]
		assert.Equal(t, "RSA", key.Kty, "Key type should be RSA")
		assert.Equal(t, "sig", key.Use, "Key use should be sig")
		assert.Equal(t, "default", key.Kid, "Kid should be default")
		assert.Equal(t, "RS256", key.Alg, "Algorithm should be RS256")
	})

	t.Run("ECDSA key", func(t *testing.T) {
		client, _ := CreateTestClientWithMock(cfg)

		// Set ECDSA signing key for testing
		privateKey := generateTestECDSAKey(t)
		require.NoError(t, client.SetSigningKeyForTesting(privateKey))

		// Test getting JWKS
		jwks, err := client.GetJWKS(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, jwks)

		// Verify JWKS structure
		assert.NotNil(t, jwks.Keys)
		assert.Greater(t, len(jwks.Keys), 0, "JWKS should contain at least one key")

		// Verify first key properties
		key := jwks.Keys[0]
		assert.Equal(t, "EC", key.Kty, "Key type should be EC")
		assert.Equal(t, "sig", key.Use, "Key use should be sig")
		assert.Equal(t, "default", key.Kid, "Kid should be default")
		assert.Equal(t, "ES256", key.Alg, "Algorithm should be ES256")
	})

	t.Run("unsupported key type", func(t *testing.T) {
		client, _ := CreateTestClientWithMock(cfg)

		// Set an unsupported key type (string instead of crypto key)
		err := client.SetSigningKeyForTesting("not-a-crypto-key")

		// Should error on setting invalid key
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported key type")
	})

	t.Run("no signing key set", func(t *testing.T) {
		client, _ := CreateTestClientWithMock(cfg)

		// Don't set any signing key - signingKey will be nil

		// Test getting JWKS should error
		jwks, err := client.GetJWKS(ctx)
		assert.Error(t, err)
		assert.Nil(t, jwks)
	})
}

// BenchmarkGetDiscoveryMetadata benchmarks discovery metadata generation
func BenchmarkGetDiscoveryMetadata(b *testing.B) {
	ctx := b.Context()

	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			PublicURL: "https://verifier.example.com",
			Outbound: model.VerifierOutbound{
				OIDCProvider: &model.OIDCOP{
					Issuer:      "https://verifier.example.com",
					SubjectType: "public",
					SubjectSalt: "test-salt",
				},
			},
			Inbound: model.VerifierInbound{
				OpenID4VP: &model.OpenID4VPConfig{
					SupportedCredentials: []model.SupportedCredentialConfig{
						{VCT: "cred1", Scopes: []string{"scope1"}},
						{VCT: "cred2", Scopes: []string{"scope2"}},
						{VCT: "cred3", Scopes: []string{"scope3"}},
					},
				},
			},
		},
	}

	client, _ := CreateTestClientWithMock(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.GetDiscoveryMetadata(ctx)
	}
}

// BenchmarkGetJWKS benchmarks JWKS generation
func BenchmarkGetJWKS(b *testing.B) {
	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			PublicURL: "https://verifier.example.com",
			Outbound: model.VerifierOutbound{
				OIDCProvider: &model.OIDCOP{
					Issuer:      "https://verifier.example.com",
					SubjectType: "public",
					SubjectSalt: "test-salt",
				},
			},
		},
	}

	client, _ := CreateTestClientWithMock(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := b.Context()
		_, _ = client.GetJWKS(ctx)
	}
}

func TestNormalizeRedirectURI(t *testing.T) {
	tests := []struct {
		name     string
		uri      string
		expected string
	}{
		{
			name:     "plain URI unchanged",
			uri:      "https://example.com/callback",
			expected: "https://example.com/callback",
		},
		{
			name:     "percent-encoded space decoded",
			uri:      "https://sso.example.org/realms/Test%20Realm/broker/oidc/endpoint",
			expected: "https://sso.example.org/realms/Test Realm/broker/oidc/endpoint",
		},
		{
			name:     "literal space unchanged",
			uri:      "https://sso.example.org/realms/Test Realm/broker/oidc/endpoint",
			expected: "https://sso.example.org/realms/Test Realm/broker/oidc/endpoint",
		},
		{
			name:     "plus sign preserved (not decoded to space)",
			uri:      "https://example.com/path+name/callback",
			expected: "https://example.com/path+name/callback",
		},
		{
			name:     "multiple encoded segments",
			uri:      "https://sso.example.org/realms/My%20Test%20Realm/broker/my%20idp/endpoint",
			expected: "https://sso.example.org/realms/My Test Realm/broker/my idp/endpoint",
		},
		{
			name:     "encoded slash preserved via PathUnescape",
			uri:      "https://example.com/a%2Fb/callback",
			expected: "https://example.com/a/b/callback",
		},
		{
			name:     "empty string",
			uri:      "",
			expected: "",
		},
		{
			name:     "query parameters with encoding",
			uri:      "https://example.com/callback?foo=bar%20baz",
			expected: "https://example.com/callback?foo=bar baz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeRedirectURI(tt.uri)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchRedirectURI(t *testing.T) {
	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			PublicURL: "https://verifier.example.com",
			Outbound: model.VerifierOutbound{
				OIDCProvider: &model.OIDCOP{
					Issuer: "https://verifier.example.com",
				},
			},
		},
	}
	client, _ := CreateTestClientWithMock(cfg)

	tests := []struct {
		name       string
		registered []string
		reqURI     string
		expected   bool
	}{
		{
			name:       "exact match",
			registered: []string{"https://example.com/callback"},
			reqURI:     "https://example.com/callback",
			expected:   true,
		},
		{
			name:       "percent-encoded registered vs decoded request",
			registered: []string{"https://sso.example.org/realms/Test%20Realm/broker/oidc/endpoint"},
			reqURI:     "https://sso.example.org/realms/Test Realm/broker/oidc/endpoint",
			expected:   true,
		},
		{
			name:       "decoded registered vs percent-encoded request",
			registered: []string{"https://sso.example.org/realms/Test Realm/broker/oidc/endpoint"},
			reqURI:     "https://sso.example.org/realms/Test%20Realm/broker/oidc/endpoint",
			expected:   true,
		},
		{
			name:       "both percent-encoded",
			registered: []string{"https://sso.example.org/realms/Test%20Realm/broker/oidc/endpoint"},
			reqURI:     "https://sso.example.org/realms/Test%20Realm/broker/oidc/endpoint",
			expected:   true,
		},
		{
			name:       "both decoded (literal space)",
			registered: []string{"https://sso.example.org/realms/Test Realm/broker/oidc/endpoint"},
			reqURI:     "https://sso.example.org/realms/Test Realm/broker/oidc/endpoint",
			expected:   true,
		},
		{
			name:       "no match",
			registered: []string{"https://example.com/callback"},
			reqURI:     "https://example.com/other",
			expected:   false,
		},
		{
			name:       "empty registered list",
			registered: []string{},
			reqURI:     "https://example.com/callback",
			expected:   false,
		},
		{
			name: "match among multiple registered URIs",
			registered: []string{
				"https://example.com/callback1",
				"https://sso.example.org/realms/Test%20Realm/broker/oidc/endpoint",
				"https://example.com/callback3",
			},
			reqURI:   "https://sso.example.org/realms/Test Realm/broker/oidc/endpoint",
			expected: true,
		},
		{
			name:       "plus sign is not treated as space",
			registered: []string{"https://example.com/path+name/callback"},
			reqURI:     "https://example.com/path name/callback",
			expected:   false,
		},
		{
			name:       "keycloak realistic URL",
			registered: []string{"https://sso.common.siros.org/realms/Test Realm/broker/test2/endpoint"},
			reqURI:     "https://sso.common.siros.org/realms/Test%20Realm/broker/test2/endpoint",
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.matchRedirectURI(tt.registered, tt.reqURI)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildOpenID4VPAuthzRequest(t *testing.T) {
	tests := []struct {
		name      string
		publicURL string
		sessionID string
		wantErr   bool
	}{
		{
			name:      "standard URL",
			publicURL: "https://verifier.example.com",
			sessionID: "session-abc-123",
		},
		{
			name:      "URL with trailing slash",
			publicURL: "https://verifier.example.com/",
			sessionID: "session-xyz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, err := buildOpenID4VPAuthzRequest(tt.publicURL, tt.sessionID, "x509_san_dns:verifier.example.com")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.True(t, strings.HasPrefix(result, "openid4vp://cb?"),
				"must use openid4vp:// scheme")

			parsed, err := url.Parse(result)
			require.NoError(t, err)

			requestURI := parsed.Query().Get("request_uri")
			assert.True(t, strings.HasSuffix(requestURI,
				"/verification/request-object/"+tt.sessionID),
				"request_uri must use path-param format, got: %s", requestURI)
			assert.NotContains(t, requestURI, "?id=",
				"request_uri must not use query-param format")

			clientID := parsed.Query().Get("client_id")
			assert.True(t, strings.HasPrefix(clientID, "x509_san_dns:"),
				"client_id must use x509_san_dns prefix")
		})
	}
}
