package apiv1

import (
	"testing"
	"time"
	"vc/pkg/cache"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUpdateSessionPreference tests the UpdateSessionPreference handler
func TestUpdateSessionPreference(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name          string
		sessionID     string
		preference    bool
		sessionExists bool
		expectError   bool
	}{
		{
			name:          "successful preference update (true)",
			sessionID:     "session-pref-1",
			preference:    true,
			sessionExists: true,
			expectError:   false,
		},
		{
			name:          "successful preference update (false)",
			sessionID:     "session-pref-2",
			preference:    false,
			sessionExists: true,
			expectError:   false,
		},
		{
			name:          "session not found",
			sessionID:     "non-existent-session",
			preference:    true,
			sessionExists: false,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := CreateTestClientWithMock(nil)

			// Setup session if needed
			if tt.sessionExists {
				authCtx := createTestDBSessionForPrefs(tt.sessionID)
				err := client.cacheService.AuthContext.Create(ctx, authCtx)
				require.NoError(t, err)
			}

			req := &UpdateSessionPreferenceRequest{
				SessionID:             tt.sessionID,
				ShowCredentialDetails: tt.preference,
			}

			response, err := client.UpdateSessionPreference(ctx, req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, response)
				assert.True(t, response.Success)

				// Verify preference was stored
				authCtx, _ := client.cacheService.AuthContext.GetByID(ctx, tt.sessionID)
				assert.Equal(t, tt.preference, authCtx.ShowCredentialDetails)
			}
		})
	}
}

// TestConfirmCredentialDisplay tests the ConfirmCredentialDisplay handler
func TestConfirmCredentialDisplay(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name             string
		sessionID        string
		confirmed        bool
		authCtxSetup     func(*cache.AuthorizationContext)
		expectError      bool
		expectCodeIssued bool
		expectErrorInURI bool
	}{
		{
			name:      "successful confirmation",
			sessionID: "session-confirm-1",
			confirmed: true,
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusAwaitingPresentation
				s.RedirectURI = "https://client.example.com/callback"
				s.State = "client-state"
			},
			expectError:      false,
			expectCodeIssued: true,
		},
		{
			name:      "user cancelled",
			sessionID: "session-cancel-1",
			confirmed: false,
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusAwaitingPresentation
				s.RedirectURI = "https://client.example.com/callback"
				s.State = "client-state"
			},
			expectError:      false,
			expectErrorInURI: true,
		},
		{
			name:      "wrong session status",
			sessionID: "session-wrong-status",
			confirmed: true,
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.Status = cache.SessionStatusPending // Not awaiting presentation
			},
			expectError: true,
		},
		{
			name:         "session not found",
			sessionID:    "non-existent-session",
			confirmed:    true,
			authCtxSetup: nil,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := CreateTestClientWithMock(nil)

			// Setup session if needed
			if tt.authCtxSetup != nil {
				authCtx := createTestDBSessionForPrefs(tt.sessionID)
				tt.authCtxSetup(authCtx)
				err := client.cacheService.AuthContext.Create(ctx, authCtx)
				require.NoError(t, err)
			}

			req := &ConfirmCredentialDisplayRequest{
				Confirmed: tt.confirmed,
			}

			response, err := client.ConfirmCredentialDisplay(ctx, tt.sessionID, req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, response)

				if tt.expectCodeIssued {
					// Verify code was issued
					authCtx, _ := client.cacheService.AuthContext.GetByID(ctx, tt.sessionID)
					assert.Equal(t, cache.SessionStatusCodeIssued, authCtx.Status)
					assert.NotEmpty(t, authCtx.Code)
					assert.Contains(t, response.RedirectURI, "code=")
					assert.Contains(t, response.RedirectURI, "state=")
				}

				if tt.expectErrorInURI {
					// Verify error response in redirect URI
					assert.Contains(t, response.RedirectURI, "error=access_denied")
					// Session should be in error status
					authCtx, _ := client.cacheService.AuthContext.GetByID(ctx, tt.sessionID)
					assert.Equal(t, cache.SessionStatusError, authCtx.Status)
				}
			}
		})
	}
}

// TestGetCredentialDisplayData tests the GetCredentialDisplayData handler
func TestGetCredentialDisplayData(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name          string
		sessionID     string
		authCtxSetup  func(*cache.AuthorizationContext)
		expectError   bool
		expectVPToken bool
	}{
		{
			name:      "successful retrieval with VP token",
			sessionID: "session-display-1",
			authCtxSetup: func(s *cache.AuthorizationContext) {
				s.VPToken = "eyJhbGciOiJFUzI1NiJ9.test.signature"
				s.VerifiedClaims = map[string]any{
					"given_name":  "John",
					"family_name": "Doe",
				}
				s.ClientID = "test-client"
				s.RedirectURI = "https://client.example.com/callback"
				s.State = "client-state"
			},
			expectError:   false,
			expectVPToken: true,
		},
		{
			name:      "session without VP token",
			sessionID: "session-no-vp",
			authCtxSetup: func(s *cache.AuthorizationContext) {
				// Don't set VP token
				s.ClientID = "test-client"
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

			// Setup session if needed
			if tt.authCtxSetup != nil {
				authCtx := createTestDBSessionForPrefs(tt.sessionID)
				tt.authCtxSetup(authCtx)
				err := client.cacheService.AuthContext.Create(ctx, authCtx)
				require.NoError(t, err)
			}

			req := &GetCredentialDisplayDataRequest{
				SessionID: tt.sessionID,
			}

			response, err := client.GetCredentialDisplayData(ctx, req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, response)

				if tt.expectVPToken {
					assert.NotEmpty(t, response.VPToken)
					assert.Equal(t, tt.sessionID, response.SessionID)
					assert.NotNil(t, response.Claims)
					assert.NotEmpty(t, response.ClientID)
					// Verify default colors are set
					assert.NotEmpty(t, response.PrimaryColor)
					assert.NotEmpty(t, response.SecondaryColor)
				}
			}
		})
	}
}

// Helper function for session preference tests
func createTestDBSessionForPrefs(sessionID string) *cache.AuthorizationContext {
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
