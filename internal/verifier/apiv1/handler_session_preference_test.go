package apiv1

import (
	"testing"
	"time"
	"vc/internal/verifier/db"

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
			client, mockDB := CreateTestClientWithMock(nil)

			// Setup session if needed
			if tt.sessionExists {
				session := createTestDBSessionForPrefs(tt.sessionID)
				err := mockDB.Sessions.Create(ctx, session)
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
				session, _ := mockDB.Sessions.GetByID(ctx, tt.sessionID)
				assert.Equal(t, tt.preference, session.OIDCRequest.ShowCredentialDetails)
			}
		})
	}
}

// TestConfirmCredentialDisplay tests the ConfirmCredentialDisplay handler
func TestConfirmCredentialDisplay(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name              string
		sessionID         string
		confirmed         bool
		sessionSetup      func(*db.Session)
		expectError       bool
		expectCodeIssued  bool
		expectErrorInURI  bool
	}{
		{
			name:      "successful confirmation",
			sessionID: "session-confirm-1",
			confirmed: true,
			sessionSetup: func(s *db.Session) {
				s.Status = db.SessionStatusAwaitingPresentation
				s.OIDCRequest.RedirectURI = "https://client.example.com/callback"
				s.OIDCRequest.State = "client-state"
			},
			expectError:      false,
			expectCodeIssued: true,
		},
		{
			name:      "user cancelled",
			sessionID: "session-cancel-1",
			confirmed: false,
			sessionSetup: func(s *db.Session) {
				s.Status = db.SessionStatusAwaitingPresentation
				s.OIDCRequest.RedirectURI = "https://client.example.com/callback"
				s.OIDCRequest.State = "client-state"
			},
			expectError:     false,
			expectErrorInURI: true,
		},
		{
			name:      "wrong session status",
			sessionID: "session-wrong-status",
			confirmed: true,
			sessionSetup: func(s *db.Session) {
				s.Status = db.SessionStatusPending // Not awaiting presentation
			},
			expectError: true,
		},
		{
			name:         "session not found",
			sessionID:    "non-existent-session",
			confirmed:    true,
			sessionSetup: nil,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, mockDB := CreateTestClientWithMock(nil)

			// Setup session if needed
			if tt.sessionSetup != nil {
				session := createTestDBSessionForPrefs(tt.sessionID)
				tt.sessionSetup(session)
				err := mockDB.Sessions.Create(ctx, session)
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
					session, _ := mockDB.Sessions.GetByID(ctx, tt.sessionID)
					assert.Equal(t, db.SessionStatusCodeIssued, session.Status)
					assert.NotEmpty(t, session.Tokens.AuthorizationCode)
					assert.Contains(t, response.RedirectURI, "code=")
					assert.Contains(t, response.RedirectURI, "state=")
				}

				if tt.expectErrorInURI {
					// Verify error response in redirect URI
					assert.Contains(t, response.RedirectURI, "error=access_denied")
					// Session should be in error status
					session, _ := mockDB.Sessions.GetByID(ctx, tt.sessionID)
					assert.Equal(t, db.SessionStatusError, session.Status)
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
		sessionSetup  func(*db.Session)
		expectError   bool
		expectVPToken bool
	}{
		{
			name:      "successful retrieval with VP token",
			sessionID: "session-display-1",
			sessionSetup: func(s *db.Session) {
				s.OpenID4VP.VPToken = "eyJhbGciOiJFUzI1NiJ9.test.signature"
				s.VerifiedClaims = map[string]any{
					"given_name":  "John",
					"family_name": "Doe",
				}
				s.OIDCRequest.ClientID = "test-client"
				s.OIDCRequest.RedirectURI = "https://client.example.com/callback"
				s.OIDCRequest.State = "client-state"
			},
			expectError:   false,
			expectVPToken: true,
		},
		{
			name:      "session without VP token",
			sessionID: "session-no-vp",
			sessionSetup: func(s *db.Session) {
				// Don't set VP token
				s.OIDCRequest.ClientID = "test-client"
			},
			expectError: true,
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
				session := createTestDBSessionForPrefs(tt.sessionID)
				tt.sessionSetup(session)
				err := mockDB.Sessions.Create(ctx, session)
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
func createTestDBSessionForPrefs(sessionID string) *db.Session {
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
		OpenID4VP:      db.OpenID4VPSession{},
		Tokens:         db.TokenSet{},
		VerifiedClaims: make(map[string]any),
	}
}
