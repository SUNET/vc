package apiv1

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"vc/internal/verifier/db"
	"vc/pkg/helpers"
	"vc/pkg/model"

	"github.com/creasty/defaults"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// TestGenerateClientID tests client ID generation
func TestGenerateClientID(t *testing.T) {
	// Generate multiple client IDs and verify they're unique and correct format
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := generateClientID()
		require.NoError(t, err)
		assert.Len(t, id, 32, "client ID should be 32 hex characters (16 bytes)")

		// Verify it's valid hex
		_, err = hex.DecodeString(id)
		assert.NoError(t, err, "client ID should be valid hex")

		assert.False(t, ids[id], "client ID should be unique")
		ids[id] = true
	}
}

// TestGenerateClientSecret tests client secret generation
func TestGenerateClientSecret(t *testing.T) {
	// Generate multiple client secrets and verify they're unique
	secrets := make(map[string]bool)
	for i := 0; i < 100; i++ {
		secret, err := generateClientSecret()
		require.NoError(t, err)
		assert.NotEmpty(t, secret)

		// Base64 URL encoded 32 bytes should be 43 characters
		assert.Len(t, secret, 43, "client secret should be 43 base64url characters")

		assert.False(t, secrets[secret], "client secret should be unique")
		secrets[secret] = true
	}
}

// TestHashClientSecret tests client secret hashing with bcrypt
func TestHashClientSecret(t *testing.T) {
	// Generate test value dynamically to avoid static analysis false positives
	testValue := t.Name() + "-value"

	hash, err := hashClientSecret(testValue)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Verify the hash is valid bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(testValue))
	assert.NoError(t, err, "hash should verify against original value")

	// Verify different values produce different hashes (or at least don't match)
	wrongValue := t.Name() + "-wrong"
	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(wrongValue))
	assert.Error(t, err, "hash should not match different value")
}

// TestGenerateRegistrationAccessToken tests registration access token generation
func TestGenerateRegistrationAccessToken(t *testing.T) {
	// Generate multiple tokens and verify they're unique
	tokens := make(map[string]bool)
	for i := 0; i < 100; i++ {
		token, err := generateRegistrationAccessToken()
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Base64 URL encoded 32 bytes should be 43 characters
		assert.Len(t, token, 43, "registration access token should be 43 base64url characters")

		assert.False(t, tokens[token], "registration access token should be unique")
		tokens[token] = true
	}
}

// TestHashRegistrationAccessToken tests registration access token hashing
func TestHashRegistrationAccessToken(t *testing.T) {
	token := "test-token-12345"

	hash, err := hashRegistrationAccessToken(token)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	// Verify the hash is correct SHA256
	expectedHash := sha256.Sum256([]byte(token))
	expectedHashHex := hex.EncodeToString(expectedHash[:])
	assert.Equal(t, expectedHashHex, hash)

	// Verify it's 64 hex characters (32 bytes)
	assert.Len(t, hash, 64)
}

// TestVerifyRegistrationAccessToken tests token verification
func TestVerifyRegistrationAccessToken(t *testing.T) {
	token := "test-token-12345"
	hash, err := hashRegistrationAccessToken(token)
	require.NoError(t, err)

	tests := []struct {
		name      string
		token     string
		hash      string
		wantError bool
	}{
		{
			name:      "valid token and hash",
			token:     token,
			hash:      hash,
			wantError: false,
		},
		{
			name:      "wrong token",
			token:     "wrong-token",
			hash:      hash,
			wantError: true,
		},
		{
			name:      "wrong hash",
			token:     token,
			hash:      "0000000000000000000000000000000000000000000000000000000000000000",
			wantError: true,
		},
		{
			name:      "empty token",
			token:     "",
			hash:      hash,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyRegistrationAccessToken(tt.token, tt.hash)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestClientRegistrationRequest_Validation tests v10 validation tags on ClientRegistrationRequest
func TestClientRegistrationRequest_Validation(t *testing.T) {
	tests := []struct {
		name    string
		req     ClientRegistrationRequest
		wantErr bool
	}{
		{
			name: "valid minimal request",
			req: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			wantErr: false,
		},
		{
			name:    "missing redirect_uris",
			req:     ClientRegistrationRequest{ClientName: "Test Client"},
			wantErr: true,
		},
		{
			name: "empty redirect_uris",
			req: ClientRegistrationRequest{
				RedirectURIs: []string{},
			},
			wantErr: true,
		},
		{
			name: "invalid redirect URI (with fragment)",
			req: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback#section"},
			},
			wantErr: true,
		},
		{
			name: "valid token endpoint auth method - client_secret_basic",
			req: ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "client_secret_basic",
			},
			wantErr: false,
		},
		{
			name: "valid token endpoint auth method - none",
			req: ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "none",
			},
			wantErr: false,
		},
		{
			name: "invalid token endpoint auth method",
			req: ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "invalid_method",
			},
			wantErr: true,
		},
		{
			name: "valid grant types",
			req: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				GrantTypes:   []string{"authorization_code", "refresh_token"},
			},
			wantErr: false,
		},
		{
			name: "invalid grant type",
			req: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				GrantTypes:   []string{"implicit"},
			},
			wantErr: true,
		},
		{
			name: "valid response type - code",
			req: ClientRegistrationRequest{
				RedirectURIs:  []string{"https://example.com/callback"},
				ResponseTypes: []string{"code"},
			},
			wantErr: false,
		},
		{
			name: "invalid response type",
			req: ClientRegistrationRequest{
				RedirectURIs:  []string{"https://example.com/callback"},
				ResponseTypes: []string{"token"},
			},
			wantErr: true,
		},
		{
			name: "valid subject type - public",
			req: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				SubjectType:  "public",
			},
			wantErr: false,
		},
		{
			name: "invalid subject type",
			req: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				SubjectType:  "invalid",
			},
			wantErr: true,
		},
		{
			name: "both jwks_uri and jwks not allowed",
			req: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				JWKSUri:      "https://example.com/.well-known/jwks.json",
				JWKS:         map[string]any{"keys": []any{}},
			},
			wantErr: true,
		},
		{
			name: "valid logo_uri",
			req: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				LogoURI:      "https://example.com/logo.png",
			},
			wantErr: false,
		},
		{
			name: "invalid logo_uri - http not allowed",
			req: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				LogoURI:      "http://example.com/logo.png",
			},
			wantErr: true,
		},
		{
			name: "invalid client_uri - http not allowed",
			req: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				ClientURI:    "http://example.com",
			},
			wantErr: true,
		},
		{
			name: "invalid policy_uri - http not allowed",
			req: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				PolicyURI:    "http://example.com/policy",
			},
			wantErr: true,
		},
		{
			name: "invalid tos_uri - http not allowed",
			req: ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				TosURI:       "http://example.com/tos",
			},
			wantErr: true,
		},
		{
			name: "valid code challenge method - S256",
			req: ClientRegistrationRequest{
				RedirectURIs:        []string{"https://example.com/callback"},
				CodeChallengeMethod: "S256",
			},
			wantErr: false,
		},
		{
			name: "invalid code challenge method",
			req: ClientRegistrationRequest{
				RedirectURIs:        []string{"https://example.com/callback"},
				CodeChallengeMethod: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, defaults.Set(&tt.req))
			err := helpers.CheckSimple(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestClientRegistrationRequest_Defaults tests default tag values on ClientRegistrationRequest
func TestClientRegistrationRequest_Defaults(t *testing.T) {
	req := &ClientRegistrationRequest{
		RedirectURIs: []string{"https://example.com/callback"},
	}

	err := defaults.Set(req)
	require.NoError(t, err)

	assert.Equal(t, "client_secret_basic", req.TokenEndpointAuthMethod)
	assert.Equal(t, []string{"authorization_code"}, req.GrantTypes)
	assert.Equal(t, []string{"code"}, req.ResponseTypes)
	assert.Equal(t, "openid", req.Scope)
	assert.Equal(t, "web", req.ApplicationType)
	assert.Equal(t, "public", req.SubjectType)
	assert.Equal(t, "RS256", req.IDTokenSignedRespAlg)
	assert.Equal(t, "S256", req.CodeChallengeMethod)
}

// TestAuthenticateClient tests client authentication
func TestAuthenticateClient(t *testing.T) {
	ctx := t.Context()
	client, mockDB := CreateTestClientWithMock(nil)

	// Create a test client with a bcrypt-hashed credential
	// Generate test value dynamically to avoid static analysis false positives
	testCredential := t.Name() + "-cred"
	hashedCredential, _ := bcrypt.GenerateFromPassword([]byte(testCredential), bcrypt.DefaultCost)

	mockDB.Clients.AddClient(&db.Client{
		ClientID:         "test-client",
		ClientSecretHash: string(hashedCredential),
	})

	mockDB.Clients.AddClient(&db.Client{
		ClientID:         "test-client",
		ClientSecretHash: string(hashedCredential),
	})

	// Also test public client (auth_method = none)
	mockDB.Clients.AddClient(&db.Client{
		ClientID:                "public-client",
		ClientSecretHash:        "",
		TokenEndpointAuthMethod: "none",
	})

	// Define wrong values dynamically
	wrongAny := t.Name() + "-any"
	wrongCred := t.Name() + "-wrong"

	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		wantErr      error
		wantClient   bool
	}{
		{
			name:         "valid credentials with bcrypt",
			clientID:     "test-client",
			clientSecret: testCredential, // Provide plaintext credential
			wantErr:      nil,
			wantClient:   true,
		},
		{
			name:         "unknown client",
			clientID:     "unknown-client",
			clientSecret: wrongAny,
			wantErr:      ErrInvalidClient,
			wantClient:   false,
		},
		{
			name:         "wrong credential",
			clientID:     "test-client",
			clientSecret: wrongCred,
			wantErr:      ErrInvalidClient,
			wantClient:   false,
		},
		{
			name:         "public client needs no credential",
			clientID:     "public-client",
			clientSecret: "",
			wantErr:      nil,
			wantClient:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := client.authenticateClient(ctx, tt.clientID, tt.clientSecret)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				if tt.wantClient {
					assert.NotNil(t, result)
					assert.Equal(t, tt.clientID, result.ClientID)
				}
			}
		})
	}
}

// TestRegisterClient tests the dynamic client registration endpoint
func TestRegisterClient(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name        string
		request     *ClientRegistrationRequest
		expectError bool
	}{
		{
			name: "successful minimal registration",
			request: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			expectError: false,
		},
		{
			name: "successful full registration",
			request: &ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback", "https://example.com/callback2"},
				TokenEndpointAuthMethod: "client_secret_basic",
				GrantTypes:              []string{"authorization_code", "refresh_token"},
				ResponseTypes:           []string{"code"},
				ClientName:              "Test Application",
				ClientURI:               "https://example.com",
				LogoURI:                 "https://example.com/logo.png",
				Scope:                   "openid profile email",
				Contacts:                []string{"admin@example.com"},
				TosURI:                  "https://example.com/tos",
				PolicyURI:               "https://example.com/privacy",
				SoftwareID:              "test-software-1",
				SoftwareVersion:         "1.0.0",
				ApplicationType:         "web",
				SubjectType:             "pairwise",
				CodeChallengeMethod:     "S256",
			},
			expectError: false,
		},
		{
			name: "registration with PKCE required",
			request: &ClientRegistrationRequest{
				RedirectURIs:        []string{"https://example.com/callback"},
				CodeChallengeMethod: "S256",
			},
			expectError: false,
		},
		{
			name:        "missing redirect URIs",
			request:     &ClientRegistrationRequest{ClientName: "Test Client"},
			expectError: true,
		},
		{
			name: "invalid redirect URI with fragment",
			request: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback#section"},
			},
			expectError: true,
		},
		{
			name: "invalid token endpoint auth method",
			request: &ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "invalid_method",
			},
			expectError: true,
		},
		{
			name: "invalid grant type",
			request: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
				GrantTypes:   []string{"implicit"},
			},
			expectError: true,
		},
		{
			name: "invalid response type",
			request: &ClientRegistrationRequest{
				RedirectURIs:  []string{"https://example.com/callback"},
				ResponseTypes: []string{"token"},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, mockDB := CreateTestClientWithMock(nil)
			client.cfg.Verifier.PublicURL = "https://verifier.example.com"

			// Simulate HTTP layer: apply defaults and validate
			require.NoError(t, defaults.Set(tt.request))
			if err := helpers.CheckSimple(tt.request); err != nil {
				if tt.expectError {
					return
				}
				t.Fatalf("unexpected validation error: %v", err)
			}

			resp, err := client.RegisterClient(ctx, tt.request)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, resp)

				// Verify response fields
				assert.NotEmpty(t, resp.ClientID)
				assert.NotEmpty(t, resp.ClientSecret)
				assert.NotEmpty(t, resp.RegistrationAccessToken)
				assert.NotEmpty(t, resp.RegistrationClientURI)
				assert.Contains(t, resp.RegistrationClientURI, resp.ClientID)
				assert.Greater(t, resp.ClientIDIssuedAt, int64(0))
				assert.Equal(t, tt.request.RedirectURIs, resp.RedirectURIs)

				// Verify client was stored in database
				storedClient, _ := mockDB.Clients.GetByClientID(ctx, resp.ClientID)
				assert.NotNil(t, storedClient)
				assert.Equal(t, resp.ClientID, storedClient.ClientID)
				assert.NotEmpty(t, storedClient.ClientSecretHash)
				assert.NotEmpty(t, storedClient.RegistrationAccessTokenHash)

				// Verify PKCE flag
				if tt.request.CodeChallengeMethod != "" {
					assert.True(t, storedClient.RequirePKCE)
				}
			}
		})
	}
}

// TestGetClientInformation tests retrieving client configuration
func TestGetClientInformation(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name          string
		setupMock     func(*testing.T, *MockClientCollection) (string, string)
		expectError   bool
		expectedError error
	}{
		{
			name: "successful retrieval",
			setupMock: func(t *testing.T, clients *MockClientCollection) (string, string) {
				token := "valid-token-123"
				hash, _ := hashRegistrationAccessToken(token)
				client := &db.Client{
					ClientID:                    "test-client-id",
					ClientSecretHash:            hashPassword(t, "secret"),
					RedirectURIs:                []string{"https://example.com/callback"},
					GrantTypes:                  []string{"authorization_code"},
					ResponseTypes:               []string{"code"},
					TokenEndpointAuthMethod:     "client_secret_basic",
					AllowedScopes:               []string{"openid", "profile"},
					ClientName:                  "Test Client",
					ClientIDIssuedAt:            1699999999,
					RegistrationAccessTokenHash: hash,
				}
				clients.Create(ctx, client)
				return "test-client-id", token
			},
			expectError: false,
		},
		{
			name: "client not found",
			setupMock: func(t *testing.T, clients *MockClientCollection) (string, string) {
				return "nonexistent-client", "some-token"
			},
			expectError:   true,
			expectedError: ErrInvalidClient,
		},
		{
			name: "invalid registration access token",
			setupMock: func(t *testing.T, clients *MockClientCollection) (string, string) {
				token := "valid-token-123"
				hash, _ := hashRegistrationAccessToken(token)
				client := &db.Client{
					ClientID:                    "test-client-id",
					RegistrationAccessTokenHash: hash,
				}
				clients.Create(ctx, client)
				return "test-client-id", "wrong-token"
			},
			expectError:   true,
			expectedError: ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, mockDB := CreateTestClientWithMock(nil)
			client.cfg.Verifier.PublicURL = "https://verifier.example.com"

			clientID, token := tt.setupMock(t, mockDB.Clients)

			resp, err := client.GetClientInformation(ctx, &GetClientInformationRequest{
				ClientID:                clientID,
				RegistrationAccessToken: "Bearer " + token,
			})

			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedError != nil {
					assert.Equal(t, tt.expectedError, err)
				}
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, clientID, resp.ClientID)
				assert.NotEmpty(t, resp.RegistrationClientURI)
			}
		})
	}
}

// TestDeleteClient tests client deletion
func TestDeleteClient(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name          string
		setupMock     func(*testing.T, *MockClientCollection) (string, string)
		expectError   bool
		expectedError error
	}{
		{
			name: "successful deletion",
			setupMock: func(t *testing.T, clients *MockClientCollection) (string, string) {
				token := "valid-token-123"
				hash, _ := hashRegistrationAccessToken(token)
				client := &db.Client{
					ClientID:                    "test-client-id",
					RegistrationAccessTokenHash: hash,
				}
				clients.Create(ctx, client)
				return "test-client-id", token
			},
			expectError: false,
		},
		{
			name: "client not found",
			setupMock: func(t *testing.T, clients *MockClientCollection) (string, string) {
				return "nonexistent-client", "some-token"
			},
			expectError:   true,
			expectedError: ErrInvalidClient,
		},
		{
			name: "invalid registration access token",
			setupMock: func(t *testing.T, clients *MockClientCollection) (string, string) {
				token := "valid-token-123"
				hash, _ := hashRegistrationAccessToken(token)
				client := &db.Client{
					ClientID:                    "test-client-id",
					RegistrationAccessTokenHash: hash,
				}
				clients.Create(ctx, client)
				return "test-client-id", "wrong-token"
			},
			expectError:   true,
			expectedError: ErrInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, mockDB := CreateTestClientWithMock(nil)

			clientID, token := tt.setupMock(t, mockDB.Clients)

			err := client.DeleteClient(ctx, &DeleteClientRequest{
				ClientID:                clientID,
				RegistrationAccessToken: "Bearer " + token,
			})

			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedError != nil {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				assert.NoError(t, err)

				// Verify client was deleted
				deletedClient, _ := mockDB.Clients.GetByClientID(ctx, clientID)
				assert.Nil(t, deletedClient)
			}
		})
	}
}

// TestUpdateClient tests client configuration update
func TestUpdateClient(t *testing.T) {
	ctx := t.Context()

	tests := []struct {
		name          string
		setupMock     func(*testing.T, *MockClientCollection) (string, string)
		request       *ClientRegistrationRequest
		expectError   bool
		expectedError error
	}{
		{
			name: "successful update",
			setupMock: func(t *testing.T, clients *MockClientCollection) (string, string) {
				token := "valid-token-123"
				hash, _ := hashRegistrationAccessToken(token)
				client := &db.Client{
					ClientID:                    "test-client-id",
					ClientSecretHash:            hashPassword(t, "secret"),
					RedirectURIs:                []string{"https://example.com/callback"},
					GrantTypes:                  []string{"authorization_code"},
					ResponseTypes:               []string{"code"},
					TokenEndpointAuthMethod:     "client_secret_basic",
					RegistrationAccessTokenHash: hash,
					ClientIDIssuedAt:            1699999999,
				}
				clients.Create(ctx, client)
				return "test-client-id", token
			},
			request: &ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/new-callback"},
				TokenEndpointAuthMethod: "client_secret_post",
				GrantTypes:              []string{"authorization_code", "refresh_token"},
				ResponseTypes:           []string{"code"},
				ClientName:              "Updated Client Name",
			},
			expectError: false,
		},
		{
			name: "client not found",
			setupMock: func(t *testing.T, clients *MockClientCollection) (string, string) {
				return "nonexistent-client", "some-token"
			},
			request: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			expectError:   true,
			expectedError: ErrInvalidClient,
		},
		{
			name: "invalid registration access token",
			setupMock: func(t *testing.T, clients *MockClientCollection) (string, string) {
				token := "valid-token-123"
				hash, _ := hashRegistrationAccessToken(token)
				client := &db.Client{
					ClientID:                    "test-client-id",
					RegistrationAccessTokenHash: hash,
				}
				clients.Create(ctx, client)
				return "test-client-id", "wrong-token"
			},
			request: &ClientRegistrationRequest{
				RedirectURIs: []string{"https://example.com/callback"},
			},
			expectError:   true,
			expectedError: ErrInvalidToken,
		},
		{
			name: "update with all optional fields",
			setupMock: func(t *testing.T, clients *MockClientCollection) (string, string) {
				token := "valid-token-456"
				hash, _ := hashRegistrationAccessToken(token)
				client := &db.Client{
					ClientID:                    "full-update-client",
					ClientSecretHash:            hashPassword(t, "secret"),
					RedirectURIs:                []string{"https://example.com/callback"},
					GrantTypes:                  []string{"authorization_code"},
					ResponseTypes:               []string{"code"},
					TokenEndpointAuthMethod:     "client_secret_basic",
					RegistrationAccessTokenHash: hash,
					ClientIDIssuedAt:            1699999999,
				}
				clients.Create(ctx, client)
				return "full-update-client", token
			},
			request: &ClientRegistrationRequest{
				RedirectURIs:        []string{"https://example.com/new-callback"},
				GrantTypes:          []string{"authorization_code", "refresh_token"},
				ResponseTypes:       []string{"code"},
				JWKSUri:             "https://example.com/.well-known/jwks.json",
				JWKS:                nil, // Can't set both jwks_uri and jwks
				ClientName:          "Full Update Client",
				ClientURI:           "https://example.com",
				LogoURI:             "https://example.com/logo.png",
				Contacts:            []string{"admin@example.com"},
				TosURI:              "https://example.com/tos",
				PolicyURI:           "https://example.com/policy",
				CodeChallengeMethod: "S256",
			},
			expectError: false,
		},
		{
			name: "update with JWKS instead of JWKSUri",
			setupMock: func(t *testing.T, clients *MockClientCollection) (string, string) {
				token := "valid-token-789"
				hash, _ := hashRegistrationAccessToken(token)
				client := &db.Client{
					ClientID:                    "jwks-update-client",
					ClientSecretHash:            hashPassword(t, "secret"),
					RedirectURIs:                []string{"https://example.com/callback"},
					GrantTypes:                  []string{"authorization_code"},
					ResponseTypes:               []string{"code"},
					TokenEndpointAuthMethod:     "client_secret_basic",
					RegistrationAccessTokenHash: hash,
					ClientIDIssuedAt:            1699999999,
				}
				clients.Create(ctx, client)
				return "jwks-update-client", token
			},
			request: &ClientRegistrationRequest{
				RedirectURIs:  []string{"https://example.com/new-callback"},
				GrantTypes:    []string{"authorization_code"},
				ResponseTypes: []string{"code"},
				JWKS:          map[string]any{"keys": []any{}}, // Use JWKS instead of JWKSUri
			},
			expectError: false,
		},
		{
			name: "invalid update request - missing redirect URIs",
			setupMock: func(t *testing.T, clients *MockClientCollection) (string, string) {
				token := "valid-token-invalid"
				hash, _ := hashRegistrationAccessToken(token)
				client := &db.Client{
					ClientID:                    "invalid-update-client",
					ClientSecretHash:            hashPassword(t, "secret"),
					RedirectURIs:                []string{"https://example.com/callback"},
					GrantTypes:                  []string{"authorization_code"},
					ResponseTypes:               []string{"code"},
					TokenEndpointAuthMethod:     "client_secret_basic",
					RegistrationAccessTokenHash: hash,
					ClientIDIssuedAt:            1699999999,
				}
				clients.Create(ctx, client)
				return "invalid-update-client", token
			},
			request: &ClientRegistrationRequest{
				ClientName: "Missing Redirect URIs",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, mockDB := CreateTestClientWithMock(nil)
			client.cfg.Verifier.PublicURL = "https://verifier.example.com"

			clientID, token := tt.setupMock(t, mockDB.Clients)

			// Simulate HTTP layer: apply defaults and validate
			require.NoError(t, defaults.Set(tt.request))
			if err := helpers.CheckSimple(tt.request); err != nil {
				if tt.expectError {
					return
				}
				t.Fatalf("unexpected validation error: %v", err)
			}

			resp, err := client.UpdateClient(ctx, &UpdateClientRequest{
				ClientID:                  clientID,
				RegistrationAccessToken:   "Bearer " + token,
				ClientRegistrationRequest: *tt.request,
			})

			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedError != nil {
					assert.Equal(t, tt.expectedError, err)
				}
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, clientID, resp.ClientID)
				assert.Equal(t, tt.request.RedirectURIs, resp.RedirectURIs)
				assert.Equal(t, tt.request.ClientName, resp.ClientName)

				// Verify database was updated
				updatedClient, _ := mockDB.Clients.GetByClientID(ctx, clientID)
				assert.NotNil(t, updatedClient)
				assert.Equal(t, tt.request.RedirectURIs, updatedClient.RedirectURIs)
				assert.Equal(t, tt.request.ClientName, updatedClient.ClientName)
			}
		})
	}
}

// TestVerifyPlaintextSecret tests plaintext secret verification
func TestVerifyPlaintextSecret(t *testing.T) {
	tests := []struct {
		name     string
		provided string
		stored   string
		want     bool
	}{
		{
			name:     "matching secrets",
			provided: "my-secret-123",
			stored:   "my-secret-123",
			want:     true,
		},
		{
			name:     "non-matching secrets",
			provided: "my-secret-123",
			stored:   "different-secret",
			want:     false,
		},
		{
			name:     "empty provided",
			provided: "",
			stored:   "my-secret",
			want:     false,
		},
		{
			name:     "both empty",
			provided: "",
			stored:   "",
			want:     true,
		},
		{
			name:     "similar but different",
			provided: "secret",
			stored:   "secret ",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verifyPlaintextSecret(tt.provided, tt.stored)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestGetOrDefault tests the getOrDefault helper function
func TestGetOrDefault(t *testing.T) {
	defaultVal := []string{"default1", "default2"}

	tests := []struct {
		name       string
		input      []string
		defaultVal []string
		want       []string
	}{
		{
			name:       "non-empty slice returns input",
			input:      []string{"value1", "value2"},
			defaultVal: defaultVal,
			want:       []string{"value1", "value2"},
		},
		{
			name:       "empty slice returns default",
			input:      []string{},
			defaultVal: defaultVal,
			want:       defaultVal,
		},
		{
			name:       "nil slice returns default",
			input:      nil,
			defaultVal: defaultVal,
			want:       defaultVal,
		},
		{
			name:       "single element returns input",
			input:      []string{"single"},
			defaultVal: defaultVal,
			want:       []string{"single"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getOrDefault(tt.input, tt.defaultVal)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestGetOrDefaultString tests the getOrDefaultString helper function
func TestGetOrDefaultString(t *testing.T) {
	defaultVal := "default-value"

	tests := []struct {
		name       string
		input      string
		defaultVal string
		want       string
	}{
		{
			name:       "non-empty string returns input",
			input:      "my-value",
			defaultVal: defaultVal,
			want:       "my-value",
		},
		{
			name:       "empty string returns default",
			input:      "",
			defaultVal: defaultVal,
			want:       defaultVal,
		},
		{
			name:       "whitespace string returns input",
			input:      "  ",
			defaultVal: defaultVal,
			want:       "  ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getOrDefaultString(tt.input, tt.defaultVal)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestGetClientByID tests client lookup from both database and static configuration
func TestGetClientByID(t *testing.T) {
	ctx := t.Context()

	// Create a test client with static clients configured
	staticClients := []model.StaticOIDCClient{
		{
			ClientID:                "static-client-1",
			ClientSecret:            "static-secret-1",
			RedirectURIs:            []string{"https://static.example.com/callback"},
			AllowedScopes:           []string{"openid", "profile"},
			TokenEndpointAuthMethod: "client_secret_basic",
			GrantTypes:              []string{"authorization_code"},
			ResponseTypes:           []string{"code"},
			ClientName:              "Static Client 1",
		},
		{
			ClientID:                "public-static-client",
			RedirectURIs:            []string{"https://public.example.com/callback"},
			TokenEndpointAuthMethod: "none",
			ClientName:              "Public Static Client",
		},
		{
			ClientID:     "static-client-defaults",
			ClientSecret: "secret-defaults",
			RedirectURIs: []string{"https://defaults.example.com/callback"},
			// Leave most fields empty to test defaults
		},
	}

	client, mockDB := CreateTestClientWithMock(&model.Cfg{
		Verifier: &model.Verifier{
			OIDC: &model.OIDCConfig{
				Issuer:        "https://test.example.com",
				SubjectType:   "pairwise",
				SubjectSalt:   "test-salt",
				StaticClients: staticClients,
			},
		},
	})

	// Add a DB client
	// Generate test value dynamically to avoid static analysis false positives
	dbTestCred := t.Name() + "-dbcred"
	hashedDBCredential, _ := bcrypt.GenerateFromPassword([]byte(dbTestCred), bcrypt.DefaultCost)
	mockDB.Clients.AddClient(&db.Client{
		ClientID:         "db-client",
		ClientSecretHash: string(hashedDBCredential),
		RedirectURIs:     []string{"https://db.example.com/callback"},
	})

	tests := []struct {
		name           string
		clientID       string
		wantNil        bool
		wantStatic     bool
		wantClientName string
	}{
		{
			name:           "DB client found",
			clientID:       "db-client",
			wantNil:        false,
			wantStatic:     false,
			wantClientName: "",
		},
		{
			name:           "static client found",
			clientID:       "static-client-1",
			wantNil:        false,
			wantStatic:     true,
			wantClientName: "Static Client 1",
		},
		{
			name:           "public static client found",
			clientID:       "public-static-client",
			wantNil:        false,
			wantStatic:     true,
			wantClientName: "Public Static Client",
		},
		{
			name:           "static client with defaults",
			clientID:       "static-client-defaults",
			wantNil:        false,
			wantStatic:     true,
			wantClientName: "",
		},
		{
			name:       "unknown client",
			clientID:   "unknown-client",
			wantNil:    true,
			wantStatic: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, isStatic, err := client.getClientByID(ctx, tt.clientID)
			require.NoError(t, err)

			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tt.clientID, result.ClientID)
				assert.Equal(t, tt.wantStatic, isStatic)
				if tt.wantClientName != "" {
					assert.Equal(t, tt.wantClientName, result.ClientName)
				}
			}
		})
	}

	// Test that static client with empty AllowedScopes gets defaults
	t.Run("static client empty scopes gets defaults", func(t *testing.T) {
		result, isStatic, err := client.getClientByID(ctx, "static-client-defaults")
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.True(t, isStatic)
		// Should have default OIDC scopes
		assert.Contains(t, result.AllowedScopes, "openid")
		assert.Contains(t, result.AllowedScopes, "profile")
		assert.Contains(t, result.AllowedScopes, "email")
	})

	// Test that static client with specified AllowedScopes keeps them
	t.Run("static client keeps specified scopes", func(t *testing.T) {
		result, _, err := client.getClientByID(ctx, "static-client-1")
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, []string{"openid", "profile"}, result.AllowedScopes)
	})
}

// TestAuthenticateClientWithStaticClients tests authentication with static clients
func TestAuthenticateClientWithStaticClients(t *testing.T) {
	ctx := t.Context()

	staticClients := []model.StaticOIDCClient{
		{
			ClientID:     "static-confidential",
			ClientSecret: "static-secret",
			RedirectURIs: []string{"https://example.com/callback"},
		},
		{
			ClientID:                "static-public",
			RedirectURIs:            []string{"https://public.example.com/callback"},
			TokenEndpointAuthMethod: "none",
		},
	}

	client, _ := CreateTestClientWithMock(&model.Cfg{
		Verifier: &model.Verifier{
			OIDC: &model.OIDCConfig{
				Issuer:        "https://test.example.com",
				SubjectType:   "pairwise",
				SubjectSalt:   "test-salt",
				StaticClients: staticClients,
			},
		},
	})

	tests := []struct {
		name         string
		clientID     string
		clientSecret string
		wantErr      error
	}{
		{
			name:         "static client valid secret",
			clientID:     "static-confidential",
			clientSecret: "static-secret",
			wantErr:      nil,
		},
		{
			name:         "static client wrong secret",
			clientID:     "static-confidential",
			clientSecret: "wrong-secret",
			wantErr:      ErrInvalidClient,
		},
		{
			name:         "static public client no secret",
			clientID:     "static-public",
			clientSecret: "",
			wantErr:      nil,
		},
		{
			name:         "unknown client",
			clientID:     "unknown",
			clientSecret: "any",
			wantErr:      ErrInvalidClient,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := client.authenticateClient(ctx, tt.clientID, tt.clientSecret)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.clientID, result.ClientID)
			}
		})
	}
}
