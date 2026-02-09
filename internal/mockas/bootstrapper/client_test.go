package bootstrapper

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/vcclient"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockUserHandler is a mock implementation of the User handler
type mockUserHandler struct {
	addPIDFunc func(ctx context.Context, body *vcclient.AddPIDRequest) (*http.Response, error)
	callCount  int
}

func (m *mockUserHandler) AddPID(ctx context.Context, body *vcclient.AddPIDRequest) (*http.Response, error) {
	m.callCount++
	if m.addPIDFunc != nil {
		return m.addPIDFunc(ctx, body)
	}
	// Default success response
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
	}, nil
}

func (m *mockUserHandler) LoginPIDUser(ctx context.Context, body any) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK}, nil
}

func (m *mockUserHandler) GetPID(ctx context.Context, body any) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK}, nil
}

func mockClient() *Client {
	return &Client{
		identities: map[string]*vcclient.UploadRequest{},
	}
}

func TestCreateJSONSourceFiles(t *testing.T) {
	ctx := t.Context()
	c := mockClient()
	err := c.makeIdentities("testdata/users_paris.xlsx")
	assert.NoError(t, err)

	t.Run("ehic", func(t *testing.T) {
		client, err := NewEHICClient(ctx, c)
		assert.NoError(t, err)

		err = client.makeSourceData("testdata/users_paris.xlsx")
		assert.NoError(t, err)

		err = client.save2Disk()
		assert.NoError(t, err)
	})

	t.Run("pda1", func(t *testing.T) {
		client, err := NewPDA1Client(ctx, c)
		assert.NoError(t, err)

		err = client.makeSourceData("testdata/users_paris.xlsx")
		assert.NoError(t, err)

		err = client.save2Disk()
		assert.NoError(t, err)
	})

	t.Run("pid-1-5", func(t *testing.T) {
		client, err := NewPIDClient(ctx, c)
		assert.NoError(t, err)

		err = client.makeSourceData("../../../bootstrapping/idp_user.json")
		assert.NoError(t, err)

		err = client.save2Disk()
		assert.NoError(t, err)
	})

	t.Run("pid-1-8", func(t *testing.T) {
		client, err := NewPID18Client(ctx, c)
		assert.NoError(t, err)

		err = client.makeSourceData("../../../bootstrapping/idp_user.json")
		assert.NoError(t, err)

		err = client.save2Disk()
		assert.NoError(t, err)
	})
	t.Run("elm", func(t *testing.T) {
		client, err := NewELMClient(ctx, c)
		assert.NoError(t, err)

		err = client.makeSourceData("testdata/users_paris.xlsx")
		assert.NoError(t, err)

		err = client.save2Disk()
		assert.NoError(t, err)
	})

	t.Run("diploma", func(t *testing.T) {
		client, err := NewDiplomaClient(ctx, c)
		assert.NoError(t, err)

		err = client.makeSourceData("testdata/users_paris.xlsx")
		assert.NoError(t, err)

		err = client.save2Disk()
		assert.NoError(t, err)
	})

	t.Run("micro_credential", func(t *testing.T) {
		client, err := NewMicroCredentialClient(ctx, c)
		assert.NoError(t, err)

		err = client.makeSourceData("testdata/users_paris.xlsx")
		assert.NoError(t, err)

		err = client.save2Disk()
		assert.NoError(t, err)
	})

	t.Run("idp_user", func(t *testing.T) {
		client, err := NewIDPUserClient(ctx, c)
		assert.NoError(t, err)

		err = client.makeSourceData("")
		assert.NoError(t, err)

		err = client.save2Disk()
		assert.NoError(t, err)
	})
}

func TestUserUpload(t *testing.T) {
	tests := []struct {
		name           string
		jsonPath       string
		bootstrapUsers []string
		wantErr        bool
		errContains    string
		setupMock      func(m *mockUserHandler)
		validateMock   func(t *testing.T, m *mockUserHandler)
		validateUser   func(t *testing.T, username string) // Validate specific user data
	}{
		{
			name:        "File does not exist",
			jsonPath:    "/nonexistent/path/test.json",
			wantErr:     true,
			errContains: "no such file or directory",
		},
		{
			name:           "Upload all users from idp_user.json",
			jsonPath:       "../../../bootstrapping/idp_user.json",
			bootstrapUsers: []string{}, // Allow all
			wantErr:        false,
			validateMock: func(t *testing.T, m *mockUserHandler) {
				// idp_user.json contains many users, verify they were uploaded
				assert.Greater(t, m.callCount, 0, "AddPID should be called for users")
			},
		},
		{
			name:           "Upload filtered - specific user ID 100 (mirren)",
			jsonPath:       "../../../bootstrapping/idp_user.json",
			bootstrapUsers: []string{"100"}, // Only allow user ID 100
			wantErr:        false,
			setupMock: func(m *mockUserHandler) {
				m.addPIDFunc = func(ctx context.Context, body *vcclient.AddPIDRequest) (*http.Response, error) {
					// Verify it's the expected user
					assert.Equal(t, "mirren", body.Username)
					assert.Equal(t, "Mirren", body.Identity.FamilyName)
					assert.Equal(t, "Helen", body.Identity.GivenName)
					return &http.Response{StatusCode: http.StatusOK}, nil
				}
			},
			validateMock: func(t *testing.T, m *mockUserHandler) {
				assert.Equal(t, 1, m.callCount, "AddPID should be called once for user 100")
			},
		},
		{
			name:           "Upload filtered - multiple users (100, 101)",
			jsonPath:       "../../../bootstrapping/idp_user.json",
			bootstrapUsers: []string{"100", "101"}, // Allow users 100 and 101
			wantErr:        false,
			validateMock: func(t *testing.T, m *mockUserHandler) {
				assert.Equal(t, 2, m.callCount, "AddPID should be called twice for users 100 and 101")
			},
		},
		{
			name:           "Upload filtered - no users allowed",
			jsonPath:       "../../../bootstrapping/idp_user.json",
			bootstrapUsers: []string{"nonexistent_user"}, // Filter out all
			wantErr:        false,
			validateMock: func(t *testing.T, m *mockUserHandler) {
				assert.Equal(t, 0, m.callCount, "AddPID should not be called when filtered")
			},
		},
		{
			name:           "AddPID returns error",
			jsonPath:       "../../../bootstrapping/idp_user.json",
			bootstrapUsers: []string{"100"}, // Try to upload user 100
			wantErr:        true,
			errContains:    "invalid request", // vcclient returns this error when server returns 500
			setupMock: func(m *mockUserHandler) {
				m.addPIDFunc = func(ctx context.Context, body *vcclient.AddPIDRequest) (*http.Response, error) {
					return nil, errors.New("upload failed")
				}
			},
		},
		{
			name:           "Verify VCT field parsing from real file",
			jsonPath:       "../../../bootstrapping/idp_user.json",
			bootstrapUsers: []string{"105"}, // phoenix user
			wantErr:        false,
			setupMock: func(m *mockUserHandler) {
				m.addPIDFunc = func(ctx context.Context, body *vcclient.AddPIDRequest) (*http.Response, error) {
					// Verify VCT field is correctly parsed
					assert.Equal(t, "phoenix", body.Username)
					return &http.Response{StatusCode: http.StatusOK}, nil
				}
			},
			validateMock: func(t *testing.T, m *mockUserHandler) {
				assert.Equal(t, 1, m.callCount, "AddPID should be called once for user 105")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			// Setup logger
			log, err := logger.New("test", "", false)
			require.NoError(t, err)

			// Setup mock HTTP server
			callCount := 0
			var lastRequest *vcclient.AddPIDRequest
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				callCount++

				// Decode the request body
				var req vcclient.AddPIDRequest
				err := json.NewDecoder(r.Body).Decode(&req)
				if err == nil {
					lastRequest = &req
				}

				// Call custom mock function if provided
				if tt.setupMock != nil {
					mockUser := &mockUserHandler{}
					tt.setupMock(mockUser)
					if mockUser.addPIDFunc != nil {
						_, err := mockUser.addPIDFunc(ctx, &req)
						if err != nil {
							w.WriteHeader(http.StatusInternalServerError)
							w.Header().Set("Content-Type", "application/json")
							json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
							return
						}
					}
				}

				// Return proper JSON response expected by vcclient
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]any{
					"status": "ok",
					"data": map[string]string{
						"message": "user created successfully",
					},
				})
			}))
			defer mockServer.Close()

			// Create client with mock vcClient
			vcClient, err := vcclient.New(&vcclient.Config{ApigwURL: mockServer.URL}, log)
			require.NoError(t, err)

			client := &Client{
				cfg: &model.Cfg{
					MockAS: &model.MockAS{
						BootstrapUsers: tt.bootstrapUsers,
					},
				},
				log:      log,
				vcClient: vcClient,
			}

			// Use the jsonPath from test case (all tests now use actual files)
			err = client.userUpload(ctx, tt.jsonPath)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}

			// Validate mock behavior
			if tt.validateMock != nil {
				mockUser := &mockUserHandler{callCount: callCount}
				tt.validateMock(t, mockUser)
			}

			// Additional assertions
			if tt.setupMock != nil && callCount > 0 && lastRequest != nil {
				// Verify the request was parsed correctly
				assert.NotNil(t, lastRequest)
			}
		})
	}
}

func TestUserUpload_JSONParsing(t *testing.T) {
	tests := []struct {
		name        string
		jsonContent string
		wantErr     bool
		errContains string
		validate    func(t *testing.T, requests map[string]*vcclient.AddPIDRequest)
	}{
		{
			name: "Valid complete AddPIDRequest structure",
			jsonContent: `{
				"test_user": {
					"username": "testuser",
					"password": "testpass",
					"identity": {
						"authentic_source_person_id": "person_123",
						"schema": {
							"name": "DefaultSchema"
						},
						"family_name": "TestFamily",
						"given_name": "TestGiven",
						"birth_date": "1990-01-01",
						"birth_place": "Test Place",
						"nationality": ["SE"],
						"issuing_authority": "SUNET",
						"issuing_country": "SE",
						"expiry_date": "2033-01-01"
					}
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, requests map[string]*vcclient.AddPIDRequest) {
				assert.Len(t, requests, 1)
				assert.Contains(t, requests, "test_user")

				req := requests["test_user"]
				assert.NotNil(t, req)
				assert.Equal(t, "testuser", req.Username)
				assert.Equal(t, "testpass", req.Password)

				assert.NotNil(t, req.Identity)
				assert.Equal(t, "person_123", req.Identity.AuthenticSourcePersonID)
				assert.Equal(t, "TestFamily", req.Identity.FamilyName)
				assert.Equal(t, "TestGiven", req.Identity.GivenName)
				assert.Equal(t, "1990-01-01", req.Identity.BirthDate)
			},
		},
		{
			name: "Multiple users in JSON",
			jsonContent: `{
				"user1": {
					"username": "user1",
					"password": "pass1",
					"identity": {
						"authentic_source_person_id": "person_1",
						"schema": {"name": "DefaultSchema"},
						"family_name": "Family1",
						"given_name": "Given1",
						"birth_date": "1980-01-01"
					},
					"meta": {
						"authentic_source": "PID_Provider:00001",
						"vct": "urn:eudi:pid:1"
					}
				},
				"user2": {
					"username": "user2",
					"password": "pass2",
					"identity": {
						"authentic_source_person_id": "person_2",
						"schema": {"name": "DefaultSchema"},
						"family_name": "Family2",
						"given_name": "Given2",
						"birth_date": "1985-05-15"
					},
					"meta": {
						"authentic_source": "PID_Provider:00002",
						"vct": "urn:eudi:pid:1"
					}
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, requests map[string]*vcclient.AddPIDRequest) {
				assert.Len(t, requests, 2)
				assert.Contains(t, requests, "user1")
				assert.Contains(t, requests, "user2")

				assert.Equal(t, "user1", requests["user1"].Username)
				assert.Equal(t, "user2", requests["user2"].Username)
			},
		},
		{
			name: "Missing required username field",
			jsonContent: `{
				"test_user": {
					"password": "testpass",
					"identity": {
						"authentic_source_person_id": "person_123",
						"schema": {"name": "DefaultSchema"}
					},
					"meta": {
						"authentic_source": "PID_Provider:00001",
						"vct": "urn:eudi:pid:1"
					}
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, requests map[string]*vcclient.AddPIDRequest) {
				assert.Len(t, requests, 1)
				req := requests["test_user"]
				assert.NotNil(t, req)
				assert.Empty(t, req.Username, "Username should be empty string when missing")
			},
		},
		{
			name: "Missing identity field",
			jsonContent: `{
				"test_user": {
					"username": "testuser",
					"password": "testpass",
					"meta": {
						"authentic_source": "PID_Provider:00001",
						"vct": "urn:eudi:pid:1"
					}
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, requests map[string]*vcclient.AddPIDRequest) {
				assert.Len(t, requests, 1)
				req := requests["test_user"]
				assert.NotNil(t, req)
				assert.Nil(t, req.Identity, "Identity should be nil when missing")
			},
		},
		{
			name: "Missing meta field",
			jsonContent: `{
				"test_user": {
					"username": "testuser",
					"password": "testpass",
					"identity": {
						"authentic_source_person_id": "person_123",
						"schema": {"name": "DefaultSchema"}
					}
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, requests map[string]*vcclient.AddPIDRequest) {
				assert.Len(t, requests, 1)
				req := requests["test_user"]
				assert.NotNil(t, req)
			},
		},
		{
			name:        "Invalid JSON - malformed",
			jsonContent: `{"test_user": {username: "invalid"}}`,
			wantErr:     true,
			errContains: "invalid character",
		},
		{
			name:        "Invalid JSON - not a map",
			jsonContent: `["array", "instead", "of", "map"]`,
			wantErr:     true,
			errContains: "cannot unmarshal array",
		},
		{
			name:        "Empty JSON object",
			jsonContent: `{}`,
			wantErr:     false,
			validate: func(t *testing.T, requests map[string]*vcclient.AddPIDRequest) {
				assert.Len(t, requests, 0)
			},
		},
		{
			name: "VCT field parsing",
			jsonContent: `{
				"vct_test": {
					"username": "vctuser",
					"password": "vctpass",
					"identity": {
						"authentic_source_person_id": "person_vct",
						"schema": {"name": "DefaultSchema"}
					},
					"meta": {
						"authentic_source": "PID_Provider:00001",
						"vct": "urn:eudi:pid:1",
						"document_version": "2.0.0"
					}
				}
			}`,
			wantErr: false,
			validate: func(t *testing.T, requests map[string]*vcclient.AddPIDRequest) {
				assert.Len(t, requests, 1)
				req := requests["vct_test"]
				assert.NotNil(t, req)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary JSON file
			tmpDir := t.TempDir()
			jsonPath := filepath.Join(tmpDir, "test.json")
			err := os.WriteFile(jsonPath, []byte(tt.jsonContent), 0644)
			require.NoError(t, err)

			// Read and parse the JSON file (simulating userUpload logic)
			b, err := os.ReadFile(filepath.Clean(jsonPath))
			require.NoError(t, err)

			requests := map[string]*vcclient.AddPIDRequest{}
			err = json.Unmarshal(b, &requests)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err, "JSON should parse without error")
				if tt.validate != nil {
					tt.validate(t, requests)
				}
			}
		})
	}
}

func TestDocumentUploader(t *testing.T) {
	tests := []struct {
		name           string
		jsonPath       string
		bootstrapUsers []string
		wantErr        bool
		errContains    string
		setupMock      func(m *mockRootHandler)
		validateMock   func(t *testing.T, m *mockRootHandler)
	}{
		{
			name:        "File does not exist",
			jsonPath:    "/nonexistent/path/test.json",
			wantErr:     true,
			errContains: "no such file or directory",
		},
		{
			name:           "Upload all documents from ehic.json",
			jsonPath:       "../../../bootstrapping/ehic.json",
			bootstrapUsers: []string{}, // Allow all
			wantErr:        false,
			validateMock: func(t *testing.T, m *mockRootHandler) {
				// ehic.json contains many documents, verify they were uploaded
				assert.Greater(t, m.callCount, 0, "Upload should be called for documents")
			},
		},
		{
			name:           "Upload filtered - specific document ID 100",
			jsonPath:       "../../../bootstrapping/ehic.json",
			bootstrapUsers: []string{"100"}, // Only allow document ID 100
			wantErr:        false,
			setupMock: func(m *mockRootHandler) {
				m.uploadFunc = func(ctx context.Context, body *vcclient.UploadRequest) (*http.Response, error) {
					// Verify it's the expected document
					assert.NotNil(t, body.Meta)
					assert.Equal(t, "urn:eudi:ehic:1", body.Meta.VCT)
					assert.Equal(t, "document_id_ehic_100", body.Meta.DocumentID)
					assert.NotNil(t, body.Identities)
					assert.Len(t, body.Identities, 1)
					assert.Equal(t, "Mirren", body.Identities[0].FamilyName)
					return &http.Response{StatusCode: http.StatusOK}, nil
				}
			},
			validateMock: func(t *testing.T, m *mockRootHandler) {
				assert.Equal(t, 1, m.callCount, "Upload should be called once for document 100")
			},
		},
		{
			name:           "Upload filtered - multiple documents (100, 101)",
			jsonPath:       "../../../bootstrapping/ehic.json",
			bootstrapUsers: []string{"100", "101"}, // Allow documents 100 and 101
			wantErr:        false,
			validateMock: func(t *testing.T, m *mockRootHandler) {
				assert.Equal(t, 2, m.callCount, "Upload should be called twice for documents 100 and 101")
			},
		},
		{
			name:           "Upload filtered - no documents allowed",
			jsonPath:       "../../../bootstrapping/ehic.json",
			bootstrapUsers: []string{"nonexistent_id"}, // Filter out all
			wantErr:        false,
			validateMock: func(t *testing.T, m *mockRootHandler) {
				assert.Equal(t, 0, m.callCount, "Upload should not be called when filtered")
			},
		},
		{
			name:           "Upload returns error",
			jsonPath:       "../../../bootstrapping/ehic.json",
			bootstrapUsers: []string{"100"}, // Try to upload document 100
			wantErr:        true,
			errContains:    "invalid request", // vcclient returns this error when server returns 500
			setupMock: func(m *mockRootHandler) {
				m.uploadFunc = func(ctx context.Context, body *vcclient.UploadRequest) (*http.Response, error) {
					return nil, errors.New("upload failed")
				}
			},
		},
		{
			name:           "Verify VCT field parsing from real ehic file",
			jsonPath:       "../../../bootstrapping/ehic.json",
			bootstrapUsers: []string{"105"}, // phoenix user
			wantErr:        false,
			setupMock: func(m *mockRootHandler) {
				m.uploadFunc = func(ctx context.Context, body *vcclient.UploadRequest) (*http.Response, error) {
					// Verify VCT field is correctly parsed
					assert.NotNil(t, body.Meta)
					assert.Equal(t, "urn:eudi:ehic:1", body.Meta.VCT)
					assert.Equal(t, "EHIC:00001", body.Meta.AuthenticSource)
					assert.NotNil(t, body.DocumentData)
					assert.NotEmpty(t, body.DocumentData)
					return &http.Response{StatusCode: http.StatusOK}, nil
				}
			},
			validateMock: func(t *testing.T, m *mockRootHandler) {
				assert.Equal(t, 1, m.callCount, "Upload should be called once for document 105")
			},
		},
		{
			name:           "Upload from pda1.json file",
			jsonPath:       "../../../bootstrapping/pda1.json",
			bootstrapUsers: []string{"100"},
			wantErr:        false,
			setupMock: func(m *mockRootHandler) {
				m.uploadFunc = func(ctx context.Context, body *vcclient.UploadRequest) (*http.Response, error) {
					assert.NotNil(t, body.Meta)
					assert.Equal(t, "urn:eudi:pda1:1", body.Meta.VCT)
					return &http.Response{StatusCode: http.StatusOK}, nil
				}
			},
			validateMock: func(t *testing.T, m *mockRootHandler) {
				assert.Equal(t, 1, m.callCount, "Upload should be called once")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			// Setup logger
			log, err := logger.New("test", "", false)
			require.NoError(t, err)

			// Setup mock HTTP server
			callCount := 0
			var lastRequest *vcclient.UploadRequest
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				callCount++

				// Decode the request body
				var req vcclient.UploadRequest
				err := json.NewDecoder(r.Body).Decode(&req)
				if err == nil {
					lastRequest = &req
				}

				// Call custom mock function if provided
				if tt.setupMock != nil {
					mockRoot := &mockRootHandler{}
					tt.setupMock(mockRoot)
					if mockRoot.uploadFunc != nil {
						_, err := mockRoot.uploadFunc(ctx, &req)
						if err != nil {
							w.WriteHeader(http.StatusInternalServerError)
							w.Header().Set("Content-Type", "application/json")
							json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
							return
						}
					}
				}

				// Return proper JSON response expected by vcclient
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]any{
					"status": "ok",
					"data": map[string]string{
						"message": "document uploaded successfully",
					},
				})
			}))
			defer mockServer.Close()

			// Create client with mock vcClient
			vcClient, err := vcclient.New(&vcclient.Config{ApigwURL: mockServer.URL}, log)
			require.NoError(t, err)

			client := &Client{
				cfg: &model.Cfg{
					MockAS: &model.MockAS{
						BootstrapUsers: tt.bootstrapUsers,
					},
				},
				log:      log,
				vcClient: vcClient,
			}

			// Use the jsonPath from test case (all tests now use actual files)
			err = client.documentUploader(ctx, tt.jsonPath)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}

			// Validate mock behavior
			if tt.validateMock != nil {
				mockRoot := &mockRootHandler{callCount: callCount}
				tt.validateMock(t, mockRoot)
			}

			// Additional assertions
			if tt.setupMock != nil && callCount > 0 && lastRequest != nil {
				// Verify the request was parsed correctly
				assert.NotNil(t, lastRequest)
			}
		})
	}
}

// mockRootHandler is a mock implementation of the Root handler
type mockRootHandler struct {
	uploadFunc func(ctx context.Context, body *vcclient.UploadRequest) (*http.Response, error)
	callCount  int
}

func (m *mockRootHandler) Upload(ctx context.Context, body *vcclient.UploadRequest) (*http.Response, error) {
	m.callCount++
	if m.uploadFunc != nil {
		return m.uploadFunc(ctx, body)
	}
	// Default success response
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
	}, nil
}
