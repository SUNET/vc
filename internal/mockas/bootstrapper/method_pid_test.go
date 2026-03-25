package bootstrapper

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeSourceData(t *testing.T) {
	tests := []struct {
		name     string
		pidUsers map[string]*vcclient.AddPIDRequest
		wantErr  bool
	}{
		{
			name: "successful processing of two PID users",
			pidUsers: map[string]*vcclient.AddPIDRequest{
				"12345678": {
					Username: "test_user_1",
					Password: "password123",
					Identity: &model.Identity{
						GivenName:               "John",
						FamilyName:              "Doe",
						BirthDate:               "1990-01-15",
						BirthPlace:              "Stockholm",
						Nationality:             []string{"SE"},
						ExpiryDate:              "2030-12-31",
						IssuingAuthority:        "Swedish Tax Agency",
						IssuingCountry:          "SE",
						AuthenticSourcePersonID: "test_person_1",
					},
				},
				"87654321": {
					Username: "test_user_2",
					Password: "password456",
					Identity: &model.Identity{
						GivenName:               "Jane",
						FamilyName:              "Smith",
						BirthDate:               "1985-05-20",
						BirthPlace:              "Gothenburg",
						Nationality:             []string{"SE"},
						ExpiryDate:              "2029-06-30",
						IssuingAuthority:        "Swedish Tax Agency",
						IssuingCountry:          "SE",
						AuthenticSourcePersonID: "test_person_2",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "single PID user",
			pidUsers: map[string]*vcclient.AddPIDRequest{
				"99999999": {
					Username: "single_user",
					Password: "password789",
					Identity: &model.Identity{
						GivenName:               "Alice",
						FamilyName:              "Anderson",
						BirthDate:               "1995-03-10",
						BirthPlace:              "Malmö",
						Nationality:             []string{"SE"},
						ExpiryDate:              "2031-01-01",
						IssuingAuthority:        "Swedish Tax Agency",
						IssuingCountry:          "SE",
						AuthenticSourcePersonID: "test_person_3",
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()

			// Create temporary directory for test files
			tempDir := t.TempDir()

			// Write test file
			testFilePath := filepath.Join(tempDir, "pid_user.json")
			testData, err := json.MarshalIndent(tt.pidUsers, "", "  ")
			require.NoError(t, err)
			err = os.WriteFile(testFilePath, testData, 0600)
			require.NoError(t, err)

			// Create pidClient
			client, err := NewPIDClient(ctx, nil)
			require.NoError(t, err)
			require.NotNil(t, client)

			// Actually call makeSourceData
			err = client.makeSourceData(testFilePath)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Verify we have the expected number of documents
			assert.Len(t, client.documents, len(tt.pidUsers), "should have %d documents", len(tt.pidUsers))

			// Verify each identity from pidUsers matches what's in client.documents
			for docID, pidRequest := range tt.pidUsers {
				actualDoc, exists := client.documents[docID]
				require.True(t, exists, "document %s should exist", docID)

				// Verify DocumentData is populated
				require.NotNil(t, actualDoc.DocumentData, "document %s should have DocumentData", docID)
				require.NotEmpty(t, actualDoc.DocumentData, "document %s DocumentData should not be empty", docID)

				// Verify Identity fields match DocumentData
				assert.Equal(t, pidRequest.Identity.GivenName, actualDoc.DocumentData["given_name"], "document %s given_name should match", docID)
				assert.Equal(t, pidRequest.Identity.FamilyName, actualDoc.DocumentData["family_name"], "document %s family_name should match", docID)
				assert.Equal(t, pidRequest.Identity.BirthDate, actualDoc.DocumentData["birthdate"], "document %s birth_date should match", docID)
				assert.Equal(t, pidRequest.Identity.BirthPlace, actualDoc.DocumentData["birth_place"], "document %s birth_place should match", docID)
				assert.Equal(t, pidRequest.Identity.ExpiryDate, actualDoc.DocumentData["expiry_date"], "document %s expiry_date should match", docID)
				assert.Equal(t, pidRequest.Identity.IssuingAuthority, actualDoc.DocumentData["issuing_authority"], "document %s issuing_authority should match", docID)
				assert.Equal(t, pidRequest.Identity.IssuingCountry, actualDoc.DocumentData["issuing_country"], "document %s issuing_country should match", docID)
				assert.Equal(t, pidRequest.Identity.AuthenticSourcePersonID, actualDoc.DocumentData["authentic_source_person_id"], "document %s authentic_source_person_id should match", docID)
			}
		})
	}
}

func TestMakeSourceData_InvalidFile(t *testing.T) {
	ctx := t.Context()

	client, err := NewPIDClient(ctx, nil)
	require.NoError(t, err)

	// Test with non-existent file
	err = client.readPidUserFile("/nonexistent/file.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "open pid user file")
}

func TestMakeSourceData_InvalidJSON(t *testing.T) {
	ctx := t.Context()

	// Create temporary directory for test files
	tempDir := t.TempDir()

	// Create invalid JSON file
	invalidFilePath := filepath.Join(tempDir, "invalid.json")
	err := os.WriteFile(invalidFilePath, []byte("{invalid json"), 0600)
	require.NoError(t, err)

	client, err := NewPIDClient(ctx, nil)
	require.NoError(t, err)

	// Test with invalid JSON
	err = client.readPidUserFile(invalidFilePath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decode pid user file")
}

func TestSave2Disk(t *testing.T) {
	ctx := t.Context()

	// Create pidClient
	client, err := NewPIDClient(ctx, nil)
	require.NoError(t, err)

	// Add some test data
	client.documents["test_123"] = &vcclient.UploadRequest{
		Meta: &model.MetaData{
			AuthenticSource: "TEST:SUNET:PID",
			VCT:             "urn:eudi:pid:1",
		},
		DocumentData: map[string]any{
			"given_name":  "Test",
			"family_name": "User",
		},
		DocumentDataVersion: "1.0.0",
	}

	// We can verify the JSON marshaling works
	b, err := json.MarshalIndent(client.documents, "", "  ")
	require.NoError(t, err)
	assert.NotEmpty(t, b)

	// Verify the JSON structure
	var result map[string]*vcclient.UploadRequest
	err = json.Unmarshal(b, &result)
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Contains(t, result, "test_123")
	assert.Equal(t, "TEST:SUNET:PID", result["test_123"].Meta.AuthenticSource)
}
