package bootstrapper

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"vc/pkg/model"
	"vc/pkg/vcclient"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPIDClient_makeSourceData(t *testing.T) {
	ctx := t.Context()

	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "pid-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Create test PID user data
	testPIDUsers := map[string]*vcclient.AddPIDRequest{
		"PID001": {
			Identity: &model.Identity{
				GivenName:                    "John",
				FamilyName:                   "Doe",
				BirthDate:                    "1990-01-01",
				IssuingAuthority:             "National Authority",
				IssuingCountry:               "SE",
				BirthPlace:                   "Stockholm",
				ExpiryDate:                   "2030-12-31",
				AuthenticSourcePersonID:      "AUTH123",
				AgeBirthYear:                 1990,
				AgeInYears:                   35,
				AgeOver14:                    "true",
				AgeOver16:                    true,
				AgeOver18:                    true,
				AgeOver21:                    true,
				AgeOver65:                    false,
				BirthFamilyName:              "Smith",
				BirthGivenName:               "Jonathan",
				DocumentNumber:               "DOC123456",
				EmailAddress:                 "john.doe@example.com",
				IssuanceDate:                 "2020-01-01",
				IssuingJurisdiction:          "Stockholm County",
				MobilePhoneNumber:            "+46701234567",
				Nationality:                  []string{"SE"},
				PersonalAdministrativeNumber: "199001011234",
				Picture:                      "base64encodedpicture",
				ResidentAddress:              "Main Street 123",
				ResidentCity:                 "Stockholm",
				ResidentCountry:              "SE",
				ResidentHouseNumber:          "123",
				ResidentPostalCode:           "12345",
				ResidentState:                "Stockholm",
				ResidentStreetAddress:        "Main Street",
				Sex:                          "1",
				TrustAnchor:                  "TrustAnchor123",
			},
		},
		"PID002": {
			Identity: &model.Identity{
				GivenName:                    "Jane",
				FamilyName:                   "Smith",
				BirthDate:                    "1985-05-15",
				IssuingAuthority:             "Regional Authority",
				IssuingCountry:               "NO",
				BirthPlace:                   "Oslo",
				ExpiryDate:                   "2028-06-30",
				AuthenticSourcePersonID:      "AUTH456",
				AgeBirthYear:                 1985,
				AgeInYears:                   40,
				AgeOver14:                    "true",
				AgeOver16:                    true,
				AgeOver18:                    true,
				AgeOver21:                    true,
				AgeOver65:                    false,
				BirthFamilyName:              "Johnson",
				BirthGivenName:               "Janet",
				DocumentNumber:               "DOC789012",
				EmailAddress:                 "jane.smith@example.com",
				IssuanceDate:                 "2018-06-15",
				IssuingJurisdiction:          "Oslo Municipality",
				MobilePhoneNumber:            "+4712345678",
				Nationality:                  []string{"NO"},
				PersonalAdministrativeNumber: "198505151234",
				Picture:                      "base64encodedpicture2",
				ResidentAddress:              "Oak Avenue 456",
				ResidentCity:                 "Oslo",
				ResidentCountry:              "NO",
				ResidentHouseNumber:          "456",
				ResidentPostalCode:           "0123",
				ResidentState:                "Oslo",
				ResidentStreetAddress:        "Oak Avenue",
				Sex:                          "2",
				TrustAnchor:                  "TrustAnchor456",
			},
		},
	}

	// Write test data to a temporary file
	testFilePath := filepath.Join(tmpDir, "test_pid_users.json")
	testData, err := json.MarshalIndent(testPIDUsers, "", "  ")
	require.NoError(t, err)
	err = os.WriteFile(testFilePath, testData, 0600)
	require.NoError(t, err)

	// Create PID client
	client, err := NewPIDClient(ctx, nil)
	require.NoError(t, err)

	// Test makeSourceData
	err = client.makeSourceData(testFilePath)
	require.NoError(t, err)

	// Verify that documents were created for both PID users
	assert.Len(t, client.documents, 2, "Should have created 2 documents")
	assert.Contains(t, client.documents, "PID001")
	assert.Contains(t, client.documents, "PID002")

	// Test PID001 document
	t.Run("PID001 Document Data", func(t *testing.T) {
		doc := client.documents["PID001"]
		require.NotNil(t, doc)
		require.NotNil(t, doc.DocumentData)

		// Verify all mandatory fields
		assert.Equal(t, "John", doc.DocumentData["given_name"])
		assert.Equal(t, "Doe", doc.DocumentData["family_name"])
		assert.Equal(t, "1990-01-01", doc.DocumentData["birthdate"])
		assert.Equal(t, "National Authority", doc.DocumentData["issuing_authority"])
		assert.Equal(t, "SE", doc.DocumentData["issuing_country"])
		assert.Equal(t, "Stockholm", doc.DocumentData["birth_place"])
		assert.Equal(t, "2030-12-31", doc.DocumentData["expiry_date"])
		assert.Equal(t, "AUTH123", doc.DocumentData["authentic_source_person_id"])
		assert.Equal(t, "1.5", doc.DocumentData["arf"])

		// Verify ARF 1.5 additional fields
		assert.Equal(t, 1990, doc.DocumentData["age_birth_year"])
		assert.Equal(t, 35, doc.DocumentData["age_in_years"])
		assert.Equal(t, "true", doc.DocumentData["age_over_14"])
		assert.Equal(t, true, doc.DocumentData["age_over_16"])
		assert.Equal(t, true, doc.DocumentData["age_over_18"])
		assert.Equal(t, true, doc.DocumentData["age_over_21"])
		assert.Equal(t, false, doc.DocumentData["age_over_65"])
		assert.Equal(t, "Smith", doc.DocumentData["birth_family_name"])
		assert.Equal(t, "Jonathan", doc.DocumentData["birth_given_name"])
		assert.Equal(t, "DOC123456", doc.DocumentData["document_number"])
		assert.Equal(t, "john.doe@example.com", doc.DocumentData["email_address"])
		assert.Equal(t, "2020-01-01", doc.DocumentData["issuance_date"])
		assert.Equal(t, "Stockholm County", doc.DocumentData["issuing_jurisdiction"])
		assert.Equal(t, "+46701234567", doc.DocumentData["mobile_phone_number"])
		assert.Equal(t, []string{"SE"}, doc.DocumentData["nationality"])
		assert.Equal(t, "199001011234", doc.DocumentData["personal_administrative_number"])
		assert.Equal(t, "base64encodedpicture", doc.DocumentData["picture"])
		assert.Equal(t, "Main Street 123", doc.DocumentData["resident_address"])
		assert.Equal(t, "Stockholm", doc.DocumentData["resident_city"])
		assert.Equal(t, "SE", doc.DocumentData["resident_country"])
		assert.Equal(t, "123", doc.DocumentData["resident_house_number"])
		assert.Equal(t, "12345", doc.DocumentData["resident_postal_code"])
		assert.Equal(t, "Stockholm", doc.DocumentData["resident_state"])
		assert.Equal(t, "Main Street", doc.DocumentData["resident_street_address"])
		assert.Equal(t, "1", doc.DocumentData["sex"])
		assert.Equal(t, "TrustAnchor123", doc.DocumentData["trust_anchor"])
	})

	// Test PID001 metadata
	t.Run("PID001 Metadata", func(t *testing.T) {
		doc := client.documents["PID001"]
		require.NotNil(t, doc.Meta)

		assert.Equal(t, "PID_Provider:00001", doc.Meta.AuthenticSource)
		assert.Equal(t, "1.0.0", doc.Meta.DocumentVersion)
		assert.Equal(t, model.CredentialTypeUrnEudiPidARF151, doc.Meta.VCT)
		assert.Equal(t, "document_id_pid_arf_1_5_PID001", doc.Meta.DocumentID)
		assert.False(t, doc.Meta.RealData)
		require.NotNil(t, doc.Meta.Collect)
		assert.Equal(t, "collect_id_pid_PID001", doc.Meta.Collect.ID)
	})

	// Test PID001 document display
	t.Run("PID001 Document Display", func(t *testing.T) {
		doc := client.documents["PID001"]
		require.NotNil(t, doc.DocumentDisplay)

		assert.Equal(t, "1.0.0", doc.DocumentDisplay.Version)
		assert.Equal(t, "secure", doc.DocumentDisplay.Type)
		require.NotNil(t, doc.DocumentDisplay.DescriptionStructured)

		enDesc, ok := doc.DocumentDisplay.DescriptionStructured["en"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "Personal Identification Document", enDesc["description"])

		svDesc, ok := doc.DocumentDisplay.DescriptionStructured["sv"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "Personligt identifikationsdokument", svDesc["beskrivning"])
	})

	// Test PID001 identities
	t.Run("PID001 Identities", func(t *testing.T) {
		doc := client.documents["PID001"]
		require.NotNil(t, doc.Identities)
		require.Len(t, doc.Identities, 1)

		identity := doc.Identities[0]
		assert.Equal(t, "John", identity.GivenName)
		assert.Equal(t, "Doe", identity.FamilyName)
		assert.Equal(t, "1990-01-01", identity.BirthDate)
	})

	// Test PID002 document with different values
	t.Run("PID002 Document Data", func(t *testing.T) {
		doc := client.documents["PID002"]
		require.NotNil(t, doc)
		require.NotNil(t, doc.DocumentData)

		assert.Equal(t, "Jane", doc.DocumentData["given_name"])
		assert.Equal(t, "Smith", doc.DocumentData["family_name"])
		assert.Equal(t, "1985-05-15", doc.DocumentData["birthdate"])
		assert.Equal(t, "NO", doc.DocumentData["issuing_country"])
		assert.Equal(t, "2", doc.DocumentData["sex"])
		assert.Equal(t, "198505151234", doc.DocumentData["personal_administrative_number"])
	})

	// Test document data version
	t.Run("Document Data Version", func(t *testing.T) {
		for pidNum, doc := range client.documents {
			assert.Equal(t, "1.0.0", doc.DocumentDataVersion, "Document %s should have version 1.0.0", pidNum)
		}
	})
}

func TestPIDClient_makeSourceData_InvalidFile(t *testing.T) {
	ctx := t.Context()
	client, err := NewPIDClient(ctx, nil)
	require.NoError(t, err)

	// Test with non-existent file
	err = client.makeSourceData("/non/existent/file.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read pid user file")
}

func TestPIDClient_makeSourceData_InvalidJSON(t *testing.T) {
	ctx := t.Context()

	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "pid-test-invalid-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Write invalid JSON to a temporary file
	testFilePath := filepath.Join(tmpDir, "invalid.json")
	err = os.WriteFile(testFilePath, []byte("{ invalid json }"), 0600)
	require.NoError(t, err)

	client, err := NewPIDClient(ctx, nil)
	require.NoError(t, err)

	// Test makeSourceData with invalid JSON
	err = client.makeSourceData(testFilePath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read pid user file")
}

func TestPIDClient_makeSourceData_EmptyData(t *testing.T) {
	ctx := t.Context()

	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "pid-test-empty-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	// Write empty PID user data to a temporary file
	testFilePath := filepath.Join(tmpDir, "empty_pid_users.json")
	testData := map[string]*vcclient.AddPIDRequest{}
	jsonData, err := json.MarshalIndent(testData, "", "  ")
	require.NoError(t, err)
	err = os.WriteFile(testFilePath, jsonData, 0600)
	require.NoError(t, err)

	client, err := NewPIDClient(ctx, nil)
	require.NoError(t, err)

	// Test makeSourceData with empty data
	err = client.makeSourceData(testFilePath)
	require.NoError(t, err)

	// Verify no documents were created
	assert.Empty(t, client.documents, "Should have created 0 documents for empty input")
}
