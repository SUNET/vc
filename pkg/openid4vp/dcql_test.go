package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

var mockDCQLExample = []byte(`{
  "credentials": [
    {
      "id": "my_credential",
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": [ "https://credentials.example.com/identity_credential" ]
      },
      "claims": [
          {"path": ["last_name"]},
          {"path": ["first_name"]},
          {"path": ["address", "street_address"]}
      ]
    }
  ]
}`)

var mockDCQLExampleFromWWWallet = []byte(`{
  "credentials": [
    {
      "id": "CustomVerifiableId0",
      "format": "vc+sd-jwt",
      "meta": {
        "vct_values": [
          "urn:eudi:pid:1"
        ]
      },
      "claims": [
        {"path": ["given_name"]},
        {"path": ["birth_given_name"]},
        {"path": ["family_name"]},
        {"path": ["birth_family_name"]},
        {"path": ["birthdate"]},
        {"path": ["place_of_birth", "country"]},
        {"path": ["place_of_birth", "region"]},
        {"path": ["place_of_birth", "locality"]},
        {"path": ["nationalities"]},
        {"path": ["personal_administrative_number"]},
        {"path": ["sex"]},
        {"path": ["address", "formatted"]},
        {"path": ["address", "street_address"]},
        {"path": ["address", "house_number"]},
        {"path": ["address", "postal_code"]},
        {"path": ["address", "locality"]},
        {"path": ["address", "region"]},
        {"path": ["address", "country"]},
        {"path": ["age_equal_or_over", "14"]},
        {"path": ["age_equal_or_over", "16"]},
        {"path": ["age_equal_or_over", "18"]},
        {"path": ["age_equal_or_over", "21"]},
        {"path": ["age_equal_or_over", "65"]},
        {"path": ["age_in_years"]},
        {"path": ["age_birth_year"]},
        {"path": ["email"]},
        {"path": ["phone_number"]},
        {"path": ["issuing_authority"]},
        {"path": ["issuing_country"]},
        {"path": ["issuing_jurisdiction"]},
        {"path": ["date_of_expiry"]},
        {"path": ["date_of_issuance"]},
        {"path": ["document_number"]},
        {"path": ["picture"]}
      ]
    }
  ],
  "credential_sets": [
    {
      "options": [
        ["CustomVerifiableId0"]
      ],
      "purpose": "Purpose not specified"
    }
  ]
}`)

func TestExample(t *testing.T) {
	tts := []struct {
		name string
		have *DCQL
		want []byte
	}{
		{
			name: "example from spec",
			have: &DCQL{
				Credentials: []CredentialQuery{
					{
						ID:     "my_credential",
						Format: "dc+sd-jwt",
						Meta: MetaQuery{
							VCTValues: []string{"https://credentials.example.com/identity_credential"},
						},
						Claims: []ClaimQuery{
							{Path: StringPath("last_name")},
							{Path: StringPath("first_name")},
							{Path: StringPath("address", "street_address")},
						},
					},
				},
			},
			want: mockDCQLExample,
		},
		{
			name: "example from wwwallet",
			have: &DCQL{
				CredentialSets: []CredentialSetQuery{
					{
						Options: [][]string{{"CustomVerifiableId0"}},
						Purpose: "Purpose not specified",
					},
				},
				Credentials: []CredentialQuery{
					{
						ID:     "CustomVerifiableId0",
						Format: "vc+sd-jwt",
						Meta: MetaQuery{
							VCTValues: []string{"urn:eudi:pid:1"},
						},
						Claims: []ClaimQuery{
							{Path: StringPath("given_name")},
							{Path: StringPath("birth_given_name")},
							{Path: StringPath("family_name")},
							{Path: StringPath("birth_family_name")},
							{Path: StringPath("birthdate")},
							{Path: StringPath("place_of_birth", "country")},
							{Path: StringPath("place_of_birth", "region")},
							{Path: StringPath("place_of_birth", "locality")},
							{Path: StringPath("nationalities")},
							{Path: StringPath("personal_administrative_number")},
							{Path: StringPath("sex")},
							{Path: StringPath("address", "formatted")},
							{Path: StringPath("address", "street_address")},
							{Path: StringPath("address", "house_number")},
							{Path: StringPath("address", "postal_code")},
							{Path: StringPath("address", "locality")},
							{Path: StringPath("address", "region")},
							{Path: StringPath("address", "country")},
							{Path: StringPath("age_equal_or_over", "14")},
							{Path: StringPath("age_equal_or_over", "16")},
							{Path: StringPath("age_equal_or_over", "18")},
							{Path: StringPath("age_equal_or_over", "21")},
							{Path: StringPath("age_equal_or_over", "65")},
							{Path: StringPath("age_in_years")},
							{Path: StringPath("age_birth_year")},
							{Path: StringPath("email")},
							{Path: StringPath("phone_number")},
							{Path: StringPath("issuing_authority")},
							{Path: StringPath("issuing_country")},
							{Path: StringPath("issuing_jurisdiction")},
							{Path: StringPath("date_of_expiry")},
							{Path: StringPath("date_of_issuance")},
							{Path: StringPath("document_number")},
							{Path: StringPath("picture")},
						},
					},
				},
			},
			want: mockDCQLExampleFromWWWallet,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.MarshalIndent(tt.have, "", "  ")
			assert.NoError(t, err)
			assert.JSONEq(t, string(tt.want), string(got))
		})
	}
}

// TestClaimSetsRoundTrip verifies that claim_sets ([][]string) and claim IDs
// survive JSON marshal/unmarshal round-trips per OID4VP §6.4.1.
func TestClaimSetsRoundTrip(t *testing.T) {
	dcql := &DCQL{
		Credentials: []CredentialQuery{
			{
				ID:     "pid",
				Format: "dc+sd-jwt",
				Meta: MetaQuery{
					VCTValues: []string{"urn:eudi:pid:1"},
				},
				Claims: []ClaimQuery{
					{ID: "name", Path: StringPath("given_name")},
					{ID: "family", Path: StringPath("family_name")},
					{ID: "age", Path: StringPath("age_over_18")},
				},
				ClaimSet: [][]string{
					{"name", "family"},
					{"name", "age"},
				},
			},
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(dcql)
	assert.NoError(t, err)

	// Unmarshal back
	var decoded DCQL
	err = json.Unmarshal(data, &decoded)
	assert.NoError(t, err)

	cred := decoded.Credentials[0]
	// Verify claim IDs survived
	assert.Equal(t, "name", cred.Claims[0].ID)
	assert.Equal(t, "family", cred.Claims[1].ID)
	assert.Equal(t, "age", cred.Claims[2].ID)

	// Verify claim_sets survived as [][]string
	assert.Equal(t, [][]string{{"name", "family"}, {"name", "age"}}, cred.ClaimSet)

	// Verify the JSON contains expected structure
	assert.Contains(t, string(data), `"claim_sets"`)
	assert.Contains(t, string(data), `"id":"name"`)
}
