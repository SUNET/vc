package model

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeCredentialOffer(t *testing.T) {
	tts := []struct {
		name string
		have string
		want map[string]any
	}{
		{
			name: "working from greece wallet",
			have: "https://wallet.dc4eu.eu/cb?credential_offer=%7B%0A%20%20%22credential_issuer%22%3A%20%22https%3A%2F%2Fsatosa-test-1.sunet.se%22%2C%0A%20%20%22credential_configuration_ids%22%3A%20%5B%0A%20%20%20%20%22EHICCredential%22%0A%20%20%5D%2C%0A%20%20%22grants%22%3A%20%7B%0A%20%20%20%20%22authorization_code%22%3A%20%7B%0A%20%20%20%20%20%20%22issuer_state%22%3A%20%22authentic_source%3Dauthentic_source_se%26vct%3DEHIC%26collect_id%3Dcollect_id_10%22%0A%20%20%20%20%7D%0A%20%20%7D%0A%7D",
			want: map[string]any{ // #nosec G101
				"credential_issuer": "https://satosa-test-1.sunet.se",
				"credential_configuration_ids": []string{
					"EHICCredential",
				},
				"grants": map[string]any{
					"authorization_code": map[string]any{
						"issuer_state": "authentic_source=authentic_source_se&vct=EHIC&collect_id=collect_id_10",
					},
				},
			},
		},
		{
			name: "not working from credential constructor",
			have: "https://wallet.dc4eu.eu/cb?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fsatosa-test-1.sunet.se%22%2C%22credential_configuration_ids%22%3A%5B%22EHICCredential%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22collect_id%3Dcollect_id_ehic_86%5Cu0026vct%3DEHIC%5Cu0026authentic_source%3DEHIC%3A00001%22%7D%7D%7D",
			want: map[string]any{ // #nosec G101
				"credential_issuer": "https://satosa-test-1.sunet.se",
				"credential_configuration_ids": []string{
					"EHICCredential",
				},
				"grants": map[string]any{
					"authorization_code": map[string]any{
						"issuer_state": "collect_id=collect_id_ehic_86\u0026vct=EHIC\u0026authentic_source=EHIC:00001",
					},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			urlObject, err := url.Parse(tt.have)
			assert.NoError(t, err)

			values, err := url.ParseQuery(urlObject.RawQuery)
			assert.NoError(t, err)

			jsonWant, err := json.MarshalIndent(tt.want, "", "  ")
			assert.NoError(t, err)

			assert.JSONEq(t, string(jsonWant), values.Get("credential_offer"))

			fmt.Println("decoded", values.Get("credential_offer"))
		})
	}
}

func TestIdentity_GetOver14(t *testing.T) {
	currentYear := time.Now().Year()
	currentDate := time.Now()

	tests := []struct {
		name      string
		birthDate string
		want      bool
		wantErr   bool
	}{
		{
			name:      "person exactly 14 years old today",
			birthDate: time.Now().AddDate(-14, 0, 0).Format("2006-01-02"),
			want:      true,
			wantErr:   false,
		},
		{
			name:      "person 14 years and 1 day old",
			birthDate: time.Now().AddDate(-14, 0, -1).Format("2006-01-02"),
			want:      true,
			wantErr:   false,
		},
		{
			name:      "person 13 years 364 days old",
			birthDate: time.Now().AddDate(-14, 0, 1).Format("2006-01-02"),
			want:      false,
			wantErr:   false,
		},
		{
			name:      "person 15 years old",
			birthDate: time.Date(currentYear-15, 6, 15, 0, 0, 0, 0, time.UTC).Format("2006-01-02"),
			want:      true,
			wantErr:   false,
		},
		{
			name:      "person 25 years old",
			birthDate: time.Date(currentYear-25, 3, 10, 0, 0, 0, 0, time.UTC).Format("2006-01-02"),
			want:      true,
			wantErr:   false,
		},
		{
			name:      "person 13 years old",
			birthDate: time.Date(currentYear-13, 8, 20, 0, 0, 0, 0, time.UTC).Format("2006-01-02"),
			want:      false,
			wantErr:   false,
		},
		{
			name:      "person 10 years old",
			birthDate: time.Date(currentYear-10, 1, 1, 0, 0, 0, 0, time.UTC).Format("2006-01-02"),
			want:      false,
			wantErr:   false,
		},
		{
			name:      "person 5 years old",
			birthDate: time.Date(currentYear-5, 12, 25, 0, 0, 0, 0, time.UTC).Format("2006-01-02"),
			want:      false,
			wantErr:   false,
		},
		{
			name:      "person born today",
			birthDate: currentDate.Format("2006-01-02"),
			want:      false,
			wantErr:   false,
		},
		{
			name:      "person 65 years old",
			birthDate: time.Date(currentYear-65, 4, 12, 0, 0, 0, 0, time.UTC).Format("2006-01-02"),
			want:      true,
			wantErr:   false,
		},
		{
			name:      "person 100 years old",
			birthDate: time.Date(currentYear-100, 7, 8, 0, 0, 0, 0, time.UTC).Format("2006-01-02"),
			want:      true,
			wantErr:   false,
		},
		{
			name:      "invalid date format",
			birthDate: "not-a-date",
			want:      false,
			wantErr:   true,
		},
		{
			name:      "invalid date format - wrong separator",
			birthDate: "1990/01/01",
			want:      false,
			wantErr:   true,
		},
		{
			name:      "empty birth date",
			birthDate: "",
			want:      false,
			wantErr:   true,
		},
		{
			name:      "invalid date - month 13",
			birthDate: "1990-13-01",
			want:      false,
			wantErr:   true,
		},
		{
			name:      "invalid date - day 32",
			birthDate: "1990-01-32",
			want:      false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := &Identity{
				BirthDate: tt.birthDate,
			}

			got, err := identity.GetOver14()

			if tt.wantErr {
				assert.Error(t, err, "Expected an error for birth date: %s", tt.birthDate)
				return
			}

			require.NoError(t, err, "Unexpected error for birth date: %s", tt.birthDate)
			assert.Equal(t, tt.want, got, "GetOver14() result mismatch for birth date: %s", tt.birthDate)
		})
	}
}

func TestIdentity_GetOver14_EdgeCases(t *testing.T) {
	t.Run("birthday today - exactly 14 years", func(t *testing.T) {
		// Person who turns 14 today
		today := time.Now()
		birthDate := today.AddDate(-14, 0, 0).Format("2006-01-02")

		identity := &Identity{
			BirthDate: birthDate,
		}

		got, err := identity.GetOver14()
		require.NoError(t, err)
		assert.True(t, got, "Person turning 14 today should be considered over 14")
	})

	t.Run("birthday tomorrow - still 13", func(t *testing.T) {
		// Person who turns 14 tomorrow
		tomorrow := time.Now().AddDate(0, 0, 1)
		birthDate := tomorrow.AddDate(-14, 0, 0).Format("2006-01-02")

		identity := &Identity{
			BirthDate: birthDate,
		}

		got, err := identity.GetOver14()
		require.NoError(t, err)
		assert.False(t, got, "Person turning 14 tomorrow should not be considered over 14 yet")
	})

	t.Run("birthday yesterday - just turned 14", func(t *testing.T) {
		// Person who turned 14 yesterday
		yesterday := time.Now().AddDate(0, 0, -1)
		birthDate := yesterday.AddDate(-14, 0, 0).Format("2006-01-02")

		identity := &Identity{
			BirthDate: birthDate,
		}

		got, err := identity.GetOver14()
		require.NoError(t, err)
		assert.True(t, got, "Person who turned 14 yesterday should be considered over 14")
	})
}

func TestIdentity_GetOver14_LeapYear(t *testing.T) {
	t.Run("born on leap day - 15 years ago", func(t *testing.T) {
		// Testing over-14 age verification with a person born 15 years ago
		// Using 15 years ensures the person is definitively over the 14-year threshold
		currentYear := time.Now().Year()

		// Find the most recent leap year that was at least 15 years ago
		leapYear := currentYear - 15
		for leapYear%4 != 0 || (leapYear%100 == 0 && leapYear%400 != 0) {
			leapYear--
		}

		// If we found a valid leap year
		if leapYear%4 == 0 && (leapYear%100 != 0 || leapYear%400 == 0) {
			birthDate := time.Date(leapYear, 2, 29, 0, 0, 0, 0, time.UTC).Format("2006-01-02")

			identity := &Identity{
				BirthDate: birthDate,
			}

			got, err := identity.GetOver14()
			require.NoError(t, err)
			assert.True(t, got, "Person born on leap day %d years ago should be over 14", currentYear-leapYear)
		}
	})
}

func TestIdentity_Marshal(t *testing.T) {
	identity := &Identity{
		AuthenticSourcePersonID: "AUTH123",
		FamilyName:              "Doe",
		GivenName:               "John",
		BirthDate:               "1990-01-01",
		BirthPlace:              "Stockholm",
		Nationality:             []string{"SE"},
		Sex:                     "1",
		EmailAddress:            "john.doe@example.com",
		MobilePhoneNumber:       "+46701234567",
		AgeOver14:               "true",
		AgeOver16:               true,
		AgeOver18:               true,
		AgeOver21:               true,
		AgeOver65:               false,
		AgeInYears:              35,
		AgeBirthYear:            1990,
	}

	result, err := identity.Marshal()
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify key fields are present
	assert.Equal(t, "AUTH123", result["authentic_source_person_id"])
	assert.Equal(t, "Doe", result["family_name"])
	assert.Equal(t, "John", result["given_name"])
	assert.Equal(t, "1990-01-01", result["birth_date"])
	assert.Equal(t, "Stockholm", result["birth_place"])
	assert.Equal(t, "1", result["sex"])
	assert.Equal(t, "john.doe@example.com", result["email_address"])
	assert.Equal(t, "+46701234567", result["mobile_phone_number"])
	assert.Equal(t, "true", result["age_over_14"])
	assert.Equal(t, true, result["age_over_16"])
	assert.Equal(t, true, result["age_over_18"])
	assert.Equal(t, true, result["age_over_21"])
	// Note: age_over_65 is false and has omitempty, so it won't be in the result
	assert.Equal(t, float64(35), result["age_in_years"]) // JSON numbers are float64
	assert.Equal(t, float64(1990), result["age_birth_year"])
}

func TestIdentity_Marshal_WithNationality(t *testing.T) {
	identity := &Identity{
		FamilyName:  "Smith",
		GivenName:   "Jane",
		BirthDate:   "1985-05-15",
		Nationality: []string{"SE", "NO"},
	}

	result, err := identity.Marshal()
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify nationality array
	nationality, ok := result["nationality"].([]any)
	require.True(t, ok)
	require.Len(t, nationality, 2)
	assert.Equal(t, "SE", nationality[0])
	assert.Equal(t, "NO", nationality[1])
}

func TestIdentity_Marshal_EmptyFields(t *testing.T) {
	identity := &Identity{
		FamilyName: "Test",
		GivenName:  "User",
		BirthDate:  "2000-01-01",
	}

	result, err := identity.Marshal()
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify required fields are present
	assert.Equal(t, "Test", result["family_name"])
	assert.Equal(t, "User", result["given_name"])
	assert.Equal(t, "2000-01-01", result["birth_date"])

	// Optional fields should not be present or be empty
	// (depending on omitempty tag behavior)
}
