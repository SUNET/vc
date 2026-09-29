package openid4vp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaimsExtractor_ExtractNestedClaim(t *testing.T) {
	ce := NewClaimsExtractor()

	tests := []struct {
		name      string
		claims    map[string]any
		path      string
		want      any
		wantError bool
	}{
		{
			name: "simple claim",
			claims: map[string]any{
				"given_name":  "John",
				"family_name": "Doe",
			},
			path: "given_name",
			want: "John",
		},
		{
			name: "nested claim - one level",
			claims: map[string]any{
				"address": map[string]any{
					"country": "SE",
					"city":    "Stockholm",
				},
			},
			path: "address.country",
			want: "SE",
		},
		{
			name: "nested claim - two levels",
			claims: map[string]any{
				"place_of_birth": map[string]any{
					"address": map[string]any{
						"country": "Sweden",
					},
				},
			},
			path: "place_of_birth.address.country",
			want: "Sweden",
		},
		{
			name: "claim not found",
			claims: map[string]any{
				"given_name": "John",
			},
			path:      "family_name",
			wantError: true,
		},
		{
			name: "nested path not found",
			claims: map[string]any{
				"address": map[string]any{
					"country": "SE",
				},
			},
			path:      "address.city",
			wantError: true,
		},
		{
			name: "empty path",
			claims: map[string]any{
				"given_name": "John",
			},
			path:      "",
			wantError: true,
		},
		{
			name: "non-object in path",
			claims: map[string]any{
				"birthdate": "1990-01-01",
			},
			path:      "birthdate.year",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ce.extractNestedClaim(tt.claims, tt.path)

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaimsExtractor_MapClaimsToOIDC(t *testing.T) {
	ce := NewClaimsExtractor()

	tests := []struct {
		name          string
		vpClaims      map[string]any
		claimMappings map[string]string
		want          map[string]any
		wantError     bool
	}{
		{
			name: "simple mapping",
			vpClaims: map[string]any{
				"given_name":  "John",
				"family_name": "Doe",
				"birthdate":   "1990-01-01",
			},
			claimMappings: map[string]string{
				"given_name":  "given_name",
				"family_name": "family_name",
			},
			want: map[string]any{
				"given_name":  "John",
				"family_name": "Doe",
			},
		},
		{
			name: "wildcard mapping - all claims",
			vpClaims: map[string]any{
				"given_name":  "John",
				"family_name": "Doe",
				"birthdate":   "1990-01-01",
				"_sd":         []string{"hash1", "hash2"}, // Should be filtered
				"_sd_alg":     "sha-256",                  // Should be filtered
			},
			claimMappings: map[string]string{
				"*": "*",
			},
			want: map[string]any{
				"given_name":  "John",
				"family_name": "Doe",
				"birthdate":   "1990-01-01",
			},
		},
		{
			name: "renamed claims",
			vpClaims: map[string]any{
				"given_name":  "John",
				"family_name": "Doe",
			},
			claimMappings: map[string]string{
				"given_name":  "first_name",
				"family_name": "last_name",
			},
			want: map[string]any{
				"first_name": "John",
				"last_name":  "Doe",
			},
		},
		{
			name: "nested claim mapping",
			vpClaims: map[string]any{
				"place_of_birth": map[string]any{
					"country": "Sweden",
					"city":    "Stockholm",
				},
			},
			claimMappings: map[string]string{
				"place_of_birth.country": "birth_country",
				"place_of_birth.city":    "birth_city",
			},
			want: map[string]any{
				"birth_country": "Sweden",
				"birth_city":    "Stockholm",
			},
		},
		{
			name: "partial mapping - missing claims ignored",
			vpClaims: map[string]any{
				"given_name": "John",
			},
			claimMappings: map[string]string{
				"given_name":  "given_name",
				"family_name": "family_name", // Not present in VP claims
				"birthdate":   "birthdate",   // Not present in VP claims
			},
			want: map[string]any{
				"given_name": "John",
			},
		},
		{
			name:          "nil VP claims",
			vpClaims:      nil,
			claimMappings: map[string]string{"given_name": "given_name"},
			wantError:     true,
		},
		{
			name:          "nil claim mappings",
			vpClaims:      map[string]any{"given_name": "John"},
			claimMappings: nil,
			wantError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ce.MapClaimsToOIDC(tt.vpClaims, tt.claimMappings)

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaimsExtractor_IsInternalClaim(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{"_sd", "_sd", true},
		{"_sd_alg", "_sd_alg", true},
		{"iss", "iss", false},
		{"iat", "iat", false},
		{"exp", "exp", false},
		{"nbf", "nbf", false},
		{"vct", "vct", true},
		{"cnf", "cnf", true},
		{"status", "status", true},
		{"given_name", "given_name", false},
		{"family_name", "family_name", false},
		{"birthdate", "birthdate", false},
		{"sub", "sub", false}, // 'sub' is actually used in OIDC, so it's not internal
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isInternalClaim(tt.key)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaimsExtractor_ExtractAndMapClaims_Integration(t *testing.T) {
	ce := NewClaimsExtractor()

	t.Run("pipeline maps PID claims and filters SD-JWT internals", func(t *testing.T) {
		vpClaims := map[string]any{
			"given_name":  "John",
			"family_name": "Doe",
			"birthdate":   "1990-01-15",
			"nationality": "SE",
			"_sd":         []string{"hash1"},
			"_sd_alg":     "sha-256",
		}

		claimMappings := map[string]string{
			"given_name":  "given_name",
			"family_name": "family_name",
			"birthdate":   "birthdate",
			"nationality": "nationality",
		}

		mapped, err := ce.MapClaimsToOIDC(vpClaims, claimMappings)
		require.NoError(t, err)

		assert.Equal(t, map[string]any{
			"given_name":  "John",
			"family_name": "Doe",
			"birthdate":   "1990-01-15",
			"nationality": "SE",
		}, mapped)
	})

	t.Run("pipeline maps EHIC nested claims", func(t *testing.T) {
		vpClaims := map[string]any{
			"card_number": "12345",
			"forename":    "John",
			"surname":     "Doe",
			"dob":         "1990-01-15",
			"institution": map[string]any{
				"name":    "Swedish Social Insurance Agency",
				"country": "SE",
			},
		}

		claimMappings := map[string]string{
			"card_number":         "ehic_card_number",
			"forename":            "given_name",
			"surname":             "family_name",
			"dob":                 "birthdate",
			"institution.name":    "insurance_provider",
			"institution.country": "insurance_country",
		}

		mapped, err := ce.MapClaimsToOIDC(vpClaims, claimMappings)
		require.NoError(t, err)

		assert.Equal(t, map[string]any{
			"ehic_card_number":   "12345",
			"given_name":         "John",
			"family_name":        "Doe",
			"birthdate":          "1990-01-15",
			"insurance_provider": "Swedish Social Insurance Agency",
			"insurance_country":  "SE",
		}, mapped)
	})
}

func TestClaimsExtractor_ExtractClaimsFromVPToken_MDocFormat(t *testing.T) {
	ce := NewClaimsExtractor()
	ctx := t.Context()

	// Create a minimal mdoc DeviceResponse
	deviceResponse := struct {
		Version   string `cbor:"version"`
		Status    uint   `cbor:"status"`
		Documents []struct {
			DocType      string `cbor:"docType"`
			IssuerSigned struct {
				NameSpaces map[string][]struct {
					ElementIdentifier string `cbor:"elementIdentifier"`
					ElementValue      any    `cbor:"elementValue"`
				} `cbor:"nameSpaces"`
			} `cbor:"issuerSigned"`
		} `cbor:"documents"`
	}{
		Version: "1.0",
		Status:  0,
		Documents: []struct {
			DocType      string `cbor:"docType"`
			IssuerSigned struct {
				NameSpaces map[string][]struct {
					ElementIdentifier string `cbor:"elementIdentifier"`
					ElementValue      any    `cbor:"elementValue"`
				} `cbor:"nameSpaces"`
			} `cbor:"issuerSigned"`
		}{
			{
				DocType: "org.iso.18013.5.1.mDL",
				IssuerSigned: struct {
					NameSpaces map[string][]struct {
						ElementIdentifier string `cbor:"elementIdentifier"`
						ElementValue      any    `cbor:"elementValue"`
					} `cbor:"nameSpaces"`
				}{
					NameSpaces: map[string][]struct {
						ElementIdentifier string `cbor:"elementIdentifier"`
						ElementValue      any    `cbor:"elementValue"`
					}{
						"org.iso.18013.5.1": {
							{ElementIdentifier: "family_name", ElementValue: "Smith"},
							{ElementIdentifier: "given_name", ElementValue: "Alice"},
						},
					},
				},
			},
		},
	}

	// Use internal cbor encoder since we can't easily import here
	// Instead, test via the ExtractMDocClaims which is already tested
	t.Run("format_detection", func(t *testing.T) {
		// JWT format should not be detected as mdoc
		jwtToken := "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig" // #nosec G101
		assert.False(t, isMDocFormatToken(jwtToken), "JWT should not be detected as mdoc")
	})

	// Test that the ClaimsExtractor routes correctly
	t.Run("empty_token", func(t *testing.T) {
		_, err := ce.ExtractClaimsFromVPToken(ctx, "")
		require.Error(t, err)
	})

	// Placeholder: in a full integration test we'd verify with actual mdoc tokens
	_ = deviceResponse
}

func TestClaimsExtractor_ExtractClaimsFromVPToken_DCQLArray(t *testing.T) {
	ce := NewClaimsExtractor()
	ctx := t.Context()

	t.Run("rejects_map_string_string_json", func(t *testing.T) {
		// Old format: map[string]string — should fail because DCQL values must be arrays
		vpToken := `{"cred1": "not-an-array"}`
		_, err := ce.ExtractClaimsFromVPToken(ctx, vpToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse DCQL vp_token")
	})

	t.Run("accepts_map_string_array_json", func(t *testing.T) {
		// New format: map[string][]string — this is what spec-compliant wallets send
		// The individual tokens will fail to parse (not real SD-JWTs), but the
		// JSON unmarshal into map[string][]string must succeed
		vpToken := `{"cred1": ["fake-token"]}`
		_, err := ce.ExtractClaimsFromVPToken(ctx, vpToken)
		require.Error(t, err)
		// Error should be about parsing the token, NOT about JSON unmarshalling
		assert.Contains(t, err.Error(), "failed to extract claims from credential")
		assert.NotContains(t, err.Error(), "failed to parse DCQL vp_token")
	})

	t.Run("empty_array_rejected", func(t *testing.T) {
		vpToken := `{"cred1": []}`
		_, err := ce.ExtractClaimsFromVPToken(ctx, vpToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty array")
	})

	t.Run("empty_object_rejected", func(t *testing.T) {
		vpToken := `{}`
		_, err := ce.ExtractClaimsFromVPToken(ctx, vpToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no credentials")
	})
}
