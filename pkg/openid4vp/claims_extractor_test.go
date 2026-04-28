package openid4vp

import (
	"testing"
	"time"

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

func TestClaimsExtractor_TransformDateFormat(t *testing.T) {
	ce := NewClaimsExtractor()

	tests := []struct {
		name      string
		value     any
		params    map[string]string
		want      any
		wantError bool
	}{
		{
			name:  "ISO to DD/MM/YYYY",
			value: "1990-01-15",
			params: map[string]string{
				"from": "2006-01-02",
				"to":   "02/01/2006",
			},
			want: "15/01/1990",
		},
		{
			name:  "DD/MM/YYYY to ISO",
			value: "15/01/1990",
			params: map[string]string{
				"from": "02/01/2006",
				"to":   "2006-01-02",
			},
			want: "1990-01-15",
		},
		{
			name:  "with time",
			value: "2024-03-15T14:30:00Z",
			params: map[string]string{
				"from": time.RFC3339,
				"to":   "2006-01-02",
			},
			want: "2024-03-15",
		},
		{
			name:  "missing from parameter",
			value: "1990-01-15",
			params: map[string]string{
				"to": "02/01/2006",
			},
			wantError: true,
		},
		{
			name:  "missing to parameter",
			value: "1990-01-15",
			params: map[string]string{
				"from": "2006-01-02",
			},
			wantError: true,
		},
		{
			name:      "non-string value",
			value:     12345,
			params:    map[string]string{"from": "2006-01-02", "to": "02/01/2006"},
			wantError: true,
		},
		{
			name:  "invalid date format",
			value: "not-a-date",
			params: map[string]string{
				"from": "2006-01-02",
				"to":   "02/01/2006",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ce.transformDateFormat(tt.value, tt.params)

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaimsExtractor_TransformBooleanString(t *testing.T) {
	ce := NewClaimsExtractor()

	tests := []struct {
		name      string
		value     any
		params    map[string]string
		want      any
		wantError bool
	}{
		{
			name:   "true to yes (default)",
			value:  true,
			params: map[string]string{},
			want:   "yes",
		},
		{
			name:   "false to no (default)",
			value:  false,
			params: map[string]string{},
			want:   "no",
		},
		{
			name:  "true with custom value",
			value: true,
			params: map[string]string{
				"true_value":  "TRUE",
				"false_value": "FALSE",
			},
			want: "TRUE",
		},
		{
			name:  "false with custom value",
			value: false,
			params: map[string]string{
				"true_value":  "TRUE",
				"false_value": "FALSE",
			},
			want: "FALSE",
		},
		{
			name:      "non-boolean value",
			value:     "not a boolean",
			params:    map[string]string{},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ce.transformBooleanString(tt.value, tt.params)

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaimsExtractor_TransformUppercase(t *testing.T) {
	ce := NewClaimsExtractor()

	tests := []struct {
		name      string
		value     any
		want      any
		wantError bool
	}{
		{
			name:  "lowercase to uppercase",
			value: "hello world",
			want:  "HELLO WORLD",
		},
		{
			name:  "mixed case",
			value: "Hello World",
			want:  "HELLO WORLD",
		},
		{
			name:  "already uppercase",
			value: "HELLO",
			want:  "HELLO",
		},
		{
			name:      "non-string value",
			value:     12345,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ce.transformUppercase(tt.value)

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaimsExtractor_TransformLowercase(t *testing.T) {
	ce := NewClaimsExtractor()

	tests := []struct {
		name      string
		value     any
		want      any
		wantError bool
	}{
		{
			name:  "uppercase to lowercase",
			value: "HELLO WORLD",
			want:  "hello world",
		},
		{
			name:  "mixed case",
			value: "Hello World",
			want:  "hello world",
		},
		{
			name:  "already lowercase",
			value: "hello",
			want:  "hello",
		},
		{
			name:      "non-string value",
			value:     12345,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ce.transformLowercase(tt.value)

			if tt.wantError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClaimsExtractor_ApplyClaimTransforms(t *testing.T) {
	ce := NewClaimsExtractor()

	tests := []struct {
		name          string
		claims        map[string]any
		transformDefs map[string]ClaimTransformDef
		want          map[string]any
		wantError     bool
	}{
		{
			name: "no transforms",
			claims: map[string]any{
				"given_name": "John",
			},
			transformDefs: nil,
			want: map[string]any{
				"given_name": "John",
			},
		},
		{
			name: "date format transform",
			claims: map[string]any{
				"birthdate": "1990-01-15",
			},
			transformDefs: map[string]ClaimTransformDef{
				"birthdate": {
					Type: "date_format",
					Params: map[string]string{
						"from": "2006-01-02",
						"to":   "02/01/2006",
					},
				},
			},
			want: map[string]any{
				"birthdate": "15/01/1990",
			},
		},
		{
			name: "boolean transform",
			claims: map[string]any{
				"age_over_18": true,
			},
			transformDefs: map[string]ClaimTransformDef{
				"age_over_18": {
					Type:   "boolean_string",
					Params: map[string]string{},
				},
			},
			want: map[string]any{
				"age_over_18": "yes",
			},
		},
		{
			name: "multiple transforms",
			claims: map[string]any{
				"given_name":  "john",
				"family_name": "DOE",
				"age_over_18": true,
			},
			transformDefs: map[string]ClaimTransformDef{
				"given_name": {
					Type: "uppercase",
				},
				"family_name": {
					Type: "lowercase",
				},
				"age_over_18": {
					Type: "boolean_string",
				},
			},
			want: map[string]any{
				"given_name":  "JOHN",
				"family_name": "doe",
				"age_over_18": "yes",
			},
		},
		{
			name: "transform non-existent claim - should skip",
			claims: map[string]any{
				"given_name": "John",
			},
			transformDefs: map[string]ClaimTransformDef{
				"family_name": { // Not present in claims
					Type: "uppercase",
				},
			},
			want: map[string]any{
				"given_name": "John",
			},
		},
		{
			name: "invalid transform type",
			claims: map[string]any{
				"given_name": "John",
			},
			transformDefs: map[string]ClaimTransformDef{
				"given_name": {
					Type: "unknown_transform",
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ce.ApplyClaimTransforms(tt.claims, tt.transformDefs)

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
		{"iss", "iss", true},
		{"iat", "iat", true},
		{"exp", "exp", true},
		{"nbf", "nbf", true},
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
	ctx := t.Context()

	t.Run("complete pipeline - PID basic", func(t *testing.T) {
		// Simulate a simple SD-JWT VP token (would normally come from sdjwtvc.CredentialParser)
		// For testing, we'll skip actual VP parsing and test the mapping/transform pipeline

		vpClaims := map[string]any{
			"given_name":  "John",
			"family_name": "Doe",
			"birthdate":   "1990-01-15",
			"age_over_18": true,
			"nationality": "SE",
			"_sd":         []string{"hash1"},
			"_sd_alg":     "sha-256",
		}

		claimMappings := map[string]string{
			"given_name":  "given_name",
			"family_name": "family_name",
			"birthdate":   "birthdate",
			"age_over_18": "age_over_18",
			"nationality": "nationality",
		}

		transformDefs := map[string]ClaimTransformDef{
			"birthdate": {
				Type: "date_format",
				Params: map[string]string{
					"from": "2006-01-02",
					"to":   "02/01/2006",
				},
			},
			"age_over_18": {
				Type: "boolean_string",
			},
		}

		// Map and transform (skipping extraction for this test)
		mapped, err := ce.MapClaimsToOIDC(vpClaims, claimMappings)
		require.NoError(t, err)

		transformed, err := ce.ApplyClaimTransforms(mapped, transformDefs)
		require.NoError(t, err)

		expected := map[string]any{
			"given_name":  "John",
			"family_name": "Doe",
			"birthdate":   "15/01/1990",
			"age_over_18": "yes",
			"nationality": "SE",
		}

		assert.Equal(t, expected, transformed)
	})

	t.Run("complete pipeline - EHIC with nested claims", func(t *testing.T) {
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

		transformDefs := map[string]ClaimTransformDef{
			"birthdate": {
				Type: "date_format",
				Params: map[string]string{
					"from": "2006-01-02",
					"to":   "02/01/2006",
				},
			},
		}

		mapped, err := ce.MapClaimsToOIDC(vpClaims, claimMappings)
		require.NoError(t, err)

		transformed, err := ce.ApplyClaimTransforms(mapped, transformDefs)
		require.NoError(t, err)

		expected := map[string]any{
			"ehic_card_number":   "12345",
			"given_name":         "John",
			"family_name":        "Doe",
			"birthdate":          "15/01/1990",
			"insurance_provider": "Swedish Social Insurance Agency",
			"insurance_country":  "SE",
		}

		assert.Equal(t, expected, transformed)
	})

	// Note: Actual VP token extraction tests would require valid SD-JWT tokens
	// Those are tested in integration tests with real token generation
	_ = ctx // Placeholder for when we add actual extraction tests
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
		assert.False(t, IsMDocFormat(jwtToken), "JWT should not be detected as mdoc")
	})

	// Test that the ClaimsExtractor routes correctly
	t.Run("empty_token", func(t *testing.T) {
		_, err := ce.ExtractClaimsFromVPToken(ctx, "")
		require.Error(t, err)
	})

	// Placeholder: in a full integration test we'd verify with actual mdoc tokens
	_ = deviceResponse
}
