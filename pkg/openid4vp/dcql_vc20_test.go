//go:build vc20

package openid4vp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetaQueryJSONSerialization(t *testing.T) {
	meta := MetaQuery{
		VCTValues:    []string{"https://example.com/credential"},
		TypeValues:   [][]string{{"VerifiableCredential", "PersonalID"}},
		DoctypeValue: "org.iso.18013.5.1.mDL",
	}

	jsonData, err := json.Marshal(meta)
	require.NoError(t, err)

	var decoded MetaQuery
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	assert.Equal(t, meta.VCTValues, decoded.VCTValues)
	assert.Equal(t, meta.TypeValues, decoded.TypeValues)
	assert.Equal(t, meta.DoctypeValue, decoded.DoctypeValue)
}

func TestVPFormatsSupportedJSONSerialization(t *testing.T) {
	formats := VPFormatsSupported{
		LDPVC: &LDPVCFormat{
			ProofTypeValues:   []string{"DataIntegrityProof"},
			CryptosuiteValues: []string{"eddsa-2022", "ecdsa-2019"},
		},
		JWTVCJson: &JWTVCFormat{
			AlgValues: []string{"ES256", "ES384"},
		},
	}

	jsonData, err := json.Marshal(formats)
	require.NoError(t, err)

	var decoded VPFormatsSupported
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	assert.Equal(t, formats.LDPVC.ProofTypeValues, decoded.LDPVC.ProofTypeValues)
	assert.Equal(t, formats.LDPVC.CryptosuiteValues, decoded.LDPVC.CryptosuiteValues)
	assert.Equal(t, formats.JWTVCJson.AlgValues, decoded.JWTVCJson.AlgValues)
}

func TestDCQLQueryExample(t *testing.T) {
	dcql := DCQL{
		Credentials: []CredentialQuery{
			{
				ID:     "pid_credential",
				Format: "ldp_vc",
				Meta: MetaQuery{
					TypeValues: [][]string{{"VerifiableCredential", "PersonalID"}},
				},
				Claims: []ClaimQuery{
					{Path: []string{"given_name"}},
					{Path: []string{"family_name"}},
					{Path: []string{"birth_date"}},
				},
			},
		},
		CredentialSets: []CredentialSetQuery{
			{
				Options: [][]string{{"pid_credential"}},
			},
		},
	}

	jsonData, err := json.Marshal(dcql)
	require.NoError(t, err)
	assert.NotEmpty(t, jsonData)

	var decoded DCQL
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	assert.Equal(t, 1, len(decoded.Credentials))
	assert.Equal(t, "pid_credential", decoded.Credentials[0].ID)
	assert.Equal(t, "ldp_vc", decoded.Credentials[0].Format)
	assert.Equal(t, 3, len(decoded.Credentials[0].Claims))
	assert.Equal(t, 1, len(decoded.CredentialSets))
}

func TestValidateCredentialQuerySDJWT(t *testing.T) {
	tests := []struct {
		name        string
		query       CredentialQuery
		expectError bool
	}{
		{
			name: "valid SD-JWT with VCT",
			query: CredentialQuery{
				ID:     "test",
				Format: FormatSDJWTVC,
				Meta: MetaQuery{
					VCTValues: []string{"https://example.com/credential"},
				},
			},
			expectError: false,
		},
		{
			name: "SD-JWT missing VCT",
			query: CredentialQuery{
				ID:     "test",
				Format: FormatSDJWTVC,
				Meta:   MetaQuery{},
			},
			expectError: true,
		},
		{
			name: "SD-JWT empty VCT array",
			query: CredentialQuery{
				ID:     "test",
				Format: FormatSDJWTVC,
				Meta: MetaQuery{
					VCTValues: []string{},
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCredentialQuery(tt.query)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateCredentialQueryMdoc(t *testing.T) {
	tests := []struct {
		name        string
		query       CredentialQuery
		expectError bool
	}{
		{
			name: "valid mdoc with doctype",
			query: CredentialQuery{
				ID:     "test",
				Format: FormatMsoMdoc,
				Meta: MetaQuery{
					DoctypeValue: "org.iso.18013.5.1.mDL",
				},
			},
			expectError: false,
		},
		{
			name: "mdoc missing doctype",
			query: CredentialQuery{
				ID:     "test",
				Format: FormatMsoMdoc,
				Meta:   MetaQuery{},
			},
			expectError: true,
		},
		{
			name: "mdoc empty doctype",
			query: CredentialQuery{
				ID:     "test",
				Format: FormatMsoMdoc,
				Meta: MetaQuery{
					DoctypeValue: "",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCredentialQuery(tt.query)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateCredentialQueryUnknownFormat(t *testing.T) {
	query := CredentialQuery{
		ID:     "test",
		Format: "unknown_format",
		Meta:   MetaQuery{},
	}

	err := ValidateCredentialQuery(query)
	assert.NoError(t, err, "unknown formats should pass validation")
}

func TestMatchTrustedAuthorities_EmptyConstraints(t *testing.T) {
	result := MatchTrustedAuthorities([]TrustedAuthority{}, [][]byte{{}}, "https://issuer.example.com", nil)
	assert.True(t, result, "empty authorities should always match")
}

func TestMatchTrustedAuthorities_NilMatcher(t *testing.T) {
	authorities := []TrustedAuthority{
		{Type: TrustedAuthorityTypeAKI, Values: []string{"test-aki"}},
	}
	result := MatchTrustedAuthorities(authorities, [][]byte{{}}, "", nil)
	assert.True(t, result, "nil matcher should always match")
}

func TestMatchTrustedAuthorities_AKI(t *testing.T) {
	tests := []struct {
		name     string
		matcher  *mockTrustedAuthorityMatcher
		expected bool
	}{
		{
			name:     "AKI match",
			matcher:  &mockTrustedAuthorityMatcher{shouldMatch: true},
			expected: true,
		},
		{
			name:     "AKI no match",
			matcher:  &mockTrustedAuthorityMatcher{shouldMatch: false},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorities := []TrustedAuthority{
				{Type: TrustedAuthorityTypeAKI, Values: []string{"test-aki-1", "test-aki-2"}},
			}
			result := MatchTrustedAuthorities(authorities, [][]byte{{}}, "", tt.matcher)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchTrustedAuthorities_ETSI(t *testing.T) {
	tests := []struct {
		name     string
		matcher  *mockTrustedAuthorityMatcher
		expected bool
	}{
		{
			name:     "ETSI match",
			matcher:  &mockTrustedAuthorityMatcher{shouldMatch: true},
			expected: true,
		},
		{
			name:     "ETSI no match",
			matcher:  &mockTrustedAuthorityMatcher{shouldMatch: false},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorities := []TrustedAuthority{
				{Type: TrustedAuthorityTypeETSI, Values: []string{"https://lotl.example.com"}},
			}
			result := MatchTrustedAuthorities(authorities, [][]byte{{}}, "", tt.matcher)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchTrustedAuthorities_OpenIDFederation(t *testing.T) {
	tests := []struct {
		name     string
		matcher  *mockTrustedAuthorityMatcher
		expected bool
	}{
		{
			name:     "OpenID Federation match",
			matcher:  &mockTrustedAuthorityMatcher{shouldMatch: true},
			expected: true,
		},
		{
			name:     "OpenID Federation no match",
			matcher:  &mockTrustedAuthorityMatcher{shouldMatch: false},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authorities := []TrustedAuthority{
				{Type: TrustedAuthorityTypeOpenIDFederation, Values: []string{"https://federation.example.com"}},
			}
			result := MatchTrustedAuthorities(authorities, nil, "https://issuer.example.com", tt.matcher)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchTrustedAuthorities_MixedTypes(t *testing.T) {
	matcher := &mockTrustedAuthorityMatcher{shouldMatch: true}
	authorities := []TrustedAuthority{
		{Type: TrustedAuthorityTypeAKI, Values: []string{"test-aki"}},
		{Type: TrustedAuthorityTypeETSI, Values: []string{"https://lotl.example.com"}},
		{Type: TrustedAuthorityTypeOpenIDFederation, Values: []string{"https://federation.example.com"}},
	}

	result := MatchTrustedAuthorities(authorities, [][]byte{{}}, "https://issuer.example.com", matcher)
	assert.True(t, result, "should match when all authority types are satisfied")
}

func TestNewTrustedAuthorityHelpers(t *testing.T) {
	t.Run("NewTrustedAuthorityAKI", func(t *testing.T) {
		ta := NewTrustedAuthorityAKI("aki1", "aki2", "aki3")
		assert.Equal(t, TrustedAuthorityTypeAKI, ta.Type)
		assert.Equal(t, 3, len(ta.Values))
		assert.Contains(t, ta.Values, "aki1")
		assert.Contains(t, ta.Values, "aki2")
		assert.Contains(t, ta.Values, "aki3")
	})

	t.Run("NewTrustedAuthorityETSI", func(t *testing.T) {
		url := "https://lotl.example.com"
		ta := NewTrustedAuthorityETSI(url)
		assert.Equal(t, TrustedAuthorityTypeETSI, ta.Type)
		assert.Equal(t, 1, len(ta.Values))
		assert.Equal(t, url, ta.Values[0])
	})

	t.Run("NewTrustedAuthorityOpenIDFederation", func(t *testing.T) {
		entityID := "https://federation.example.com"
		ta := NewTrustedAuthorityOpenIDFederation(entityID)
		assert.Equal(t, TrustedAuthorityTypeOpenIDFederation, ta.Type)
		assert.Equal(t, 1, len(ta.Values))
		assert.Equal(t, entityID, ta.Values[0])
	})
}

func TestTrustedAuthorityJSONSerialization(t *testing.T) {
	original := TrustedAuthority{
		Type:   TrustedAuthorityTypeAKI,
		Values: []string{"aki1", "aki2"},
	}

	jsonData, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded TrustedAuthority
	err = json.Unmarshal(jsonData, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Type, decoded.Type)
	assert.Equal(t, original.Values, decoded.Values)
}
