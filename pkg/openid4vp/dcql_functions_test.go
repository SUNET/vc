package openid4vp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsW3CVCFormatIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		expected bool
	}{
		{"ldp_vc format", "ldp_vc", true},
		{"jwt_vc_json format", FormatJwtVCJson, true},
		{"SD-JWT format", FormatSDJWTVC, false},
		{"mso_mdoc format", FormatMsoMdoc, false},
		{"unknown format", "unknown", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsW3CVCFormatIdentifier(tt.format)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsSDJWTFormatIdentifier(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		expected bool
	}{
		{"SD-JWT VC format", FormatSDJWTVC, true},
		{"ldp_vc format", "ldp_vc", false},
		{"jwt_vc_json format", FormatJwtVCJson, false},
		{"mso_mdoc format", FormatMsoMdoc, false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSDJWTFormatIdentifier(tt.format)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsMdocFormat(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		expected bool
	}{
		{"mso_mdoc format", FormatMsoMdoc, true},
		{"SD-JWT format", FormatSDJWTVC, false},
		{"ldp_vc format", "ldp_vc", false},
		{"jwt_vc_json format", FormatJwtVCJson, false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsMdocFormat(tt.format)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchTypeValues(t *testing.T) {
	tests := []struct {
		name            string
		credentialTypes []string
		typeValues      [][]string
		expected        bool
	}{
		{
			name:            "no constraints - always match",
			credentialTypes: []string{"Type1", "Type2"},
			typeValues:      [][]string{},
			expected:        true,
		},
		{
			name:            "exact match single alternative",
			credentialTypes: []string{"VerifiableCredential", "PersonalID"},
			typeValues:      [][]string{{"VerifiableCredential", "PersonalID"}},
			expected:        true,
		},
		{
			name:            "match with superset",
			credentialTypes: []string{"VerifiableCredential", "PersonalID", "EuropeanID"},
			typeValues:      [][]string{{"VerifiableCredential", "PersonalID"}},
			expected:        true,
		},
		{
			name:            "no match - missing required type",
			credentialTypes: []string{"VerifiableCredential"},
			typeValues:      [][]string{{"VerifiableCredential", "PersonalID"}},
			expected:        false,
		},
		{
			name:            "match second alternative",
			credentialTypes: []string{"VerifiableCredential", "HealthCard"},
			typeValues: [][]string{
				{"VerifiableCredential", "PersonalID"},
				{"VerifiableCredential", "HealthCard"},
			},
			expected: true,
		},
		{
			name:            "no match any alternative",
			credentialTypes: []string{"VerifiableCredential", "DrivingLicense"},
			typeValues: [][]string{
				{"VerifiableCredential", "PersonalID"},
				{"VerifiableCredential", "HealthCard"},
			},
			expected: false,
		},
		{
			name:            "empty credential types",
			credentialTypes: []string{},
			typeValues:      [][]string{{"VerifiableCredential"}},
			expected:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchTypeValues(tt.credentialTypes, tt.typeValues)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContainsAll(t *testing.T) {
	tests := []struct {
		name            string
		credentialTypes []string
		requiredTypes   []string
		expected        bool
	}{
		{
			name:            "all required types present",
			credentialTypes: []string{"A", "B", "C"},
			requiredTypes:   []string{"A", "B"},
			expected:        true,
		},
		{
			name:            "missing one required type",
			credentialTypes: []string{"A", "B"},
			requiredTypes:   []string{"A", "B", "C"},
			expected:        false,
		},
		{
			name:            "empty required types",
			credentialTypes: []string{"A", "B"},
			requiredTypes:   []string{},
			expected:        true,
		},
		{
			name:            "empty credential types with required",
			credentialTypes: []string{},
			requiredTypes:   []string{"A"},
			expected:        false,
		},
		{
			name:            "exact match",
			credentialTypes: []string{"A", "B", "C"},
			requiredTypes:   []string{"A", "B", "C"},
			expected:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsAll(tt.credentialTypes, tt.requiredTypes)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchCryptosuite(t *testing.T) {
	tests := []struct {
		name              string
		cryptosuite       string
		cryptosuiteValues []string
		expected          bool
	}{
		{
			name:              "no constraints - always match",
			cryptosuite:       "eddsa-2022",
			cryptosuiteValues: []string{},
			expected:          true,
		},
		{
			name:              "exact match",
			cryptosuite:       "eddsa-2022",
			cryptosuiteValues: []string{"eddsa-2022"},
			expected:          true,
		},
		{
			name:              "match in list",
			cryptosuite:       "ecdsa-2019",
			cryptosuiteValues: []string{"eddsa-2022", "ecdsa-2019", "rsa-2018"},
			expected:          true,
		},
		{
			name:              "no match",
			cryptosuite:       "unknown-suite",
			cryptosuiteValues: []string{"eddsa-2022", "ecdsa-2019"},
			expected:          false,
		},
		{
			name:              "empty cryptosuite string",
			cryptosuite:       "",
			cryptosuiteValues: []string{"eddsa-2022"},
			expected:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchCryptosuite(tt.cryptosuite, tt.cryptosuiteValues)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchProofType(t *testing.T) {
	tests := []struct {
		name            string
		proofType       string
		proofTypeValues []string
		expected        bool
	}{
		{
			name:            "no constraints - always match",
			proofType:       "Ed25519Signature2020",
			proofTypeValues: []string{},
			expected:        true,
		},
		{
			name:            "exact match",
			proofType:       "Ed25519Signature2020",
			proofTypeValues: []string{"Ed25519Signature2020"},
			expected:        true,
		},
		{
			name:            "match in list",
			proofType:       "EcdsaSecp256k1Signature2019",
			proofTypeValues: []string{"Ed25519Signature2020", "EcdsaSecp256k1Signature2019", "RsaSignature2018"},
			expected:        true,
		},
		{
			name:            "no match",
			proofType:       "UnknownProofType",
			proofTypeValues: []string{"Ed25519Signature2020", "EcdsaSecp256k1Signature2019"},
			expected:        false,
		},
		{
			name:            "empty proof type",
			proofType:       "",
			proofTypeValues: []string{"Ed25519Signature2020"},
			expected:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchProofType(tt.proofType, tt.proofTypeValues)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMatchTrustedAuthorities(t *testing.T) {
	tests := []struct {
		name                string
		authorities         []TrustedAuthority
		credentialCertChain [][]byte
		issuer              string
		setupMatcher        func() TrustedAuthorityMatcher
		expected            bool
	}{
		{
			name:                "no authorities - always match",
			authorities:         []TrustedAuthority{},
			credentialCertChain: nil,
			issuer:              "",
			setupMatcher: func() TrustedAuthorityMatcher {
				return &mockTrustedAuthorityMatcher{shouldMatch: true}
			},
			expected: true,
		},
		{
			name: "single AKI authority match",
			authorities: []TrustedAuthority{
				{Type: TrustedAuthorityTypeAKI, Values: []string{"test-aki"}},
			},
			credentialCertChain: [][]byte{{}},
			issuer:              "",
			setupMatcher: func() TrustedAuthorityMatcher {
				return &mockTrustedAuthorityMatcher{shouldMatch: true}
			},
			expected: true,
		},
		{
			name: "single authority no match",
			authorities: []TrustedAuthority{
				{Type: TrustedAuthorityTypeAKI, Values: []string{"test-aki"}},
			},
			credentialCertChain: [][]byte{{}},
			issuer:              "",
			setupMatcher: func() TrustedAuthorityMatcher {
				return &mockTrustedAuthorityMatcher{shouldMatch: false}
			},
			expected: false,
		},
		{
			name: "ETSI authority match",
			authorities: []TrustedAuthority{
				{Type: TrustedAuthorityTypeETSI, Values: []string{"https://lotl.example.com"}},
			},
			credentialCertChain: [][]byte{{}},
			issuer:              "",
			setupMatcher: func() TrustedAuthorityMatcher {
				return &mockTrustedAuthorityMatcher{shouldMatch: true}
			},
			expected: true,
		},
		{
			name: "OpenID Federation authority match",
			authorities: []TrustedAuthority{
				{Type: TrustedAuthorityTypeOpenIDFederation, Values: []string{"https://federation.example.com"}},
			},
			credentialCertChain: nil,
			issuer:              "https://issuer.example.com",
			setupMatcher: func() TrustedAuthorityMatcher {
				return &mockTrustedAuthorityMatcher{shouldMatch: true}
			},
			expected: true,
		},
		{
			name: "nil matcher - always match",
			authorities: []TrustedAuthority{
				{Type: TrustedAuthorityTypeAKI, Values: []string{"test-aki"}},
			},
			credentialCertChain: nil,
			issuer:              "",
			setupMatcher:        func() TrustedAuthorityMatcher { return nil },
			expected:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := tt.setupMatcher()
			result := MatchTrustedAuthorities(tt.authorities, tt.credentialCertChain, tt.issuer, matcher)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Mock implementation for testing
type mockTrustedAuthorityMatcher struct {
	shouldMatch bool
}

func (m *mockTrustedAuthorityMatcher) MatchAKI(credentialCertChain [][]byte, aki string) bool {
	return m.shouldMatch
}

func (m *mockTrustedAuthorityMatcher) MatchETSI(credentialCertChain [][]byte, tlURL string) bool {
	return m.shouldMatch
}

func (m *mockTrustedAuthorityMatcher) MatchOpenIDFederation(issuer string, trustAnchorEntityID string) bool {
	return m.shouldMatch
}

func TestNewTrustedAuthorityAKI(t *testing.T) {
	aki1 := "base64encodedaki1"
	aki2 := "base64encodedaki2"
	ta := NewTrustedAuthorityAKI(aki1, aki2)

	assert.Equal(t, TrustedAuthorityTypeAKI, ta.Type)
	assert.Equal(t, 2, len(ta.Values))
	assert.Contains(t, ta.Values, aki1)
	assert.Contains(t, ta.Values, aki2)
}

func TestNewTrustedAuthorityETSI(t *testing.T) {
	url := "https://lotl.example.com"
	ta := NewTrustedAuthorityETSI(url)

	assert.Equal(t, TrustedAuthorityTypeETSI, ta.Type)
	assert.Equal(t, 1, len(ta.Values))
	assert.Equal(t, url, ta.Values[0])
}

func TestNewTrustedAuthorityOpenIDFederation(t *testing.T) {
	entityID := "https://federation.example.com"
	ta := NewTrustedAuthorityOpenIDFederation(entityID)

	assert.Equal(t, TrustedAuthorityTypeOpenIDFederation, ta.Type)
	assert.Equal(t, 1, len(ta.Values))
	assert.Equal(t, entityID, ta.Values[0])
}

func TestValidateCredentialQuery(t *testing.T) {
	tests := []struct {
		name        string
		query       CredentialQuery
		expectError bool
	}{
		{
			name: "valid SD-JWT query with VCT",
			query: CredentialQuery{
				ID:     "test_credential",
				Format: FormatSDJWTVC,
				Meta: MetaQuery{
					VCTValues: []string{"https://example.com/credential"},
				},
			},
			expectError: false,
		},
		{
			name: "valid ldp_vc query with type values",
			query: CredentialQuery{
				ID:     "test_credential",
				Format: "ldp_vc",
				Meta: MetaQuery{
					TypeValues: [][]string{{"VerifiableCredential", "PersonalID"}},
				},
			},
			expectError: false,
		},
		{
			name: "valid mso_mdoc query with doctype",
			query: CredentialQuery{
				ID:     "test_credential",
				Format: FormatMsoMdoc,
				Meta: MetaQuery{
					DoctypeValue: "org.iso.18013.5.1.mDL",
				},
			},
			expectError: false,
		},
		{
			name: "SD-JWT missing VCT values",
			query: CredentialQuery{
				ID:     "test_credential",
				Format: FormatSDJWTVC,
			},
			expectError: true,
		},
		{
			name: "ldp_vc missing type values",
			query: CredentialQuery{
				ID:     "test_credential",
				Format: "ldp_vc",
			},
			expectError: true,
		},
		{
			name: "mso_mdoc missing doctype",
			query: CredentialQuery{
				ID:     "test_credential",
				Format: FormatMsoMdoc,
			},
			expectError: true,
		},
		{
			name: "unknown format passes validation",
			query: CredentialQuery{
				ID:     "test_credential",
				Format: "unknown_format",
			},
			expectError: false,
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

func TestDCQLValidationError(t *testing.T) {
	err := &DCQLValidationError{
		Field:   "test_field",
		Message: "test error message",
	}

	errorString := err.Error()
	assert.Contains(t, errorString, "test_field")
	assert.Contains(t, errorString, "test error message")
	assert.Contains(t, errorString, "DCQL validation error")
}

func TestNewVC20CredentialQuery(t *testing.T) {
	id := "my_credential"
	typeValues := [][]string{{"VerifiableCredential", "PersonalID"}}
	claims := []ClaimQuery{{Path: StringPath("given_name")}}

	query := NewVC20CredentialQuery(id, typeValues, claims)

	assert.NotNil(t, query)
	assert.Equal(t, id, query.ID)
	assert.Equal(t, "ldp_vc", query.Format)
	assert.NotNil(t, query.RequireCryptographicHolderBinding)
	assert.True(t, query.RequiresCryptographicHolderBinding())
	assert.Equal(t, typeValues, query.Meta.TypeValues)
	assert.Equal(t, claims, query.Claims)
}

func TestNewVC20VPFormatsSupported(t *testing.T) {
	cryptosuites := []string{"eddsa-2022", "ecdsa-2019"}
	formats := NewVC20VPFormatsSupported(cryptosuites)

	assert.NotNil(t, formats)
	assert.NotNil(t, formats.LDPVC)
	assert.Equal(t, []string{"DataIntegrityProof"}, formats.LDPVC.ProofTypeValues)
	assert.Equal(t, cryptosuites, formats.LDPVC.CryptosuiteValues)
}
