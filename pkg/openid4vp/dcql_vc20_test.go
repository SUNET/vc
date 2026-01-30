//go:build vc20

package openid4vp

import (
	"encoding/json"
	"testing"
)

func TestIsW3CVCFormatIdentifier(t *testing.T) {
	tests := []struct {
		format   string
		expected bool
	}{
		{"ldp_vc", true},
		{FormatJwtVCJson, true},
		{FormatSDJWTVC, false},
		{FormatMsoMdoc, false},
		{"unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			result := IsW3CVCFormatIdentifier(tt.format)
			if result != tt.expected {
				t.Errorf("IsW3CVCFormatIdentifier(%q) = %v, want %v", tt.format, result, tt.expected)
			}
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
			name:            "empty type_values matches any",
			credentialTypes: []string{"VerifiableCredential", "IDCredential"},
			typeValues:      nil,
			expected:        true,
		},
		{
			name:            "single alternative - exact match",
			credentialTypes: []string{"VerifiableCredential", "IDCredential"},
			typeValues:      [][]string{{"VerifiableCredential", "IDCredential"}},
			expected:        true,
		},
		{
			name:            "single alternative - superset matches",
			credentialTypes: []string{"VerifiableCredential", "IDCredential", "ExtraType"},
			typeValues:      [][]string{{"VerifiableCredential", "IDCredential"}},
			expected:        true,
		},
		{
			name:            "single alternative - missing type",
			credentialTypes: []string{"VerifiableCredential"},
			typeValues:      [][]string{{"VerifiableCredential", "IDCredential"}},
			expected:        false,
		},
		{
			name:            "multiple alternatives - matches second",
			credentialTypes: []string{"VerifiableCredential", "UniversityDegreeCredential"},
			typeValues: [][]string{
				{"VerifiableCredential", "IDCredential"},
				{"VerifiableCredential", "UniversityDegreeCredential"},
			},
			expected: true,
		},
		{
			name:            "multiple alternatives - matches none",
			credentialTypes: []string{"VerifiableCredential", "OtherCredential"},
			typeValues: [][]string{
				{"VerifiableCredential", "IDCredential"},
				{"VerifiableCredential", "UniversityDegreeCredential"},
			},
			expected: false,
		},
		{
			name:            "fully expanded IRIs",
			credentialTypes: []string{"https://www.w3.org/2018/credentials#VerifiableCredential", "https://example.org/IDCredential"},
			typeValues:      [][]string{{"https://www.w3.org/2018/credentials#VerifiableCredential", "https://example.org/IDCredential"}},
			expected:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchTypeValues(tt.credentialTypes, tt.typeValues)
			if result != tt.expected {
				t.Errorf("MatchTypeValues() = %v, want %v", result, tt.expected)
			}
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
			name:              "empty values matches any",
			cryptosuite:       "ecdsa-rdfc-2019",
			cryptosuiteValues: nil,
			expected:          true,
		},
		{
			name:              "exact match",
			cryptosuite:       "ecdsa-rdfc-2019",
			cryptosuiteValues: []string{"ecdsa-rdfc-2019", "eddsa-rdfc-2022"},
			expected:          true,
		},
		{
			name:              "no match",
			cryptosuite:       "bbs-2023",
			cryptosuiteValues: []string{"ecdsa-rdfc-2019", "eddsa-rdfc-2022"},
			expected:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchCryptosuite(tt.cryptosuite, tt.cryptosuiteValues)
			if result != tt.expected {
				t.Errorf("MatchCryptosuite() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestValidateCredentialQuery(t *testing.T) {
	tests := []struct {
		name    string
		query   CredentialQuery
		wantErr bool
	}{
		{
			name: "valid ldp_vc query",
			query: CredentialQuery{
				ID:     "test",
				Format: "ldp_vc",
				Meta: MetaQuery{
					TypeValues: [][]string{{"VerifiableCredential", "IDCredential"}},
				},
			},
			wantErr: false,
		},
		{
			name: "ldp_vc missing type_values",
			query: CredentialQuery{
				ID:     "test",
				Format: "ldp_vc",
				Meta:   MetaQuery{},
			},
			wantErr: true,
		},
		{
			name: "valid dc+sd-jwt query",
			query: CredentialQuery{
				ID:     "test",
				Format: FormatSDJWTVC,
				Meta: MetaQuery{
					VCTValues: []string{"https://credentials.example.com/identity_credential"},
				},
			},
			wantErr: false,
		},
		{
			name: "dc+sd-jwt missing vct_values",
			query: CredentialQuery{
				ID:     "test",
				Format: FormatSDJWTVC,
				Meta:   MetaQuery{},
			},
			wantErr: true,
		},
		{
			name: "valid mso_mdoc query",
			query: CredentialQuery{
				ID:     "test",
				Format: FormatMsoMdoc,
				Meta: MetaQuery{
					DoctypeValue: "org.iso.18013.5.1.mDL",
				},
			},
			wantErr: false,
		},
		{
			name: "mso_mdoc missing doctype_value",
			query: CredentialQuery{
				ID:     "test",
				Format: FormatMsoMdoc,
				Meta:   MetaQuery{},
			},
			wantErr: true,
		},
		{
			name: "unknown format - no validation",
			query: CredentialQuery{
				ID:     "test",
				Format: "unknown",
				Meta:   MetaQuery{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCredentialQuery(tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCredentialQuery() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestNewVC20CredentialQuery(t *testing.T) {
	query := NewVC20CredentialQuery(
		"pid_credential",
		[][]string{{"VerifiableCredential", "IDCredential"}},
		[]ClaimQuery{
			{Path: []string{"credentialSubject", "given_name"}},
			{Path: []string{"credentialSubject", "family_name"}},
		},
	)

	if query.ID != "pid_credential" {
		t.Errorf("ID = %q, want %q", query.ID, "pid_credential")
	}
	if query.Format != "ldp_vc" {
		t.Errorf("Format = %q, want %q", query.Format, "ldp_vc")
	}
	if len(query.Meta.TypeValues) != 1 {
		t.Errorf("TypeValues length = %d, want 1", len(query.Meta.TypeValues))
	}
	if len(query.Claims) != 2 {
		t.Errorf("Claims length = %d, want 2", len(query.Claims))
	}
	if !query.RequireCryptographicHolderBinding {
		t.Error("RequireCryptographicHolderBinding should be true by default")
	}
}

func TestNewVC20VPFormatsSupported(t *testing.T) {
	cryptosuites := []string{"ecdsa-rdfc-2019", "ecdsa-sd-2023", "eddsa-rdfc-2022"}
	formats := NewVC20VPFormatsSupported(cryptosuites)

	if formats.LDPVC == nil {
		t.Fatal("LDPVC should not be nil")
	}
	if len(formats.LDPVC.ProofTypeValues) != 1 || formats.LDPVC.ProofTypeValues[0] != "DataIntegrityProof" {
		t.Errorf("ProofTypeValues = %v, want [DataIntegrityProof]", formats.LDPVC.ProofTypeValues)
	}
	if len(formats.LDPVC.CryptosuiteValues) != 3 {
		t.Errorf("CryptosuiteValues length = %d, want 3", len(formats.LDPVC.CryptosuiteValues))
	}
}

func TestMetaQueryJSONSerialization(t *testing.T) {
	// Test SD-JWT VC format
	sdJwtMeta := MetaQuery{
		VCTValues: []string{"https://credentials.example.com/identity_credential"},
	}
	sdJwtJSON, err := json.Marshal(sdJwtMeta)
	if err != nil {
		t.Fatalf("Failed to marshal SD-JWT meta: %v", err)
	}
	t.Logf("SD-JWT meta JSON: %s", sdJwtJSON)

	var parsedSDJwt MetaQuery
	if err := json.Unmarshal(sdJwtJSON, &parsedSDJwt); err != nil {
		t.Fatalf("Failed to unmarshal SD-JWT meta: %v", err)
	}
	if len(parsedSDJwt.VCTValues) != 1 {
		t.Errorf("VCTValues length = %d, want 1", len(parsedSDJwt.VCTValues))
	}

	// Test W3C VC format
	w3cMeta := MetaQuery{
		TypeValues: [][]string{
			{"https://www.w3.org/2018/credentials#VerifiableCredential", "https://example.org/IDCredential"},
		},
	}
	w3cJSON, err := json.Marshal(w3cMeta)
	if err != nil {
		t.Fatalf("Failed to marshal W3C meta: %v", err)
	}
	t.Logf("W3C meta JSON: %s", w3cJSON)

	var parsedW3C MetaQuery
	if err := json.Unmarshal(w3cJSON, &parsedW3C); err != nil {
		t.Fatalf("Failed to unmarshal W3C meta: %v", err)
	}
	if len(parsedW3C.TypeValues) != 1 {
		t.Errorf("TypeValues length = %d, want 1", len(parsedW3C.TypeValues))
	}
	if len(parsedW3C.TypeValues[0]) != 2 {
		t.Errorf("TypeValues[0] length = %d, want 2", len(parsedW3C.TypeValues[0]))
	}
}

func TestVPFormatsSupportedJSONSerialization(t *testing.T) {
	formats := VPFormatsSupported{
		LDPVC: &LDPVCFormat{
			ProofTypeValues:   []string{"DataIntegrityProof"},
			CryptosuiteValues: []string{"ecdsa-rdfc-2019", "ecdsa-sd-2023"},
		},
		SDJWT: &SDJWTVCFormat{
			SDJWTAlgValues: []string{"ES256", "ES384"},
			KBJWTAlgValues: []string{"ES256"},
		},
	}

	jsonBytes, err := json.Marshal(formats)
	if err != nil {
		t.Fatalf("Failed to marshal VPFormatsSupported: %v", err)
	}
	t.Logf("VPFormatsSupported JSON: %s", jsonBytes)

	var parsed VPFormatsSupported
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal VPFormatsSupported: %v", err)
	}

	if parsed.LDPVC == nil {
		t.Fatal("LDPVC should not be nil after unmarshal")
	}
	if len(parsed.LDPVC.CryptosuiteValues) != 2 {
		t.Errorf("CryptosuiteValues length = %d, want 2", len(parsed.LDPVC.CryptosuiteValues))
	}
	if parsed.SDJWT == nil {
		t.Fatal("SDJWT should not be nil after unmarshal")
	}
	if len(parsed.SDJWT.SDJWTAlgValues) != 2 {
		t.Errorf("SDJWTAlgValues length = %d, want 2", len(parsed.SDJWT.SDJWTAlgValues))
	}
}

func TestDCQLQueryExample(t *testing.T) {
	// Example from OpenID4VP spec - W3C VC format
	query := DCQL{
		Credentials: []CredentialQuery{
			{
				ID:     "example_ldp_vc",
				Format: "ldp_vc",
				Meta: MetaQuery{
					TypeValues: [][]string{{"IDCredential"}},
				},
				Claims: []ClaimQuery{
					{Path: []string{"credentialSubject", "family_name"}},
					{Path: []string{"credentialSubject", "given_name"}},
					{Path: []string{"credentialSubject", "birthdate"}},
				},
			},
		},
	}

	jsonBytes, err := json.MarshalIndent(query, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal DCQL query: %v", err)
	}
	t.Logf("DCQL Query JSON:\n%s", jsonBytes)

	// Validate the query
	for _, cq := range query.Credentials {
		if err := ValidateCredentialQuery(cq); err != nil {
			t.Errorf("ValidateCredentialQuery failed: %v", err)
		}
	}
}

// TestIsSDJWTFormatIdentifier tests the IsSDJWTFormatIdentifier function.
func TestIsSDJWTFormatIdentifier(t *testing.T) {
	tests := []struct {
		format   string
		expected bool
	}{
		{FormatSDJWTVC, true},
		{"dc+sd-jwt", true},
		{"ldp_vc", false},
		{FormatJwtVCJson, false},
		{FormatMsoMdoc, false},
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			result := IsSDJWTFormatIdentifier(tt.format)
			if result != tt.expected {
				t.Errorf("IsSDJWTFormatIdentifier(%q) = %v, want %v", tt.format, result, tt.expected)
			}
		})
	}
}

// TestIsMdocFormat tests the IsMdocFormat function.
func TestIsMdocFormat(t *testing.T) {
	tests := []struct {
		format   string
		expected bool
	}{
		{FormatMsoMdoc, true},
		{"mso_mdoc", true},
		{"ldp_vc", false},
		{FormatJwtVCJson, false},
		{FormatSDJWTVC, false},
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			result := IsMdocFormat(tt.format)
			if result != tt.expected {
				t.Errorf("IsMdocFormat(%q) = %v, want %v", tt.format, result, tt.expected)
			}
		})
	}
}

// TestMatchProofType tests the MatchProofType function.
func TestMatchProofType(t *testing.T) {
	tests := []struct {
		name            string
		proofType       string
		proofTypeValues []string
		expected        bool
	}{
		{
			name:            "empty constraint matches any",
			proofType:       "DataIntegrityProof",
			proofTypeValues: nil,
			expected:        true,
		},
		{
			name:            "exact match",
			proofType:       "DataIntegrityProof",
			proofTypeValues: []string{"DataIntegrityProof"},
			expected:        true,
		},
		{
			name:            "multiple allowed - matches first",
			proofType:       "DataIntegrityProof",
			proofTypeValues: []string{"DataIntegrityProof", "Ed25519Signature2020"},
			expected:        true,
		},
		{
			name:            "multiple allowed - matches second",
			proofType:       "Ed25519Signature2020",
			proofTypeValues: []string{"DataIntegrityProof", "Ed25519Signature2020"},
			expected:        true,
		},
		{
			name:            "no match",
			proofType:       "JsonWebSignature2020",
			proofTypeValues: []string{"DataIntegrityProof", "Ed25519Signature2020"},
			expected:        false,
		},
		{
			name:            "case sensitive",
			proofType:       "dataintegrityproof",
			proofTypeValues: []string{"DataIntegrityProof"},
			expected:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchProofType(tt.proofType, tt.proofTypeValues)
			if result != tt.expected {
				t.Errorf("MatchProofType(%q, %v) = %v, want %v", tt.proofType, tt.proofTypeValues, result, tt.expected)
			}
		})
	}
}

// TestDCQLValidationError tests the DCQLValidationError type.
func TestDCQLValidationError(t *testing.T) {
	tests := []struct {
		name     string
		err      *DCQLValidationError
		expected string
	}{
		{
			name: "type_values error",
			err: &DCQLValidationError{
				Field:   "meta.type_values",
				Message: "type_values is required for W3C VC format",
			},
			expected: "DCQL validation error on meta.type_values: type_values is required for W3C VC format",
		},
		{
			name: "vct_values error",
			err: &DCQLValidationError{
				Field:   "meta.vct_values",
				Message: "vct_values is required for SD-JWT VC format",
			},
			expected: "DCQL validation error on meta.vct_values: vct_values is required for SD-JWT VC format",
		},
		{
			name: "doctype_value error",
			err: &DCQLValidationError{
				Field:   "meta.doctype_value",
				Message: "doctype_value is required for ISO mdoc format",
			},
			expected: "DCQL validation error on meta.doctype_value: doctype_value is required for ISO mdoc format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.err.Error()
			if result != tt.expected {
				t.Errorf("Error() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestValidateCredentialQuerySDJWT tests validation for SD-JWT format queries.
func TestValidateCredentialQuerySDJWT(t *testing.T) {
	// Valid SD-JWT query
	validQuery := CredentialQuery{
		ID:     "test_sdjwt",
		Format: FormatSDJWTVC,
		Meta: MetaQuery{
			VCTValues: []string{"https://example.org/IDCredential"},
		},
	}
	if err := ValidateCredentialQuery(validQuery); err != nil {
		t.Errorf("Expected valid SD-JWT query to pass, got: %v", err)
	}

	// Invalid SD-JWT query - missing vct_values
	invalidQuery := CredentialQuery{
		ID:     "test_sdjwt_invalid",
		Format: FormatSDJWTVC,
		Meta:   MetaQuery{},
	}
	err := ValidateCredentialQuery(invalidQuery)
	if err == nil {
		t.Error("Expected error for SD-JWT query without vct_values")
	}
	if dcqlErr, ok := err.(*DCQLValidationError); ok {
		if dcqlErr.Field != "meta.vct_values" {
			t.Errorf("Expected field 'meta.vct_values', got %q", dcqlErr.Field)
		}
	} else {
		t.Error("Expected DCQLValidationError type")
	}
}

// TestValidateCredentialQueryMdoc tests validation for ISO mdoc format queries.
func TestValidateCredentialQueryMdoc(t *testing.T) {
	// Valid mdoc query
	validQuery := CredentialQuery{
		ID:     "test_mdoc",
		Format: FormatMsoMdoc,
		Meta: MetaQuery{
			DoctypeValue: "org.iso.18013.5.1.mDL",
		},
	}
	if err := ValidateCredentialQuery(validQuery); err != nil {
		t.Errorf("Expected valid mdoc query to pass, got: %v", err)
	}

	// Invalid mdoc query - missing doctype_value
	invalidQuery := CredentialQuery{
		ID:     "test_mdoc_invalid",
		Format: FormatMsoMdoc,
		Meta:   MetaQuery{},
	}
	err := ValidateCredentialQuery(invalidQuery)
	if err == nil {
		t.Error("Expected error for mdoc query without doctype_value")
	}
	if dcqlErr, ok := err.(*DCQLValidationError); ok {
		if dcqlErr.Field != "meta.doctype_value" {
			t.Errorf("Expected field 'meta.doctype_value', got %q", dcqlErr.Field)
		}
	} else {
		t.Error("Expected DCQLValidationError type")
	}
}

// TestValidateCredentialQueryUnknownFormat tests that unknown formats pass validation.
func TestValidateCredentialQueryUnknownFormat(t *testing.T) {
	query := CredentialQuery{
		ID:     "test_unknown",
		Format: "unknown_format",
		Meta:   MetaQuery{},
	}
	if err := ValidateCredentialQuery(query); err != nil {
		t.Errorf("Expected unknown format to pass validation (no constraints), got: %v", err)
	}
}

// mockTrustedAuthorityMatcher implements TrustedAuthorityMatcher for testing.
type mockTrustedAuthorityMatcher struct {
	akiMatches      map[string]bool
	etsiMatches     map[string]bool
	federationMatch map[string]bool
}

func (m *mockTrustedAuthorityMatcher) MatchAKI(credentialCertChain [][]byte, aki string) bool {
	if m.akiMatches == nil {
		return false
	}
	return m.akiMatches[aki]
}

func (m *mockTrustedAuthorityMatcher) MatchETSI(credentialCertChain [][]byte, tlURL string) bool {
	if m.etsiMatches == nil {
		return false
	}
	return m.etsiMatches[tlURL]
}

func (m *mockTrustedAuthorityMatcher) MatchOpenIDFederation(issuer string, trustAnchorEntityID string) bool {
	if m.federationMatch == nil {
		return false
	}
	// Match based on issuer + trust anchor combination
	return m.federationMatch[issuer+":"+trustAnchorEntityID]
}

func TestMatchTrustedAuthorities_EmptyConstraints(t *testing.T) {
	// Empty trusted_authorities should match any credential
	result := MatchTrustedAuthorities(nil, nil, "did:example:issuer", nil)
	if !result {
		t.Error("Expected empty trusted_authorities to match")
	}

	result = MatchTrustedAuthorities([]TrustedAuthority{}, nil, "did:example:issuer", nil)
	if !result {
		t.Error("Expected empty array trusted_authorities to match")
	}
}

func TestMatchTrustedAuthorities_NilMatcher(t *testing.T) {
	// With constraints but nil matcher, should pass (trust decision elsewhere)
	tas := []TrustedAuthority{
		NewTrustedAuthorityAKI("abc123"),
	}
	result := MatchTrustedAuthorities(tas, nil, "did:example:issuer", nil)
	if !result {
		t.Error("Expected nil matcher to return true (no validation)")
	}
}

func TestMatchTrustedAuthorities_AKI(t *testing.T) {
	matcher := &mockTrustedAuthorityMatcher{
		akiMatches: map[string]bool{
			"s9tIpPmhxdiuNkHMEWNpYim8S8Y": true,
		},
	}

	tests := []struct {
		name     string
		tas      []TrustedAuthority
		expected bool
	}{
		{
			name:     "matching AKI",
			tas:      []TrustedAuthority{NewTrustedAuthorityAKI("s9tIpPmhxdiuNkHMEWNpYim8S8Y")},
			expected: true,
		},
		{
			name:     "non-matching AKI",
			tas:      []TrustedAuthority{NewTrustedAuthorityAKI("nonexistent")},
			expected: false,
		},
		{
			name: "multiple AKI values - one matches",
			tas: []TrustedAuthority{
				NewTrustedAuthorityAKI("nonexistent", "s9tIpPmhxdiuNkHMEWNpYim8S8Y"),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchTrustedAuthorities(tt.tas, nil, "", matcher)
			if result != tt.expected {
				t.Errorf("MatchTrustedAuthorities() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMatchTrustedAuthorities_ETSI(t *testing.T) {
	matcher := &mockTrustedAuthorityMatcher{
		etsiMatches: map[string]bool{
			"https://lotl.example.com": true,
		},
	}

	tests := []struct {
		name     string
		tas      []TrustedAuthority
		expected bool
	}{
		{
			name:     "matching ETSI TL",
			tas:      []TrustedAuthority{NewTrustedAuthorityETSI("https://lotl.example.com")},
			expected: true,
		},
		{
			name:     "non-matching ETSI TL",
			tas:      []TrustedAuthority{NewTrustedAuthorityETSI("https://other.example.com")},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchTrustedAuthorities(tt.tas, nil, "", matcher)
			if result != tt.expected {
				t.Errorf("MatchTrustedAuthorities() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMatchTrustedAuthorities_OpenIDFederation(t *testing.T) {
	matcher := &mockTrustedAuthorityMatcher{
		federationMatch: map[string]bool{
			"did:web:issuer.example.com:https://trustanchor.example.com": true,
		},
	}

	tests := []struct {
		name     string
		tas      []TrustedAuthority
		issuer   string
		expected bool
	}{
		{
			name:     "matching federation",
			tas:      []TrustedAuthority{NewTrustedAuthorityOpenIDFederation("https://trustanchor.example.com")},
			issuer:   "did:web:issuer.example.com",
			expected: true,
		},
		{
			name:     "non-matching federation",
			tas:      []TrustedAuthority{NewTrustedAuthorityOpenIDFederation("https://other.example.com")},
			issuer:   "did:web:issuer.example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := MatchTrustedAuthorities(tt.tas, nil, tt.issuer, matcher)
			if result != tt.expected {
				t.Errorf("MatchTrustedAuthorities() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMatchTrustedAuthorities_MixedTypes(t *testing.T) {
	// Test that matching ANY authority type succeeds
	matcher := &mockTrustedAuthorityMatcher{
		akiMatches: map[string]bool{
			"aki123": false,
		},
		etsiMatches: map[string]bool{
			"https://lotl.example.com": true, // This one matches
		},
	}

	tas := []TrustedAuthority{
		NewTrustedAuthorityAKI("aki123"),
		NewTrustedAuthorityETSI("https://lotl.example.com"),
	}

	result := MatchTrustedAuthorities(tas, nil, "", matcher)
	if !result {
		t.Error("Expected match when at least one trusted authority matches")
	}
}

func TestNewTrustedAuthorityHelpers(t *testing.T) {
	// Test AKI helper
	aki := NewTrustedAuthorityAKI("value1", "value2")
	if aki.Type != TrustedAuthorityTypeAKI {
		t.Errorf("Expected type %q, got %q", TrustedAuthorityTypeAKI, aki.Type)
	}
	if len(aki.Values) != 2 {
		t.Errorf("Expected 2 values, got %d", len(aki.Values))
	}

	// Test ETSI helper
	etsi := NewTrustedAuthorityETSI("https://example.com")
	if etsi.Type != TrustedAuthorityTypeETSI {
		t.Errorf("Expected type %q, got %q", TrustedAuthorityTypeETSI, etsi.Type)
	}

	// Test OpenID Federation helper
	fed := NewTrustedAuthorityOpenIDFederation("https://trust.example.com")
	if fed.Type != TrustedAuthorityTypeOpenIDFederation {
		t.Errorf("Expected type %q, got %q", TrustedAuthorityTypeOpenIDFederation, fed.Type)
	}
}

func TestTrustedAuthorityJSONSerialization(t *testing.T) {
	ta := NewTrustedAuthorityAKI("s9tIpPmhxdiuNkHMEWNpYim8S8Y")

	// Serialize
	data, err := json.Marshal(ta)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Verify JSON structure matches OpenID4VP spec
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if parsed["type"] != "aki" {
		t.Errorf("Expected type 'aki', got %v", parsed["type"])
	}

	values, ok := parsed["values"].([]any)
	if !ok || len(values) != 1 {
		t.Errorf("Expected values array with 1 element")
	}
}
