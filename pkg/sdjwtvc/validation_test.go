package sdjwtvc

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateDocument_Success(t *testing.T) {
	// Setup VCTM
	givenName := "given_name"
	familyName := "family_name"
	birthdate := "birthdate"

	vctm := &VCTM{
		VCT: "test:credential:1",
		Claims: []Claim{
			{
				Path:      []*string{&givenName},
				SD:        "always",
				Mandatory: true,
			},
			{
				Path:      []*string{&familyName},
				SD:        "always",
				Mandatory: true,
			},
			{
				Path:      []*string{&birthdate},
				SD:        "allowed",
				Mandatory: false,
			},
		},
	}

	// Valid document with all mandatory claims
	doc := map[string]any{
		"given_name":  "John",
		"family_name": "Doe",
		"birthdate":   "1990-01-01",
	}

	docData, err := json.Marshal(doc)
	require.NoError(t, err)

	// Validate
	err = ValidateDocument(docData, vctm)
	assert.NoError(t, err)
}

func TestValidateDocument_MissingMandatoryClaim(t *testing.T) {
	givenName := "given_name"
	familyName := "family_name"

	vctm := &VCTM{
		VCT: "test:credential:1",
		Claims: []Claim{
			{
				Path:      []*string{&givenName},
				SD:        "always",
				Mandatory: true,
			},
			{
				Path:      []*string{&familyName},
				SD:        "always",
				Mandatory: true,
			},
		},
	}

	// Document missing mandatory family_name
	doc := map[string]any{
		"given_name": "John",
	}

	docData, err := json.Marshal(doc)
	require.NoError(t, err)

	// Validate
	err = ValidateDocument(docData, vctm)
	assert.Error(t, err)

	validationErr, ok := err.(*ValidationErrors)
	require.True(t, ok, "expected ValidationErrors type")
	assert.Len(t, validationErr.Errors, 1)
	assert.Equal(t, "$.family_name", validationErr.Errors[0].Field)
	assert.Contains(t, validationErr.Errors[0].Message, "mandatory")
}

func TestValidateDocument_MultipleMissingClaims(t *testing.T) {
	givenName := "given_name"
	familyName := "family_name"
	birthdate := "birthdate"

	vctm := &VCTM{
		VCT: "test:credential:1",
		Claims: []Claim{
			{
				Path:      []*string{&givenName},
				SD:        "always",
				Mandatory: true,
			},
			{
				Path:      []*string{&familyName},
				SD:        "always",
				Mandatory: true,
			},
			{
				Path:      []*string{&birthdate},
				SD:        "always",
				Mandatory: true,
			},
		},
	}

	// Document missing multiple mandatory claims
	doc := map[string]any{}

	docData, err := json.Marshal(doc)
	require.NoError(t, err)

	// Validate
	err = ValidateDocument(docData, vctm)
	assert.Error(t, err)

	validationErr, ok := err.(*ValidationErrors)
	require.True(t, ok)
	assert.Len(t, validationErr.Errors, 3)
}

func TestValidateDocument_NestedClaims(t *testing.T) {
	address := "address"
	street := "street"
	city := "city"

	vctm := &VCTM{
		VCT: "test:credential:1",
		Claims: []Claim{
			{
				Path:      []*string{&address, &street},
				SD:        "always",
				Mandatory: true,
			},
			{
				Path:      []*string{&address, &city},
				SD:        "always",
				Mandatory: true,
			},
		},
	}

	// Valid nested document
	doc := map[string]any{
		"address": map[string]any{
			"street": "123 Main St",
			"city":   "Springfield",
		},
	}

	docData, err := json.Marshal(doc)
	require.NoError(t, err)

	// Validate
	err = ValidateDocument(docData, vctm)
	assert.NoError(t, err)
}

func TestValidateDocument_MissingNestedClaim(t *testing.T) {
	address := "address"
	street := "street"
	city := "city"

	vctm := &VCTM{
		VCT: "test:credential:1",
		Claims: []Claim{
			{
				Path:      []*string{&address, &street},
				SD:        "always",
				Mandatory: true,
			},
			{
				Path:      []*string{&address, &city},
				SD:        "always",
				Mandatory: true,
			},
		},
	}

	// Document missing nested city
	doc := map[string]any{
		"address": map[string]any{
			"street": "123 Main St",
		},
	}

	docData, err := json.Marshal(doc)
	require.NoError(t, err)

	// Validate
	err = ValidateDocument(docData, vctm)
	assert.Error(t, err)

	validationErr, ok := err.(*ValidationErrors)
	require.True(t, ok)
	assert.Len(t, validationErr.Errors, 1)
	assert.Equal(t, "$.address.city", validationErr.Errors[0].Field)
}

func TestValidateDocument_OptionalClaimsMissing(t *testing.T) {
	givenName := "given_name"
	nickname := "nickname"

	vctm := &VCTM{
		VCT: "test:credential:1",
		Claims: []Claim{
			{
				Path:      []*string{&givenName},
				SD:        "always",
				Mandatory: true,
			},
			{
				Path:      []*string{&nickname},
				SD:        "allowed",
				Mandatory: false,
			},
		},
	}

	// Document without optional nickname
	doc := map[string]any{
		"given_name": "John",
	}

	docData, err := json.Marshal(doc)
	require.NoError(t, err)

	// Validate - should pass
	err = ValidateDocument(docData, vctm)
	assert.NoError(t, err)
}

// VCTMs frequently mark JWT envelope claims (iss, exp, cnf) as mandatory for
// verifier-side conformance, but those values are filled in by the issuer
// pipeline at signing time rather than by the document data source. Document
// validation must skip them — see isIssuerSuppliedClaim in validation.go.
func TestValidateDocument_IssuerSuppliedMandatoryClaimsExempt(t *testing.T) {
	iss := "iss"
	exp := "exp"
	cnf := "cnf"
	givenName := "given_name"

	vctm := &VCTM{
		VCT: "test:credential:1",
		Claims: []Claim{
			{Path: []*string{&iss}, Mandatory: true},
			{Path: []*string{&exp}, Mandatory: true},
			{Path: []*string{&cnf}, Mandatory: true},
			{Path: []*string{&givenName}, SD: "always", Mandatory: true},
		},
	}

	// Document data omits iss/exp/cnf — those come from the issuer at signing.
	doc := map[string]any{
		"given_name": "John",
	}

	docData, err := json.Marshal(doc)
	require.NoError(t, err)

	err = ValidateDocument(docData, vctm)
	assert.NoError(t, err)
}

func TestValidateDocument_InvalidJSON(t *testing.T) {
	vctm := &VCTM{
		VCT:    "test:credential:1",
		Claims: []Claim{},
	}

	// Invalid JSON
	docData := []byte("{invalid json}")

	// Validate
	err := ValidateDocument(docData, vctm)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid document data")
}

func TestValidateDocument_NilVCTM(t *testing.T) {
	doc := map[string]any{
		"given_name": "John",
	}

	docData, err := json.Marshal(doc)
	require.NoError(t, err)

	// Validate with nil VCTM
	err = ValidateDocument(docData, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "VCTM is nil")
}

// ValidateClaims operates on fully assembled credential claims, so mandatory
// JWT/SD-JWT envelope claims (iss, exp, cnf, vct, iat, ...) declared by the
// VCTM must be present. The issuer-supplied exemption used by ValidateDocument
// must not leak into ValidateClaims.
func TestValidateClaims_RequiresMandatoryEnvelopeClaims(t *testing.T) {
	iss := "iss"
	exp := "exp"
	cnf := "cnf"
	givenName := "given_name"

	vctm := &VCTM{
		VCT: "test:credential:1",
		Claims: []Claim{
			{Path: []*string{&iss}, Mandatory: true},
			{Path: []*string{&exp}, Mandatory: true},
			{Path: []*string{&cnf}, Mandatory: true},
			{Path: []*string{&givenName}, SD: "always", Mandatory: true},
		},
	}

	// Assembled-credential payload missing envelope claims — should fail.
	claims := map[string]any{
		"given_name": "John",
	}

	err := ValidateClaims(claims, vctm)
	require.Error(t, err)

	validationErr, ok := err.(*ValidationErrors)
	require.True(t, ok)

	missing := map[string]bool{}
	for _, e := range validationErr.Errors {
		missing[e.Field] = true
	}
	assert.True(t, missing["$.iss"], "expected 'iss' to be reported missing")
	assert.True(t, missing["$.exp"], "expected 'exp' to be reported missing")
	assert.True(t, missing["$.cnf"], "expected 'cnf' to be reported missing")
}

func TestValidateClaims_ArrayValues(t *testing.T) {
	nationality := "nationality"

	vctm := &VCTM{
		VCT: "test:credential:1",
		Claims: []Claim{
			{
				Path:      []*string{&nationality},
				SD:        "always",
				Mandatory: false,
			},
		},
	}

	// Document with array value
	doc := map[string]any{
		"nationality": []any{"US", "GB"},
	}

	// Validate
	err := ValidateClaims(doc, vctm)
	assert.NoError(t, err)
}

func TestValidateClaimPaths_StrictMode_Success(t *testing.T) {
	givenName := "given_name"
	familyName := "family_name"

	vctm := &VCTM{
		VCT: "test:credential:1",
		Claims: []Claim{
			{
				Path: []*string{&givenName},
			},
			{
				Path: []*string{&familyName},
			},
		},
	}

	// Document with only defined claims
	doc := map[string]any{
		"given_name":  "John",
		"family_name": "Doe",
	}

	// Validate in strict mode
	err := ValidateClaimPaths(doc, vctm, true)
	assert.NoError(t, err)
}

func TestValidateClaimPaths_StrictMode_ExtraClaims(t *testing.T) {
	givenName := "given_name"

	vctm := &VCTM{
		VCT: "test:credential:1",
		Claims: []Claim{
			{
				Path: []*string{&givenName},
			},
		},
	}

	// Document with extra claim not in VCTM
	doc := map[string]any{
		"given_name": "John",
		"nickname":   "Johnny", // Not in VCTM
	}

	// Validate in strict mode
	err := ValidateClaimPaths(doc, vctm, true)
	assert.Error(t, err)

	validationErr, ok := err.(*ValidationErrors)
	require.True(t, ok)
	assert.True(t, len(validationErr.Errors) > 0)

	// Find the error about nickname
	found := false
	for _, e := range validationErr.Errors {
		if e.Field == "nickname" {
			found = true
			assert.Contains(t, e.Message, "not defined in VCTM")
		}
	}
	assert.True(t, found, "expected error for 'nickname' field")
}

func TestValidateClaimPaths_NonStrictMode_ExtraClaims(t *testing.T) {
	givenName := "given_name"

	vctm := &VCTM{
		VCT: "test:credential:1",
		Claims: []Claim{
			{
				Path: []*string{&givenName},
			},
		},
	}

	// Document with extra claim
	doc := map[string]any{
		"given_name": "John",
		"nickname":   "Johnny",
	}

	// Validate in non-strict mode (should pass)
	err := ValidateClaimPaths(doc, vctm, false)
	assert.NoError(t, err)
}

func TestValidateClaimPaths_StandardClaimsAllowed(t *testing.T) {
	givenName := "given_name"

	vctm := &VCTM{
		VCT: "test:credential:1",
		Claims: []Claim{
			{
				Path: []*string{&givenName},
			},
		},
	}

	// Document with standard JWT/SD-JWT claims
	doc := map[string]any{
		"given_name": "John",
		"iss":        "https://issuer.example.com",
		"iat":        1234567890,
		"exp":        1234567890,
		"vct":        "test:credential:1",
		"cnf":        map[string]any{"jwk": map[string]any{"kty": "EC"}},
	}

	// Validate in strict mode - standard claims should be allowed
	err := ValidateClaimPaths(doc, vctm, true)
	assert.NoError(t, err)
}

func TestIsStandardClaim(t *testing.T) {
	tests := []struct {
		claim    string
		expected bool
	}{
		{"iss", true},
		{"sub", true},
		{"aud", true},
		{"exp", true},
		{"nbf", true},
		{"iat", true},
		{"jti", true},
		{"vct", true},
		{"cnf", true},
		{"_sd", true},
		{"_sd_alg", true},
		{"...", true},
		{"given_name", false},
		{"custom_claim", false},
	}

	for _, tt := range tests {
		t.Run(tt.claim, func(t *testing.T) {
			result := isStandardClaim(tt.claim)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{
		Field:   "given_name",
		Message: "is required",
	}

	assert.Equal(t, "validation error for field 'given_name': is required", err.Error())
}

func TestValidationErrors_Error(t *testing.T) {
	errors := &ValidationErrors{
		Errors: []ValidationError{
			{Field: "given_name", Message: "is required"},
			{Field: "family_name", Message: "is required"},
		},
	}

	errMsg := errors.Error()
	assert.Contains(t, errMsg, "multiple validation errors")
	assert.Contains(t, errMsg, "given_name")
	assert.Contains(t, errMsg, "family_name")
}

func TestValidationErrors_SingleError(t *testing.T) {
	errors := &ValidationErrors{
		Errors: []ValidationError{
			{Field: "given_name", Message: "is required"},
		},
	}

	errMsg := errors.Error()
	assert.Equal(t, "validation error for field 'given_name': is required", errMsg)
}
