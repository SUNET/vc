package credential

import (
	"testing"

	"vc/pkg/logger"
)

func TestNewValidator(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)
	if v == nil {
		t.Error("Expected validator, got nil")
	}
	if v.log == nil {
		t.Error("Expected logger to be set")
	}
}

func TestValidateCredentialValid(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential, got error: %v", err)
	}
}

func TestValidateCredentialMissingContext(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for missing @context")
	}
}

func TestValidateCredentialInvalidContextFormat(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	// Context as number - invalid
	cred := map[string]any{
		"@context":          123,
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for invalid @context format")
	}
}

func TestValidateCredentialEmptyContext(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for empty @context")
	}
}

func TestValidateCredentialWrongFirstContext(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://example.com/wrong-context"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for wrong first @context")
	}
}

func TestValidateCredentialContextWithInvalidURL(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2", "not a url"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for invalid URL in @context")
	}
}

func TestValidateCredentialContextWithObject(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	// Object in context is valid
	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2", map[string]any{"@vocab": "https://example.com/"}},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with object context, got error: %v", err)
	}
}

func TestValidateCredentialContextWithInvalidItem(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	// Number in context is invalid (must be string or object)
	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2", 123},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for invalid item in @context")
	}
}

func TestValidateCredentialMissingType(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for missing type")
	}
}

func TestValidateCredentialInvalidTypeFormat(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              123, // Invalid - must be string or array
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for invalid type format")
	}
}

func TestValidateCredentialEmptyType(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for empty type array")
	}
}

func TestValidateCredentialMissingVerifiableCredentialType(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"SomeOtherType"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for missing VerifiableCredential type")
	}
}

func TestValidateCredentialTypeAsString(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              "VerifiableCredential", // Single string
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with string type, got error: %v", err)
	}
}

func TestValidateCredentialMissingIssuer(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for missing issuer")
	}
}

func TestValidateCredentialInvalidIssuerURL(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "not a url",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for invalid issuer URL")
	}
}

func TestValidateCredentialIssuerAsObject(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiableCredential"},
		"issuer": map[string]any{
			"id":   "https://example.com/issuer",
			"name": "Example Issuer",
		},
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with object issuer, got error: %v", err)
	}
}

func TestValidateCredentialIssuerObjectMissingID(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiableCredential"},
		"issuer": map[string]any{
			"name": "Example Issuer", // Missing id
		},
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for issuer object missing id")
	}
}

func TestValidateCredentialIssuerObjectInvalidIDType(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiableCredential"},
		"issuer": map[string]any{
			"id": 123, // Invalid type
		},
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for issuer id not a string")
	}
}

func TestValidateCredentialIssuerObjectInvalidIDURL(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiableCredential"},
		"issuer": map[string]any{
			"id": "not a url",
		},
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for invalid issuer id URL")
	}
}

func TestValidateCredentialInvalidIssuerFormat(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            123, // Invalid format
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for invalid issuer format")
	}
}

func TestValidateCredentialMissingCredentialSubject(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiableCredential"},
		"issuer":   "https://example.com/issuer",
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for missing credentialSubject")
	}
}

func TestValidateCredentialNullCredentialSubject(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": nil,
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for null credentialSubject")
	}
}

func TestValidateCredentialEmptyCredentialSubject(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for empty credentialSubject")
	}
}

func TestValidateCredentialSubjectAsArray(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiableCredential"},
		"issuer":   "https://example.com/issuer",
		"credentialSubject": []any{
			map[string]any{"id": "did:example:123"},
			map[string]any{"id": "did:example:456"},
		},
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with array credentialSubject, got error: %v", err)
	}
}

func TestValidateCredentialEmptySubjectArray(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": []any{},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for empty credentialSubject array")
	}
}

func TestValidateCredentialEmptySubjectInArray(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiableCredential"},
		"issuer":   "https://example.com/issuer",
		"credentialSubject": []any{
			map[string]any{}, // Empty item
		},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for empty credentialSubject item in array")
	}
}

func TestValidateCredentialInvalidSubjectFormat(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": "invalid", // Should be object or array
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for invalid credentialSubject format")
	}
}

func TestValidateCredentialValidityPeriod(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"validFrom":         "2020-01-01T00:00:00Z",
		"validUntil":        "2025-01-01T00:00:00Z",
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with validity period, got error: %v", err)
	}
}

func TestValidateCredentialInvalidValidFrom(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"validFrom":         "not a date",
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for invalid validFrom format")
	}
}

func TestValidateCredentialValidFromNotString(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"validFrom":         123,
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for validFrom not a string")
	}
}

func TestValidateCredentialInvalidValidUntil(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"validUntil":        "not a date",
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for invalid validUntil format")
	}
}

func TestValidateCredentialValidUntilNotString(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"validUntil":        123,
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for validUntil not a string")
	}
}

func TestValidateCredentialValidUntilBeforeValidFrom(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"validFrom":         "2025-01-01T00:00:00Z",
		"validUntil":        "2020-01-01T00:00:00Z", // Before validFrom
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for validUntil before validFrom")
	}
}

func TestValidateCredentialWithStatus(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"credentialStatus": map[string]any{
			"id":   "https://example.com/status/1",
			"type": "BitstringStatusListEntry",
		},
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with status, got error: %v", err)
	}
}

func TestValidateCredentialStatusMissingType(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"credentialStatus": map[string]any{
			"id": "https://example.com/status/1",
		},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for credentialStatus missing type")
	}
}

func TestValidateCredentialStatusInvalidIDType(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"credentialStatus": map[string]any{
			"id":   123, // Invalid
			"type": "BitstringStatusListEntry",
		},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for credentialStatus id not a string")
	}
}

func TestValidateCredentialStatusInvalidIDURL(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"credentialStatus": map[string]any{
			"id":   "not a url",
			"type": "BitstringStatusListEntry",
		},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for credentialStatus id not a URL")
	}
}

func TestValidateCredentialStatusAsArray(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"credentialStatus": []any{
			map[string]any{
				"id":   "https://example.com/status/1",
				"type": "BitstringStatusListEntry",
			},
		},
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with status array, got error: %v", err)
	}
}

func TestValidateCredentialWithSchema(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"credentialSchema": map[string]any{
			"id":   "https://example.com/schema/1",
			"type": "JsonSchema",
		},
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with schema, got error: %v", err)
	}
}

func TestValidateCredentialSchemaMissingType(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"credentialSchema": map[string]any{
			"id": "https://example.com/schema/1",
		},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for credentialSchema missing type")
	}
}

func TestValidateCredentialSchemaMissingID(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"credentialSchema": map[string]any{
			"type": "JsonSchema",
		},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for credentialSchema missing id")
	}
}

func TestValidateCredentialSchemaInvalidIDType(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"credentialSchema": map[string]any{
			"id":   123,
			"type": "JsonSchema",
		},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for credentialSchema id not a string")
	}
}

func TestValidateCredentialSchemaInvalidIDURL(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"credentialSchema": map[string]any{
			"id":   "not a url",
			"type": "JsonSchema",
		},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for credentialSchema id not a URL")
	}
}

func TestValidateCredentialSchemaAsArray(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"credentialSchema": []any{
			map[string]any{
				"id":   "https://example.com/schema/1",
				"type": "JsonSchema",
			},
		},
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with schema array, got error: %v", err)
	}
}

func TestValidateCredentialSchemaNotObject(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"credentialSchema": []any{
			"not an object",
		},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for credentialSchema not an object")
	}
}

func TestValidateCredentialWithTermsOfUse(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"termsOfUse": map[string]any{
			"type": "IssuerPolicy",
		},
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with termsOfUse, got error: %v", err)
	}
}

func TestValidateCredentialTermsOfUseMissingType(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"termsOfUse":        map[string]any{},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for termsOfUse missing type")
	}
}

func TestValidateCredentialTermsOfUseNotObject(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"termsOfUse":        []any{"not an object"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for termsOfUse not an object")
	}
}

func TestValidateCredentialWithEvidence(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"evidence": map[string]any{
			"type": "DocumentVerification",
		},
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with evidence, got error: %v", err)
	}
}

func TestValidateCredentialEvidenceMissingType(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"evidence":          map[string]any{},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for evidence missing type")
	}
}

func TestValidateCredentialEvidenceNotObject(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"evidence":          []any{"not an object"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for evidence not an object")
	}
}

func TestValidateCredentialWithRefreshService(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"refreshService": map[string]any{
			"type": "ManualRefreshService",
		},
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with refreshService, got error: %v", err)
	}
}

func TestValidateCredentialRefreshServiceMissingType(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"refreshService":    map[string]any{},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for refreshService missing type")
	}
}

func TestValidateCredentialRefreshServiceNotObject(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"refreshService":    []any{"not an object"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for refreshService not an object")
	}
}

func TestValidateCredentialWithID(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"id":                "https://example.com/credentials/123",
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with id, got error: %v", err)
	}
}

func TestValidateCredentialInvalidIDType(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"id":                123,
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for id not a string")
	}
}

func TestValidateCredentialInvalidIDURL(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"id":                "not a url",
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for invalid id URL")
	}
}

func TestValidateCredentialWithNameAndDescription(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"name":              "Example Credential",
		"description":       "An example credential",
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with name and description, got error: %v", err)
	}
}

func TestValidateCredentialNameAsLanguageMap(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"name": map[string]any{
			"en": "Example Credential",
			"de": "Beispiel-Nachweis",
		},
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with language map name, got error: %v", err)
	}
}

func TestValidateCredentialNameAsValueObject(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"name": map[string]any{
			"@value":    "Example Credential",
			"@language": "en",
		},
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with value object name, got error: %v", err)
	}
}

func TestValidateCredentialNameAsArray(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"name": []any{
			"Example Credential",
			map[string]any{"de": "Beispiel-Nachweis"},
		},
	}

	err := v.ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential with name array, got error: %v", err)
	}
}

func TestValidateCredentialInvalidNameFormat(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"name":              123, // Invalid
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for invalid name format")
	}
}

func TestValidateCredentialNameMapWithNonStringValue(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"name": map[string]any{
			"en": 123, // Invalid
		},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for name map with non-string value")
	}
}

func TestValidateCredentialValueObjectWithInvalidKey(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
		"name": map[string]any{
			"@value":     "Example",
			"invalidKey": "test", // Invalid key in value object
		},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for value object with invalid key")
	}
}

func TestValidatePresentationValid(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	vp := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiablePresentation"},
	}

	err := v.ValidatePresentation(vp)
	if err != nil {
		t.Errorf("Expected valid presentation, got error: %v", err)
	}
}

func TestValidatePresentationWithID(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	vp := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"id":       "https://example.com/presentations/123",
		"type":     []any{"VerifiablePresentation"},
	}

	err := v.ValidatePresentation(vp)
	if err != nil {
		t.Errorf("Expected valid presentation with id, got error: %v", err)
	}
}

func TestValidatePresentationMissingContext(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	vp := map[string]any{
		"type": []any{"VerifiablePresentation"},
	}

	err := v.ValidatePresentation(vp)
	if err == nil {
		t.Error("Expected error for presentation missing @context")
	}
}

func TestValidatePresentationMissingType(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	vp := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
	}

	err := v.ValidatePresentation(vp)
	if err == nil {
		t.Error("Expected error for presentation missing type")
	}
}

// Test deprecated standalone functions
func TestValidateCredentialStandalone(t *testing.T) {
	cred := map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "https://example.com/issuer",
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := ValidateCredential(cred)
	if err != nil {
		t.Errorf("Expected valid credential, got error: %v", err)
	}
}

func TestValidatePresentationStandalone(t *testing.T) {
	vp := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiablePresentation"},
	}

	err := ValidatePresentation(vp)
	if err != nil {
		t.Errorf("Expected valid presentation, got error: %v", err)
	}
}

// Test isURL function
func TestIsURL(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"https://example.com", true},
		{"http://example.com", true},
		{"did:example:123", true},
		{"urn:uuid:123", true},
		{"not a url", false},
		{"https://", false},
		{"http://", false},
		{"did:", false},
		{"", false},
		{"has space.com", false},
	}

	for _, tt := range tests {
		result := isURL(tt.url)
		if result != tt.expected {
			t.Errorf("isURL(%q) = %v, expected %v", tt.url, result, tt.expected)
		}
	}
}

// Test issuer with invalid name/description metadata
func TestValidateCredentialIssuerWithInvalidMetadata(t *testing.T) {
	log := logger.NewSimple("test")
	v := NewValidator(log)

	cred := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		"type":     []any{"VerifiableCredential"},
		"issuer": map[string]any{
			"id":   "https://example.com/issuer",
			"name": 123, // Invalid
		},
		"credentialSubject": map[string]any{"id": "did:example:123"},
	}

	err := v.ValidateCredential(cred)
	if err == nil {
		t.Error("Expected error for issuer with invalid metadata")
	}
}
