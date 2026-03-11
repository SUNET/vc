package samlsp

import (
	"testing"

	"vc/pkg/credential"
	"vc/pkg/model"

	"github.com/stretchr/testify/assert"
)

func TestNewClaimTransformer(t *testing.T) {
	mappings := map[string]model.CredentialMapping{
		"pid": {
			CredentialConfigID: "urn:eudi:pid:1",
			Attributes: map[string]model.AttributeConfig{
				"urn:oid:2.5.4.42": {Claim: "given_name", Required: true},
			},
		},
	}

	transformer := NewClaimTransformer(mappings)
	assert.NotNil(t, transformer)
}

func TestGetMapping(t *testing.T) {
	mappings := map[string]model.CredentialMapping{
		"pid": {
			Attributes: map[string]model.AttributeConfig{},
		},
	}

	transformer := NewClaimTransformer(mappings)

	// Test existing mapping
	mapping, err := transformer.GetMapping("pid")
	assert.NoError(t, err)
	assert.NotNil(t, mapping)

	// Test non-existent mapping
	_, err = transformer.GetMapping("unknown")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown credential type")
}

func TestTransformClaims_SimpleMapping(t *testing.T) {
	mappings := map[string]model.CredentialMapping{
		"pid": {
			Attributes: map[string]model.AttributeConfig{
				"urn:oid:2.5.4.42": {Claim: "given_name", Required: true},
				"urn:oid:2.5.4.4":  {Claim: "family_name", Required: true},
			},
		},
	}

	transformer := NewClaimTransformer(mappings)

	attributes := map[string]any{
		"urn:oid:2.5.4.42": "John",
		"urn:oid:2.5.4.4":  "Doe",
	}

	doc, err := transformer.TransformClaims("pid", attributes)
	assert.NoError(t, err)
	assert.NotNil(t, doc)
	assert.Equal(t, "John", doc["given_name"])
	assert.Equal(t, "Doe", doc["family_name"])
}

func TestTransformClaims_NestedMapping(t *testing.T) {
	mappings := map[string]model.CredentialMapping{
		"pid": {
			Attributes: map[string]model.AttributeConfig{
				"urn:oid:2.5.4.42": {Claim: "identity.given_name", Required: true},
				"urn:oid:2.5.4.4":  {Claim: "identity.family_name", Required: true},
				"urn:oid:2.5.4.10": {Claim: "identity.organization", Required: false},
			},
		},
	}

	transformer := NewClaimTransformer(mappings)

	attributes := map[string]any{
		"urn:oid:2.5.4.42": "John",
		"urn:oid:2.5.4.4":  "Doe",
		"urn:oid:2.5.4.10": "ACME Corp",
	}

	doc, err := transformer.TransformClaims("pid", attributes)
	assert.NoError(t, err)
	assert.NotNil(t, doc)

	// Verify nested structure
	identity, exists := doc["identity"]
	assert.True(t, exists)

	identityMap, ok := identity.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "John", identityMap["given_name"])
	assert.Equal(t, "Doe", identityMap["family_name"])
	assert.Equal(t, "ACME Corp", identityMap["organization"])
}

func TestTransformClaims_RequiredAttributeMissing(t *testing.T) {
	mappings := map[string]model.CredentialMapping{
		"pid": {
			Attributes: map[string]model.AttributeConfig{
				"urn:oid:2.5.4.42": {Claim: "given_name", Required: true},
				"urn:oid:2.5.4.4":  {Claim: "family_name", Required: true},
			},
		},
	}

	transformer := NewClaimTransformer(mappings)

	attributes := map[string]any{
		"urn:oid:2.5.4.42": "John",
		// Missing required family_name
	}

	_, err := transformer.TransformClaims("pid", attributes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing required attribute")
}

func TestTransformClaims_OptionalAttributeMissing(t *testing.T) {
	mappings := map[string]model.CredentialMapping{
		"pid": {
			Attributes: map[string]model.AttributeConfig{
				"urn:oid:2.5.4.42": {Claim: "given_name", Required: true},
				"urn:oid:2.5.4.10": {Claim: "organization", Required: false},
			},
		},
	}

	transformer := NewClaimTransformer(mappings)

	attributes := map[string]any{
		"urn:oid:2.5.4.42": "John",
		// Missing optional organization - should be OK
	}

	doc, err := transformer.TransformClaims("pid", attributes)
	assert.NoError(t, err)
	assert.NotNil(t, doc)
	assert.Equal(t, "John", doc["given_name"])
	assert.NotContains(t, doc, "organization")
}

func TestTransformClaims_DefaultValue(t *testing.T) {
	mappings := map[string]model.CredentialMapping{
		"pid": {
			Attributes: map[string]model.AttributeConfig{
				"urn:oid:2.5.4.42": {Claim: "given_name", Required: true},
				"urn:oid:2.5.4.10": {Claim: "country", Required: false, Default: "SE"},
			},
		},
	}

	transformer := NewClaimTransformer(mappings)

	attributes := map[string]any{
		"urn:oid:2.5.4.42": "John",
		// Missing country - should use default
	}

	doc, err := transformer.TransformClaims("pid", attributes)
	assert.NoError(t, err)
	assert.NotNil(t, doc)
	assert.Equal(t, "John", doc["given_name"])
	assert.Equal(t, "SE", doc["country"])
}

func TestApplyTransform_Lowercase(t *testing.T) {
	result := credential.ApplyTransform("JOHN.DOE@EXAMPLE.COM", "lowercase")
	assert.Equal(t, "john.doe@example.com", result)
}

func TestApplyTransform_Uppercase(t *testing.T) {
	result := credential.ApplyTransform("john doe", "uppercase")
	assert.Equal(t, "JOHN DOE", result)
}

func TestApplyTransform_Trim(t *testing.T) {
	result := credential.ApplyTransform("  John Doe  ", "trim")
	assert.Equal(t, "John Doe", result)
}

func TestApplyTransform_NonString(t *testing.T) {
	// Should return original value for non-strings
	result := credential.ApplyTransform(123, "lowercase")
	assert.Equal(t, 123, result)
}

func TestApplyTransform_UnknownTransform(t *testing.T) {
	result := credential.ApplyTransform("test", "unknown")
	assert.Equal(t, "test", result)
}

func TestTransformClaims_WithTransformations(t *testing.T) {
	mappings := map[string]model.CredentialMapping{
		"pid": {
			Attributes: map[string]model.AttributeConfig{
				"urn:oid:0.9.2342.19200300.100.1.3": {
					Claim:     "email",
					Required:  true,
					Transform: "lowercase",
				},
				"urn:oid:2.5.4.42": {
					Claim:     "given_name",
					Required:  true,
					Transform: "trim",
				},
			},
		},
	}

	transformer := NewClaimTransformer(mappings)

	attributes := map[string]any{
		"urn:oid:0.9.2342.19200300.100.1.3": "JOHN.DOE@EXAMPLE.COM",
		"urn:oid:2.5.4.42":                  "  John  ",
	}

	doc, err := transformer.TransformClaims("pid", attributes)
	assert.NoError(t, err)
	assert.Equal(t, "john.doe@example.com", doc["email"])
	assert.Equal(t, "John", doc["given_name"])
}

func TestSetNestedValue_Simple(t *testing.T) {
	doc := make(map[string]any)
	err := credential.SetNestedValue(doc, "name", "John")
	assert.NoError(t, err)
	assert.Equal(t, "John", doc["name"])
}

func TestSetNestedValue_Nested(t *testing.T) {
	doc := make(map[string]any)
	err := credential.SetNestedValue(doc, "person.name", "John")
	assert.NoError(t, err)

	person, exists := doc["person"]
	assert.True(t, exists)

	personMap, ok := person.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "John", personMap["name"])
}

func TestSetNestedValue_DeepNesting(t *testing.T) {
	doc := make(map[string]any)
	err := credential.SetNestedValue(doc, "a.b.c.d", "value")
	assert.NoError(t, err)

	// Navigate down the structure
	a, _ := doc["a"].(map[string]any)
	b, _ := a["b"].(map[string]any)
	c, _ := b["c"].(map[string]any)
	assert.Equal(t, "value", c["d"])
}

func TestSetNestedValue_MultipleValues(t *testing.T) {
	doc := make(map[string]any)

	err := credential.SetNestedValue(doc, "identity.given_name", "John")
	assert.NoError(t, err)

	err = credential.SetNestedValue(doc, "identity.family_name", "Doe")
	assert.NoError(t, err)

	err = credential.SetNestedValue(doc, "identity.email", "john@example.com")
	assert.NoError(t, err)

	identity, _ := doc["identity"].(map[string]any)
	assert.Equal(t, "John", identity["given_name"])
	assert.Equal(t, "Doe", identity["family_name"])
	assert.Equal(t, "john@example.com", identity["email"])
}

func TestSetNestedValue_EmptyPath(t *testing.T) {
	doc := make(map[string]any)
	err := credential.SetNestedValue(doc, "", "value")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty path")
}

func TestSetNestedValue_PathConflict(t *testing.T) {
	doc := make(map[string]any)

	// Set a simple value
	doc["person"] = "John"

	// Try to set a nested value under it - should fail
	err := credential.SetNestedValue(doc, "person.name", "Doe")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "path conflict")
}

func TestGetNestedValue_Simple(t *testing.T) {
	doc := map[string]any{
		"name": "John",
	}

	value, exists := credential.GetNestedValue(doc, "name")
	assert.True(t, exists)
	assert.Equal(t, "John", value)
}

func TestGetNestedValue_Nested(t *testing.T) {
	doc := map[string]any{
		"person": map[string]any{
			"name": "John",
		},
	}

	value, exists := credential.GetNestedValue(doc, "person.name")
	assert.True(t, exists)
	assert.Equal(t, "John", value)
}

func TestGetNestedValue_NotFound(t *testing.T) {
	doc := map[string]any{
		"name": "John",
	}

	_, exists := credential.GetNestedValue(doc, "age")
	assert.False(t, exists)
}

func TestGetNestedValue_EmptyPath(t *testing.T) {
	doc := map[string]any{}

	_, exists := credential.GetNestedValue(doc, "")
	assert.False(t, exists)
}

func TestTransformClaims_ComplexRealWorld(t *testing.T) {
	// Simulate a real-world PID credential with nested identity structure
	mappings := map[string]model.CredentialMapping{
		"pid": {
			CredentialConfigID: "urn:eudi:pid:1",
			Attributes: map[string]model.AttributeConfig{
				"urn:oid:2.5.4.42":                  {Claim: "identity.given_name", Required: true},
				"urn:oid:2.5.4.4":                   {Claim: "identity.family_name", Required: true},
				"urn:oid:0.9.2342.19200300.100.1.3": {Claim: "identity.email_address", Required: false, Transform: "lowercase"},
				"urn:oid:1.2.752.29.4.13":           {Claim: "identity.personal_administrative_number", Required: false},
				"urn:oid:2.5.4.10":                  {Claim: "identity.resident_city", Required: false},
				"urn:oid:2.5.4.6":                   {Claim: "identity.resident_country", Required: false, Default: "SE"},
			},
		},
	}

	transformer := NewClaimTransformer(mappings)

	attributes := map[string]any{
		"urn:oid:2.5.4.42":                  "Magnus",
		"urn:oid:2.5.4.4":                   "Svensson",
		"urn:oid:0.9.2342.19200300.100.1.3": "MAGNUS.SVENSSON@EXAMPLE.SE",
		"urn:oid:1.2.752.29.4.13":           "197001011234",
		"urn:oid:2.5.4.10":                  "Stockholm",
		// resident_country missing - should use default
	}

	doc, err := transformer.TransformClaims("pid", attributes)
	assert.NoError(t, err)
	assert.NotNil(t, doc)

	// Verify nested identity structure
	identity, exists := doc["identity"]
	assert.True(t, exists)

	identityMap, ok := identity.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "Magnus", identityMap["given_name"])
	assert.Equal(t, "Svensson", identityMap["family_name"])
	assert.Equal(t, "magnus.svensson@example.se", identityMap["email_address"]) // Lowercased
	assert.Equal(t, "197001011234", identityMap["personal_administrative_number"])
	assert.Equal(t, "Stockholm", identityMap["resident_city"])
	assert.Equal(t, "SE", identityMap["resident_country"]) // Default value
}
