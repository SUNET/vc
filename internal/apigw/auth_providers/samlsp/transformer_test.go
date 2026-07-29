package samlsp

import (
	"testing"

	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
)

func TestNewClaimTransformer(t *testing.T) {
	mapping := model.AttributeMapping{
		"urn:oid:2.5.4.42": {Claim: "given_name", Required: true},
	}

	transformer := NewClaimTransformer(mapping)
	assert.NotNil(t, transformer)
}

func TestTransformClaims_SimpleMapping(t *testing.T) {
	mapping := model.AttributeMapping{
		"urn:oid:2.5.4.42": {Claim: "given_name", Required: true},
		"urn:oid:2.5.4.4":  {Claim: "family_name", Required: true},
	}

	transformer := NewClaimTransformer(mapping)

	attributes := map[string]any{
		"urn:oid:2.5.4.42": "John",
		"urn:oid:2.5.4.4":  "Doe",
	}

	doc, err := transformer.TransformClaims(attributes)
	assert.NoError(t, err)
	assert.NotNil(t, doc)
	assert.Equal(t, "John", doc["given_name"])
	assert.Equal(t, "Doe", doc["family_name"])
}

func TestTransformClaims_RequiredAttributeMissing(t *testing.T) {
	mapping := model.AttributeMapping{
		"urn:oid:2.5.4.42": {Claim: "given_name", Required: true},
		"urn:oid:2.5.4.4":  {Claim: "family_name", Required: true},
	}

	transformer := NewClaimTransformer(mapping)

	attributes := map[string]any{
		"urn:oid:2.5.4.42": "John",
	}

	_, err := transformer.TransformClaims(attributes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing required attribute")
}

func TestTransformClaims_OptionalAttributeMissing(t *testing.T) {
	mapping := model.AttributeMapping{
		"urn:oid:2.5.4.42": {Claim: "given_name", Required: true},
		"urn:oid:2.5.4.10": {Claim: "organization", Required: false},
	}

	transformer := NewClaimTransformer(mapping)

	attributes := map[string]any{
		"urn:oid:2.5.4.42": "John",
	}

	doc, err := transformer.TransformClaims(attributes)
	assert.NoError(t, err)
	assert.NotNil(t, doc)
	assert.Equal(t, "John", doc["given_name"])
	assert.NotContains(t, doc, "organization")
}

func TestTransformClaims_DefaultValue(t *testing.T) {
	mapping := model.AttributeMapping{
		"urn:oid:2.5.4.42": {Claim: "given_name", Required: true},
		"urn:oid:2.5.4.10": {Claim: "country", Required: false, Default: "SE"},
	}

	transformer := NewClaimTransformer(mapping)

	attributes := map[string]any{
		"urn:oid:2.5.4.42": "John",
	}

	doc, err := transformer.TransformClaims(attributes)
	assert.NoError(t, err)
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
	result := credential.ApplyTransform(123, "lowercase")
	assert.Equal(t, 123, result)
}

func TestApplyTransform_UnknownTransform(t *testing.T) {
	result := credential.ApplyTransform("test", "unknown")
	assert.Equal(t, "test", result)
}

func TestTransformClaims_WithTransformations(t *testing.T) {
	mapping := model.AttributeMapping{
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
	}

	transformer := NewClaimTransformer(mapping)

	attributes := map[string]any{
		"urn:oid:0.9.2342.19200300.100.1.3": "JOHN.DOE@EXAMPLE.COM",
		"urn:oid:2.5.4.42":                  "  John  ",
	}

	doc, err := transformer.TransformClaims(attributes)
	assert.NoError(t, err)
	assert.Equal(t, "john.doe@example.com", doc["email"])
	assert.Equal(t, "John", doc["given_name"])
}

func TestTransformClaims_ComplexRealWorld(t *testing.T) {
	mapping := model.AttributeMapping{
		"urn:oid:2.5.4.42":                  {Claim: "identity.given_name", Required: true},
		"urn:oid:2.5.4.4":                   {Claim: "identity.family_name", Required: true},
		"urn:oid:0.9.2342.19200300.100.1.3": {Claim: "identity.email_address", Required: false, Transform: "lowercase"},
		"urn:oid:1.2.752.29.4.13":           {Claim: "identity.personal_administrative_number", Required: false},
		"urn:oid:2.5.4.10":                  {Claim: "identity.resident_city", Required: false},
		"urn:oid:2.5.4.6":                   {Claim: "identity.resident_country", Required: false, Default: "SE"},
	}

	transformer := NewClaimTransformer(mapping)

	attributes := map[string]any{
		"urn:oid:2.5.4.42":                  "Magnus",
		"urn:oid:2.5.4.4":                   "Svensson",
		"urn:oid:0.9.2342.19200300.100.1.3": "MAGNUS.SVENSSON@EXAMPLE.SE",
		"urn:oid:1.2.752.29.4.13":           "197001011234",
		"urn:oid:2.5.4.10":                  "Stockholm",
	}

	doc, err := transformer.TransformClaims(attributes)
	assert.NoError(t, err)
	assert.NotNil(t, doc)

	identity, exists := doc["identity"]
	assert.True(t, exists)

	identityMap, ok := identity.(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "Magnus", identityMap["given_name"])
	assert.Equal(t, "Svensson", identityMap["family_name"])
	assert.Equal(t, "magnus.svensson@example.se", identityMap["email_address"])
	assert.Equal(t, "197001011234", identityMap["personal_administrative_number"])
	assert.Equal(t, "Stockholm", identityMap["resident_city"])
	assert.Equal(t, "SE", identityMap["resident_country"])
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
	person, _ := doc["person"]
	personMap, _ := person.(map[string]any)
	assert.Equal(t, "John", personMap["name"])
}

func TestSetNestedValue_EmptyPath(t *testing.T) {
	doc := make(map[string]any)
	err := credential.SetNestedValue(doc, "", "value")
	assert.Error(t, err)
}

func TestSetNestedValue_PathConflict(t *testing.T) {
	doc := make(map[string]any)
	doc["person"] = "John"
	err := credential.SetNestedValue(doc, "person.name", "Doe")
	assert.Error(t, err)
}

func TestGetNestedValue_Simple(t *testing.T) {
	doc := map[string]any{"name": "John"}
	value, exists := credential.GetNestedValue(doc, "name")
	assert.True(t, exists)
	assert.Equal(t, "John", value)
}

func TestGetNestedValue_NotFound(t *testing.T) {
	doc := map[string]any{"name": "John"}
	_, exists := credential.GetNestedValue(doc, "age")
	assert.False(t, exists)
}

func TestGetNestedValue_EmptyPath(t *testing.T) {
	doc := map[string]any{}
	_, exists := credential.GetNestedValue(doc, "")
	assert.False(t, exists)
}
