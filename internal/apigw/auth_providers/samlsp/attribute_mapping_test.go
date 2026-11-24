package samlsp

import (
	"testing"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/model"

	"github.com/stretchr/testify/assert"
)

func TestNewAttributeMapper(t *testing.T) {
	mapping := model.AttributeMapping{
		"urn:oid:2.5.4.42": {Claim: claimpath.Keys("given_name"), Required: true},
	}
	mapper := NewAttributeMapper(mapping)
	assert.NotNil(t, mapper)
}

func TestAttributeMapper_SimpleMapping(t *testing.T) {
	mapping := model.AttributeMapping{
		"urn:oid:2.5.4.42": {Claim: claimpath.Keys("given_name"), Required: true},
		"urn:oid:2.5.4.4":  {Claim: claimpath.Keys("family_name"), Required: true},
	}
	mapper := NewAttributeMapper(mapping)
	attributes := map[string]any{
		"urn:oid:2.5.4.42": "John",
		"urn:oid:2.5.4.4":  "Doe",
	}
	doc, err := mapper.Apply(attributes)
	assert.NoError(t, err)
	assert.Equal(t, "John", doc["given_name"])
	assert.Equal(t, "Doe", doc["family_name"])
}

func TestAttributeMapper_RequiredAttributeMissing(t *testing.T) {
	mapping := model.AttributeMapping{
		"urn:oid:2.5.4.42": {Claim: claimpath.Keys("given_name"), Required: true},
		"urn:oid:2.5.4.4":  {Claim: claimpath.Keys("family_name"), Required: true},
	}
	mapper := NewAttributeMapper(mapping)
	_, err := mapper.Apply(map[string]any{"urn:oid:2.5.4.42": "John"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing required attribute")
}

func TestAttributeMapper_OptionalAttributeMissing(t *testing.T) {
	mapping := model.AttributeMapping{
		"urn:oid:2.5.4.42": {Claim: claimpath.Keys("given_name"), Required: true},
		"urn:oid:2.5.4.10": {Claim: claimpath.Keys("organization"), Required: false},
	}
	mapper := NewAttributeMapper(mapping)
	doc, err := mapper.Apply(map[string]any{"urn:oid:2.5.4.42": "John"})
	assert.NoError(t, err)
	assert.Equal(t, "John", doc["given_name"])
	assert.NotContains(t, doc, "organization")
}

func TestAttributeMapper_DefaultValue(t *testing.T) {
	mapping := model.AttributeMapping{
		"urn:oid:2.5.4.42": {Claim: claimpath.Keys("given_name"), Required: true},
		"urn:oid:2.5.4.10": {Claim: claimpath.Keys("country"), Required: false, Default: "SE"},
	}
	mapper := NewAttributeMapper(mapping)
	doc, err := mapper.Apply(map[string]any{"urn:oid:2.5.4.42": "John"})
	assert.NoError(t, err)
	assert.Equal(t, "John", doc["given_name"])
	assert.Equal(t, "SE", doc["country"])
}

func TestAttributeMapper_ComplexRealWorld(t *testing.T) {
	mapping := model.AttributeMapping{
		"urn:oid:2.5.4.42":                  {Claim: claimpath.Keys("identity", "given_name"), Required: true},
		"urn:oid:2.5.4.4":                   {Claim: claimpath.Keys("identity", "family_name"), Required: true},
		"urn:oid:0.9.2342.19200300.100.1.3": {Claim: claimpath.Keys("identity", "email_address"), Required: false},
		"urn:oid:1.2.752.29.4.13":           {Claim: claimpath.Keys("identity", "personal_administrative_number"), Required: false},
		"urn:oid:2.5.4.10":                  {Claim: claimpath.Keys("identity", "resident_city"), Required: false},
		"urn:oid:2.5.4.6":                   {Claim: claimpath.Keys("identity", "resident_country"), Required: false, Default: "SE"},
	}
	mapper := NewAttributeMapper(mapping)
	attributes := map[string]any{
		"urn:oid:2.5.4.42":                  "Magnus",
		"urn:oid:2.5.4.4":                   "Svensson",
		"urn:oid:0.9.2342.19200300.100.1.3": "magnus.svensson@example.se",
		"urn:oid:1.2.752.29.4.13":           "197001011234",
		"urn:oid:2.5.4.10":                  "Stockholm",
	}
	doc, err := mapper.Apply(attributes)
	assert.NoError(t, err)
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
