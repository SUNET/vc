package samlsp

import (
	"fmt"
	"vc/pkg/credential"
	"vc/pkg/logger"
	"vc/pkg/model"
)

// AttributeMapper handles mapping between SAML attributes and credential claims
// DEPRECATED: Use ClaimTransformer instead for new implementations
type AttributeMapper struct {
	mappings map[string]model.CredentialMapping
	log      *logger.Log
}

// NewAttributeMapper creates a new attribute mapper
// DEPRECATED: Use BuildTransformer() and ClaimTransformer instead
func NewAttributeMapper(mappings map[string]model.CredentialMapping, log *logger.Log) *AttributeMapper {
	return &AttributeMapper{
		mappings: mappings,
		log:      log.New("mapper"),
	}
}

// MapAttributes maps SAML attributes to credential claims
// DEPRECATED: Use ClaimTransformer.TransformClaims() instead
func (m *AttributeMapper) MapAttributes(samlAttrs map[string][]string, samlType string) (map[string]any, error) {
	mapping, ok := m.mappings[samlType]
	if !ok {
		return nil, fmt.Errorf("no attribute mapping found for SAML type: %s", samlType)
	}

	claims := make(map[string]any)

	for samlAttr, attrCfg := range mapping.Attributes {
		values, exists := samlAttrs[samlAttr]
		if !exists {
			// Check if required
			if attrCfg.Required {
				return nil, fmt.Errorf("required attribute missing: %s (claim: %s)", samlAttr, attrCfg.Claim)
			}
			// Use default if available
			if attrCfg.Default != "" {
				claims[attrCfg.Claim] = attrCfg.Default
			}
			continue
		}

		var value any
		if len(values) == 1 {
			value = values[0]
		} else if len(values) > 1 {
			value = values
		} else {
			continue
		}

		// Apply transformation
		value = credential.ApplyTransform(value, attrCfg.Transform)

		claims[attrCfg.Claim] = value
	}

	m.log.Debug("mapped SAML attributes",
		"saml_type", samlType,
		"saml_attrs_count", len(samlAttrs),
		"mapped_claims_count", len(claims))

	return claims, nil
}

// IsValidCredentialType checks if a credential type has a mapping configured
func (m *AttributeMapper) IsValidCredentialType(samlType string) bool {
	_, ok := m.mappings[samlType]
	return ok
}

// GetDefaultIdP returns the default IdP for a credential type, if configured
func (m *AttributeMapper) GetDefaultIdP(samlType string) (string, bool) {
	mapping, ok := m.mappings[samlType]
	if !ok {
		return "", false
	}
	return mapping.DefaultIdP, mapping.DefaultIdP != ""
}

// GetSupportedCredentialTypes returns all configured credential types
func (m *AttributeMapper) GetSupportedCredentialTypes() []string {
	types := make([]string, 0, len(m.mappings))
	for credType := range m.mappings {
		types = append(types, credType)
	}
	return types
}

// GetCredentialType returns the credential type (which is now the map key)
// DEPRECATED: The credential type is already known from the request
func (m *AttributeMapper) GetCredentialType(credentialType string) (string, bool) {
	_, ok := m.mappings[credentialType]
	if !ok {
		return "", false
	}
	// The credential type IS the key in the map
	return credentialType, true
}

// GetCredentialConfigID returns the OpenID4VCI config ID for a credential type
func (m *AttributeMapper) GetCredentialConfigID(credentialType string) (string, bool) {
	mapping, ok := m.mappings[credentialType]
	if !ok {
		return "", false
	}
	return mapping.CredentialConfigID, true
}
