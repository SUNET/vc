package samlsp

import (
	"fmt"
	"strings"
)

// AttributeMapping defines how an external attribute maps to a credential claim
// Protocol-agnostic - works for SAML OIDs, OIDC claim names, etc.
type AttributeMapping struct {
	Claim     string // Dot-notation path: "identity.family_name" or simple "family_name"
	Required  bool   // Whether this attribute is required
	Transform string // Optional transformation: "lowercase", "uppercase", "trim"
	Default   string // Optional default value if attribute is missing
}

// CredentialMapping defines how to issue a specific credential type
// Protocol-agnostic - credential type is the identifier, not tied to SAML
type CredentialMapping struct {
	CredentialType     string                       // Credential type identifier (e.g., "pid")
	CredentialConfigID string                       // OpenID4VCI credential configuration ID
	Attributes         map[string]*AttributeMapping // Attribute identifier → AttributeMapping
	DefaultIdP         string                       // Optional default IdP
}

// ClaimTransformer transforms external attributes into credential claims
// Protocol-agnostic - works for SAML, OIDC, or other attribute sources
type ClaimTransformer struct {
	mappings map[string]*CredentialMapping // credential type → mapping
}

// NewClaimTransformer creates a new claim transformer from a map of credential mappings
func NewClaimTransformer(mappings map[string]*CredentialMapping) *ClaimTransformer {
	return &ClaimTransformer{
		mappings: mappings,
	}
}

// GetMapping returns the credential mapping for a credential type
func (t *ClaimTransformer) GetMapping(credentialType string) (*CredentialMapping, error) {
	mapping, exists := t.mappings[credentialType]
	if !exists {
		return nil, fmt.Errorf("unknown credential type: %s", credentialType)
	}
	return mapping, nil
}

// TransformClaims converts external attributes to a generic document structure
// Protocol-agnostic - attributes can come from SAML, OIDC, or other sources
func (t *ClaimTransformer) TransformClaims(
	credentialType string,
	attributes map[string]any,
) (map[string]any, error) {
	mapping, err := t.GetMapping(credentialType)
	if err != nil {
		return nil, err
	}

	// Build nested document structure using dot notation
	doc := make(map[string]any)

	for oid, attrMapping := range mapping.Attributes {
		value, exists := attributes[oid]

		if !exists {
			if attrMapping.Required {
				return nil, fmt.Errorf("missing required attribute: %s (claim: %s)", oid, attrMapping.Claim)
			}
			if attrMapping.Default != "" {
				value = attrMapping.Default
			} else {
				continue
			}
		}

		// Apply transformations
		value = applyTransform(value, attrMapping.Transform)

		// Set value in document using dot-notation path
		if err := setNestedValue(doc, attrMapping.Claim, value); err != nil {
			return nil, fmt.Errorf("failed to set claim %s: %w", attrMapping.Claim, err)
		}
	}

	return doc, nil
}

// applyTransform applies a transformation to a value
func applyTransform(value any, transform string) any {
	if transform == "" {
		return value
	}

	// Only apply transformations to strings
	str, ok := value.(string)
	if !ok {
		return value
	}

	switch transform {
	case "lowercase":
		return strings.ToLower(str)
	case "uppercase":
		return strings.ToUpper(str)
	case "trim":
		return strings.TrimSpace(str)
	default:
		return value
	}
}

// setNestedValue sets a value in a map using dot-notation path
// Example: "identity.family_name" creates map[identity][family_name] = value
func setNestedValue(doc map[string]any, path string, value any) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}

	// Split path by dots
	parts := strings.Split(path, ".")

	// Simple case: no nesting
	if len(parts) == 1 {
		doc[path] = value
		return nil
	}

	// Navigate/create nested structure
	current := doc
	for i := 0; i < len(parts)-1; i++ {
		key := parts[i]

		// Check if key exists
		next, exists := current[key]
		if !exists {
			// Create new map
			newMap := make(map[string]any)
			current[key] = newMap
			current = newMap
		} else {
			// Key exists - ensure it's a map
			nextMap, ok := next.(map[string]any)
			if !ok {
				return fmt.Errorf("path conflict: %s is not a map", strings.Join(parts[:i+1], "."))
			}
			current = nextMap
		}
	}

	// Set final value
	finalKey := parts[len(parts)-1]
	current[finalKey] = value
	return nil
}

// getNestedValue retrieves a value from a map using dot-notation path
// Used for validation/testing
func getNestedValue(doc map[string]any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}

	parts := strings.Split(path, ".")

	// Simple case: no nesting
	if len(parts) == 1 {
		val, exists := doc[path]
		return val, exists
	}

	// Navigate nested structure
	current := doc
	for i := 0; i < len(parts)-1; i++ {
		key := parts[i]
		next, exists := current[key]
		if !exists {
			return nil, false
		}

		nextMap, ok := next.(map[string]any)
		if !ok {
			return nil, false
		}
		current = nextMap
	}

	// Get final value
	finalKey := parts[len(parts)-1]
	val, exists := current[finalKey]
	return val, exists
}
