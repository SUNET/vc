//go:build oidcrp

package oidcrp

import (
	"fmt"
	"strings"

	"vc/pkg/model"
)

// ClaimTransformer transforms OIDC claims into credential claims
type ClaimTransformer struct {
	Mappings map[string]model.CredentialMapping // credential type → mapping
}

// NewClaimTransformer creates a new claim transformer from a map of credential mappings
func NewClaimTransformer(mappings map[string]model.CredentialMapping) *ClaimTransformer {
	return &ClaimTransformer{
		Mappings: mappings,
	}
}

// GetMapping returns the credential mapping for a credential type
func (t *ClaimTransformer) GetMapping(credentialType string) (*model.CredentialMapping, error) {
	mapping, exists := t.Mappings[credentialType]
	if !exists {
		return nil, fmt.Errorf("unknown credential type: %s", credentialType)
	}
	return &mapping, nil
}

// TransformClaims converts OIDC claims to a generic document structure
func (t *ClaimTransformer) TransformClaims(
	credentialType string,
	claims map[string]any,
) (map[string]any, error) {
	mapping, err := t.GetMapping(credentialType)
	if err != nil {
		return nil, err
	}

	// Build nested document structure using dot notation
	doc := make(map[string]any)

	for claimName, attrMapping := range mapping.Attributes {
		value, exists := claims[claimName]

		if !exists {
			if attrMapping.Required {
				return nil, fmt.Errorf("missing required claim: %s (target: %s)", claimName, attrMapping.Claim)
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
	current[parts[len(parts)-1]] = value
	return nil
}
