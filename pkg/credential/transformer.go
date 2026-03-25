package credential

import (
	"fmt"
	"strings"

	"github.com/SUNET/vc/pkg/model"
)

// ClaimTransformer transforms external attributes/claims into credential document structures.
// Protocol-agnostic — works for SAML OIDs, OIDC claim names, or any other attribute source.
type ClaimTransformer struct {
	mappings map[string]model.CredentialMapping // credential type → mapping
}

// NewClaimTransformer creates a new claim transformer from credential mappings.
func NewClaimTransformer(mappings map[string]model.CredentialMapping) *ClaimTransformer {
	return &ClaimTransformer{
		mappings: mappings,
	}
}

// GetMapping returns the credential mapping for a credential type.
func (t *ClaimTransformer) GetMapping(credentialType string) (*model.CredentialMapping, error) {
	mapping, exists := t.mappings[credentialType]
	if !exists {
		return nil, fmt.Errorf("unknown credential type: %s", credentialType)
	}
	return &mapping, nil
}

// TransformClaims converts external attributes (keyed by protocol-specific identifiers)
// to a generic document structure using the configured mappings.
func (t *ClaimTransformer) TransformClaims(
	credentialType string,
	attributes map[string]any,
) (map[string]any, error) {
	mapping, err := t.GetMapping(credentialType)
	if err != nil {
		return nil, err
	}

	doc := make(map[string]any)

	for attrID, attrCfg := range mapping.Attributes {
		value, exists := attributes[attrID]

		if !exists {
			if attrCfg.Required {
				return nil, fmt.Errorf("missing required attribute: %s (claim: %s)", attrID, attrCfg.Claim)
			}
			if attrCfg.Default != "" {
				value = attrCfg.Default
			} else {
				continue
			}
		}

		value = ApplyTransform(value, attrCfg.Transform)

		if err := SetNestedValue(doc, attrCfg.Claim, value); err != nil {
			return nil, fmt.Errorf("failed to set claim %s: %w", attrCfg.Claim, err)
		}
	}

	return doc, nil
}

// ApplyTransform applies a named transformation to a value.
func ApplyTransform(value any, transform string) any {
	if transform == "" {
		return value
	}

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

// SetNestedValue sets a value in a map using dot-notation path.
// Example: "identity.family_name" creates map[identity][family_name] = value
func SetNestedValue(doc map[string]any, path string, value any) error {
	if path == "" {
		return fmt.Errorf("empty path")
	}

	parts := strings.Split(path, ".")

	if len(parts) == 1 {
		doc[path] = value
		return nil
	}

	current := doc
	for i := 0; i < len(parts)-1; i++ {
		key := parts[i]

		next, exists := current[key]
		if !exists {
			newMap := make(map[string]any)
			current[key] = newMap
			current = newMap
		} else {
			nextMap, ok := next.(map[string]any)
			if !ok {
				return fmt.Errorf("path conflict: %s is not a map", strings.Join(parts[:i+1], "."))
			}
			current = nextMap
		}
	}

	current[parts[len(parts)-1]] = value
	return nil
}

// GetNestedValue retrieves a value from a map using dot-notation path.
func GetNestedValue(doc map[string]any, path string) (any, bool) {
	if path == "" {
		return nil, false
	}

	parts := strings.Split(path, ".")

	if len(parts) == 1 {
		val, exists := doc[path]
		return val, exists
	}

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

	val, exists := current[parts[len(parts)-1]]
	return val, exists
}
