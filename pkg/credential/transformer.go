package credential

import (
	"fmt"
	"strings"

	"github.com/SUNET/vc/pkg/model"
	"github.com/biter777/countries"
)

// ClaimTransformer transforms external attributes/claims into credential document structures.
// Protocol-agnostic — works for SAML OIDs, OIDC claim names, or any other attribute source.
type ClaimTransformer struct {
	mapping model.AttributeMapping
}

// NewClaimTransformer creates a new claim transformer from an attribute mapping.
func NewClaimTransformer(mapping model.AttributeMapping) *ClaimTransformer {
	return &ClaimTransformer{
		mapping: mapping,
	}
}

// TransformClaims converts external attributes (keyed by protocol-specific identifiers)
// to a generic document structure using the configured mapping.
func (t *ClaimTransformer) TransformClaims(
	attributes map[string]any,
) (map[string]any, error) {
	doc := make(map[string]any)

	for attrID, attrCfg := range t.mapping {
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

		if attrCfg.AsArray {
			value = wrapAsArray(value)
		}

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
	case "country_alpha2":
		cc := countries.ByName(str)
		if cc == countries.Unknown {
			return value
		}
		return cc.Alpha2()
	case "country_alpha3":
		cc := countries.ByName(str)
		if cc == countries.Unknown {
			return value
		}
		return cc.Alpha3()
	default:
		return value
	}
}

// wrapAsArray wraps a scalar string value in a single-element []string.
// Any non-string value (including slices of any element type) is returned unchanged.
func wrapAsArray(value any) any {
	switch v := value.(type) {
	case string:
		return []string{v}
	default:
		return v
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
