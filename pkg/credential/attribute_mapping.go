package credential

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/SUNET/vc/pkg/model"
)

// AttributeMapper maps protocol-specific attribute names to canonical claim
// paths using a supplied AttributeMapping. Value normalisation (case folding,
// date reformatting, canonicalisation, etc.) is intentionally NOT the
// mapper's job — those live as derivations in the target scope config.
type AttributeMapper struct {
	mapping model.AttributeMapping
}

// NewAttributeMapper creates a new attribute mapper from an attribute mapping.
func NewAttributeMapper(mapping model.AttributeMapping) *AttributeMapper {
	return &AttributeMapper{
		mapping: mapping,
	}
}

// Apply converts external attributes (keyed by protocol-specific
// identifiers) into a generic claim document. It renames attributes to their
// mapped claim names and honours per-attribute required + default + as_array.
// Data sources are rename-only; value transformation lives in derivations on
// the target scope.
func (t *AttributeMapper) Apply(attributes map[string]any) (map[string]any, error) {
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

		// Multi-valued attribute mapped to a non-array claim: keep the first
		// value and warn so operators can spot IdP release changes.
		if !attrCfg.AsArray {
			if slice, ok := value.([]string); ok {
				if len(slice) > 1 {
					slog.Warn("attribute has multiple values, collapsing to first for non-array claim",
						"attribute", attrID, "claim", attrCfg.Claim, "count", len(slice))
				}
				if len(slice) == 0 {
					continue
				}
				value = slice[0]
			}
		}

		if attrCfg.AsArray {
			value = wrapAsArray(value)
		}

		if err := SetNestedValue(doc, attrCfg.Claim, value); err != nil {
			return nil, fmt.Errorf("failed to set claim %s: %w", attrCfg.Claim, err)
		}
	}

	return doc, nil
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

// MergeDefaults injects default claim values into doc for any claim path
// whose key is not already present, treating each defaults key as a
// dot-notation claim path (matching the AttributeMapping Claim field).
// Existing values — including nested ones — always win. Overlapping default
// paths ("identity" and "identity.country") are rejected because merging
// them is otherwise order-dependent on Go map iteration.
func MergeDefaults(doc, defaults map[string]any) error {
	paths := make([]string, 0, len(defaults))
	for k := range defaults {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for i, p := range paths {
		for _, q := range paths[i+1:] {
			if strings.HasPrefix(q, p+".") {
				return fmt.Errorf("overlapping default paths: %q is a prefix of %q", p, q)
			}
		}
	}

	for _, path := range paths {
		if _, present := GetNestedValue(doc, path); present {
			continue
		}
		if err := SetNestedValue(doc, path, defaults[path]); err != nil {
			return fmt.Errorf("failed to set default %s: %w", path, err)
		}
	}
	return nil
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
