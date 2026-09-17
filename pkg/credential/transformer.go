package credential

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

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

		transformed, terr := applyTransformOrError(value, attrCfg.Transform)
		if terr != nil {
			if attrCfg.Required {
				return nil, fmt.Errorf("failed to transform required attribute %s (claim: %s): %w", attrID, attrCfg.Claim, terr)
			}
			continue
		}
		value = transformed

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

// ApplyTransform applies a named transformation to a value.
func ApplyTransform(value any, transform string) any {
	v, _ := applyTransformOrError(value, transform)
	return v
}

// applyTransformOrError is the error-returning form used by TransformClaims
// so that invalid inputs to a validating transform (currently
// yyyymmdd_to_iso) can reject required claims or be skipped for optional
// ones, instead of silently passing an invalid value into the credential.
func applyTransformOrError(value any, transform string) (any, error) {
	if transform == "" {
		return value, nil
	}

	// Apply per element for slice-typed inputs (multi-valued SAML attrs) so
	// e.g. country_alpha2 maps each nationality individually.
	if slice, ok := value.([]string); ok {
		out := make([]string, 0, len(slice))
		for _, item := range slice {
			transformed, err := applyTransformOrError(item, transform)
			if err != nil {
				return value, err
			}
			s, ok := transformed.(string)
			if !ok {
				s = item
			}
			out = append(out, s)
		}
		return out, nil
	}

	str, ok := value.(string)
	if !ok {
		return value, nil
	}

	switch transform {
	case "lowercase":
		return strings.ToLower(str), nil
	case "uppercase":
		return strings.ToUpper(str), nil
	case "trim":
		return strings.TrimSpace(str), nil
	case "country_alpha2":
		cc := countries.ByName(str)
		if cc == countries.Unknown {
			return value, nil
		}
		return cc.Alpha2(), nil
	case "country_alpha3":
		cc := countries.ByName(str)
		if cc == countries.Unknown {
			return value, nil
		}
		return cc.Alpha3(), nil
	case "yyyymmdd_to_iso":
		// SCHAC schacDateOfBirth is "YYYYMMDD"; SD-JWT VC birthdate is ISO "YYYY-MM-DD".
		// time.Parse validates day-of-month, so impossible dates like 20240230
		// surface as an error instead of being emitted verbatim.
		t, err := time.Parse("20060102", str)
		if err != nil {
			return value, fmt.Errorf("invalid YYYYMMDD date %q: %w", str, err)
		}
		return t.Format("2006-01-02"), nil
	default:
		return value, nil
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
