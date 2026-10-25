package credential

import (
	"fmt"
	"log/slog"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/model"
)

// AttributeMapper maps protocol-specific attribute names to canonical claims
// using a supplied AttributeMapping. Value normalisation (case folding,
// date reformatting, canonicalisation, etc.) is intentionally NOT the
// mapper's job — those live as derivations in the target scope config.
type AttributeMapper struct {
	mapping model.AttributeMapping
	shape   claimpath.Shape
}

// NewAttributeMapper creates a new attribute mapper from an attribute
// mapping, writing claims into a document of the given shape.
func NewAttributeMapper(mapping model.AttributeMapping, shape claimpath.Shape) *AttributeMapper {
	return &AttributeMapper{
		mapping: mapping,
		shape:   shape,
	}
}

// Apply converts external attributes (keyed by protocol-specific
// identifiers) into a generic claim document. It renames attributes to their
// mapped claims and honours per-attribute required + default + as_array.
// Data sources are rename-only; value transformation lives in derivations on
// the target scope.
func (t *AttributeMapper) Apply(attributes map[string]any) (map[string]any, error) {
	doc := make(map[string]any)

	for attrID, attrCfg := range t.mapping {
		value, ok, err := attributeValue(attrID, attrCfg, attributes)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if err := t.shape.Set(doc, attrCfg.Claim, value); err != nil {
			return nil, fmt.Errorf("failed to set claim %s: %w", attrCfg.Claim, err)
		}
	}

	return doc, nil
}

// attributeValue returns the value an attribute maps to its claim: the
// attribute, or its default, shaped as the claim is configured.
func attributeValue(attrID string, attrCfg model.AttributeConfig, attributes map[string]any) (any, bool, error) {
	value, exists := attributes[attrID]
	if !exists {
		if attrCfg.Required {
			return nil, false, fmt.Errorf("missing required attribute: %s (claim: %s)", attrID, attrCfg.Claim)
		}
		if attrCfg.Default == "" {
			return nil, false, nil
		}
		value = attrCfg.Default
	}

	if attrCfg.AsArray {
		return wrapAsArray(value), true, nil
	}

	// Multi-valued attribute mapped to a non-array claim: keep the first
	// value and warn so operators can spot IdP release changes.
	slice, ok := value.([]string)
	if !ok {
		return value, true, nil
	}
	if len(slice) > 1 {
		slog.Warn("attribute has multiple values, collapsing to first for non-array claim",
			"attribute", attrID, "claim", attrCfg.Claim.String(), "count", len(slice))
	}
	if len(slice) == 0 {
		return nil, false, nil
	}
	return slice[0], true, nil
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
