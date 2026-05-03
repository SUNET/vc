package model

import "maps"

// IdentityMapping represents a person identity stored in the "identities" collection.
// Documents reference these by AuthenticSourcePersonID in their Identities []string field.
type IdentityMapping struct {
	// AuthenticSourcePersonID is the unique identifier for this person within the authentic source
	AuthenticSourcePersonID string `json:"authentic_source_person_id" bson:"authentic_source_person_id" validate:"required,max=128,printascii"`

	// AuthenticSource is the source system that owns this identity
	AuthenticSource string `json:"authentic_source" bson:"authentic_source" validate:"required,max=128,printascii"`

	// Identity holds well-known typed identity attributes for matching.
	// Preferred over Attributes when the fields are known at upload time.
	Identity *Identity `json:"identity,omitempty" bson:"identity,omitempty"`

	// Attributes holds optional untyped identity attributes for resolution.
	// Used as a fallback when typed Identity fields are not available.
	Attributes map[string]any `json:"attributes,omitempty" bson:"attributes"`
}

// ResolutionAttributes returns the effective attributes for identity resolution.
// Typed Identity fields take precedence; remaining keys come from Attributes map.
func (m *IdentityMapping) ResolutionAttributes() map[string]any {
	result := make(map[string]any)

	// Start with untyped attributes
	maps.Copy(result, m.Attributes)

	// Overlay typed fields (precedence)
	if m.Identity != nil {
		maps.Copy(result, m.Identity.ToMap())
	}

	return result
}
