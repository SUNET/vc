package model

import "time"

// IdentityMapping represents an identity stored in the "identity_mappings" collection.
// Documents reference these by AuthenticSourcePersonID in their IdentityMappingIDs []string field.
type IdentityMapping struct {
	// AuthenticSourcePersonID is the unique identifier for this entity within the authentic source
	AuthenticSourcePersonID string `json:"authentic_source_person_id" bson:"authentic_source_person_id" validate:"required,max=128,printascii"`

	// AuthenticSource is the source system that owns this identity
	AuthenticSource string `json:"authentic_source" bson:"authentic_source" validate:"required,max=128,printascii"`

	// Attributes holds identity attributes used for resolution (e.g. family_name, given_name, birth_date)
	Attributes map[string]string `json:"attributes,omitempty" bson:"attributes" validate:"omitempty,dive,keys,safe_key,endkeys"`

	// CreatedAt is the timestamp when the mapping was created
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
}
