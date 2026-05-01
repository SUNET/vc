package model

import "time"

// V2Document is the simplified document model for the v2 datastore API.
type V2Document struct {
	Meta         *V2MetaData    `json:"meta,omitempty" bson:"meta" validate:"required"`
	Identities   []string       `json:"identities,omitempty" bson:"identities" validate:"required,min=1"`
	DocumentData map[string]any `json:"document_data,omitempty" bson:"document_data" validate:"required"`
}

// V2MetaData contains the minimal metadata for a v2 document.
type V2MetaData struct {
	// required: true
	// example: SUNET
	AuthenticSource string `json:"authentic_source,omitempty" bson:"authentic_source" validate:"required,max=128,printascii"`

	// required: true
	// example: "ehic"
	Scope string `json:"scope,omitempty" bson:"scope" validate:"required,max=128,printascii"`

	// required: false (auto-generated if empty)
	// example: 019681a2-...-uuid7
	DocumentID string `json:"document_id,omitempty" bson:"document_id" validate:"omitempty,max=128,printascii"`

	// required: false
	// format: int64
	CredentialValidFrom *int64 `json:"credential_valid_from,omitempty" bson:"credential_valid_from,omitempty"`

	// required: false
	// format: int64
	CredentialValidTo *int64 `json:"credential_valid_to,omitempty" bson:"credential_valid_to,omitempty"`

	// required: false
	Revocation *Revocation `json:"revocation,omitempty" bson:"revocation,omitempty"`
}

// IdentityMapping maps arbitrary key-value attributes to a unique identifier,
// scoped per authentic source.
type IdentityMapping struct {
	// required: true
	AuthenticSource string `json:"authentic_source" bson:"authentic_source" validate:"required,max=128,printascii"`

	// Unique identifier for this individual/entity within the authentic source.
	// Auto-generated (UUIDv7) if not provided on creation.
	Identifier string `json:"identifier" bson:"identifier" validate:"omitempty,max=128,printascii"`

	// Arbitrary key-value attributes for identity resolution (e.g. {"ssn": "010101-0101"}).
	Attributes map[string]string `json:"attributes" bson:"attributes" validate:"required,min=1"`

	CreatedAt time.Time `json:"created_at" bson:"created_at"`
}
