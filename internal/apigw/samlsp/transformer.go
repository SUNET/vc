package samlsp

import (
	"vc/pkg/credential"
	"vc/pkg/model"
)

// ClaimTransformer transforms SAML attributes into credential claims.
// Delegates to the shared credential.ClaimTransformer.
type ClaimTransformer = credential.ClaimTransformer

// NewClaimTransformer creates a new claim transformer from credential mappings.
func NewClaimTransformer(mappings map[string]model.CredentialMapping) *ClaimTransformer {
	return credential.NewClaimTransformer(mappings)
}
