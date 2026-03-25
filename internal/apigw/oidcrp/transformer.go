package oidcrp

import (
	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/model"
)

// ClaimTransformer transforms OIDC claims into credential claims.
// Delegates to the shared credential.ClaimTransformer.
type ClaimTransformer = credential.ClaimTransformer

// NewClaimTransformer creates a new claim transformer from credential mappings.
func NewClaimTransformer(mappings map[string]model.CredentialMapping) *ClaimTransformer {
	return credential.NewClaimTransformer(mappings)
}
