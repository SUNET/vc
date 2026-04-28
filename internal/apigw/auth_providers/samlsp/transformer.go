package samlsp

import (
	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/model"
)

// ClaimTransformer transforms SAML attributes into credential claims.
// Delegates to the shared credential.ClaimTransformer.
type ClaimTransformer = credential.ClaimTransformer

// NewClaimTransformer creates a new claim transformer from an attribute mapping.
func NewClaimTransformer(mapping model.AttributeMapping) *ClaimTransformer {
	return credential.NewClaimTransformer(mapping)
}
