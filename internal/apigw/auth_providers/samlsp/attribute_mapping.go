package samlsp

import (
	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/credential"
	"github.com/SUNET/vc/pkg/model"
)

// AttributeMapper transforms SAML attributes into credential claims.
// Delegates to the shared credential.AttributeMapper.
type AttributeMapper = credential.AttributeMapper

// NewAttributeMapper creates a new attribute mapper from an attribute
// mapping. The provider's claims are a JSON object.
func NewAttributeMapper(mapping model.AttributeMapping) *AttributeMapper {
	return credential.NewAttributeMapper(mapping, claimpath.Nested())
}
