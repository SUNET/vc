package model

import (
	"fmt"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/openid4vp"
)

// PresentedShape returns how the verified claims of a presented credential
// of this type are held.
func (c *CredentialMetadata) PresentedShape() claimpath.Shape {
	return openid4vp.PresentedShape(c.Format)
}

// DocumentShape returns how the document data of a credential of this type
// holds its claims: an mso_mdoc as one key per data element its MDDL
// declares, and a credential of each other format, whose schema is a VCTM,
// as its JSON object.
func (c *CredentialMetadata) DocumentShape() (claimpath.Shape, error) {
	if !openid4vp.IsMdocFormat(c.Format) {
		return claimpath.Nested(), nil
	}
	mddl := c.GetMDDL()
	if mddl == nil {
		return claimpath.Shape{}, fmt.Errorf("the %s credential has no MDDL to place its claims by", c.Format)
	}
	return claimpath.MDocElements(mddl.Claims), nil
}
