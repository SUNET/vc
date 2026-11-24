package openid4vp

import "github.com/SUNET/vc/pkg/claimpath"

// PresentedShape returns how the verified claims of a presented credential
// of the format are held: an mdoc as one "<namespace>.<element>" key per
// data element, a JSON-based credential as its JSON object.
func PresentedShape(format string) claimpath.Shape {
	if IsMdocFormat(format) || IsMdocZkFormat(format) {
		return claimpath.MDocQualified()
	}
	return claimpath.Nested()
}
