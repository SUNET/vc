package legacyclaims

import (
	"strings"

	"github.com/SUNET/vc/pkg/claimpath"
	"github.com/SUNET/vc/pkg/openid4vp"
)

// Presented returns the reading of main's dotted names of the claims of a
// presented credential of format: MDocQualified for an mdoc, Nested
// otherwise.
func Presented(format string) Shape {
	if openid4vp.IsMdocFormat(format) || openid4vp.IsMdocZkFormat(format) {
		return MDocQualified()
	}
	return Nested()
}

// PresentedClaim reads main's dotted name of a claim of a presented
// credential of format.
func PresentedClaim(format, name string) (claimpath.Pointer, error) {
	return Presented(format).Dotted(name)
}

// PresentedName returns main's dotted name of the claim p of a presented
// credential of format: the name PresentedClaim reads as p. It reports
// false for a pointer no dotted name reads as, such as one with a key
// that holds a dot.
func PresentedName(format string, p claimpath.Pointer) (string, bool) {
	keys, ok := p.KeyNames()
	if !ok {
		return "", false
	}
	name := strings.Join(keys, ".")
	read, err := PresentedClaim(format, name)
	if err != nil || !read.Equal(p) {
		return "", false
	}
	return name, true
}
