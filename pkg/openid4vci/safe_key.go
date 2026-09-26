package openid4vci

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

// safeKeyRe accepts a simple alphanumeric/underscore key starting with a
// letter, at most 64 characters. Map keys carrying these values reach
// MongoDB field paths, so a dot or a "$" operator prefix would be
// field-path injection.
var safeKeyRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)

// RegisterSafeKey registers the "safe_key" validation on v.
//
// This lives here, in the package furthest down the import graph, because
// every validator that touches a struct tagged safe_key has to register it
// or panic - go-playground/validator resolves the tag chain when it first
// parses the struct, before omitempty is evaluated, so an unregistered tag
// panics even for an absent field. PARRequest.DynamicParams made that
// concrete: it is tagged safe_key here, and this package cannot import
// pkg/helpers where the tag was registered, since pkg/helpers imports this
// one.
//
// pkg/helpers and pkg/cache call this rather than keeping their own copies.
// They each build a validator with different tag-name resolution, which is
// why they construct separately, but the pattern itself is one definition -
// three copies of a field-path injection guard is three chances to widen
// one of them.
func RegisterSafeKey(v *validator.Validate) error {
	return v.RegisterValidation("safe_key", func(fl validator.FieldLevel) bool {
		return safeKeyRe.MatchString(fl.Field().String())
	})
}
