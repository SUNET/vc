package model

import (
	"reflect"
	"strconv"
	"testing"

	"github.com/SUNET/vc/pkg/nymauth"
	"github.com/stretchr/testify/require"
)

// The doc_example is what an operator copies into their configuration,
// so an example the loader would refuse is a configuration reference
// that teaches the wrong value. For verifier_id that is worse than a
// typo: the BARE DNS name was the correct value until 2026-10-20 and
// still reads as plausible, and hashing it yields a pseudonym no other
// implementation reports - a wrong answer about a person rather than an
// error anyone sees.
func TestVerifierIDDocExampleIsItselfAValidVerifierID(t *testing.T) {
	field, found := reflect.TypeOf(NymAuthVerifier{}).FieldByName("VerifierID")
	require.True(t, found, "VerifierID is gone; this guard is reading the wrong field")

	example, err := strconv.Unquote(field.Tag.Get("doc_example"))
	require.NoError(t, err, "doc_example is a quoted YAML scalar")

	require.NoError(t, nymauth.CheckVerifierID(example),
		"the configuration reference's own example would be refused at startup")
}
