package credential

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsAbsoluteIRI pins the rule this helper replaced
// `strings.Contains(s, ":")` with, and the narrower mistake inside it.
//
// expandedTypes uses it to drop terms no context defines, so anything it
// wrongly calls absolute survives expansion unchanged and can then satisfy a
// meta.type_values constraint by string coincidence. "Nonempty before the
// colon" is not the test: RFC 3986 section 3.1 spells a scheme
// ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
func TestIsAbsoluteIRI(t *testing.T) {
	for _, iri := range []string{
		"https://example.org/Type",
		"urn:example:Type",
		"did:example:123#key-1",
		"a:b",
		"x+y-z.1:Type",
		"HTTPS://EXAMPLE.ORG/Type",
	} {
		assert.True(t, IsAbsoluteIRI(iri), "%q is an absolute IRI", iri)
	}

	for _, relative := range []string{
		"",
		"Type",
		":Type",
		"/relative:Type",
		"path/to:thing",
		"#fragment:thing",
		"?query:thing",
		// A scheme may not start with a digit, and "_" is not a scheme
		// character at all - both merely contain a colon.
		"1:Type",
		"foo_bar:Type",
		"a b:Type",
		"a%b:Type",
	} {
		assert.False(t, IsAbsoluteIRI(relative), "%q is not an absolute IRI", relative)
	}
}
