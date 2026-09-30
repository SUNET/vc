package openid4vp

import (
	"slices"
	"testing"
)

// TestExpandedTypes_RejectsRelativeIRIWithAColon pins that this path uses
// the STRICT absolute-IRI test, not `strings.Contains(iri, ":")`.
//
// A term the credential's context does not define survives expansion as a
// relative IRI. Some of those contain a colon - "/relative:Type" is the
// example - so the loose test admitted exactly the values meta.type_values
// must never contain, letting a query be satisfied by string coincidence.
func TestExpandedTypes_RejectsRelativeIRIWithAColon(t *testing.T) {
	// A credential whose @context defines nothing, so every custom term
	// stays relative after expansion. The base context is what makes the
	// document expandable at all.
	credMap := map[string]any{
		"@context": []any{"https://www.w3.org/ns/credentials/v2"},
		// "/relative:Type" is an IRI-shaped string no context defines, so
		// expansion keeps it verbatim - relative, and carrying a colon.
		// That is precisely the value strings.Contains(iri, ":") admits.
		"type":   []any{"VerifiableCredential", "/relative:Type"},
		"id":     "urn:uuid:11111111-2222-3333-4444-555555555555",
		"issuer": "https://issuer.example.com",
		"credentialSubject": map[string]any{
			"id": "did:example:holder",
		},
	}

	got, err := expandedTypes(credMap)
	if err != nil {
		t.Fatalf("expandedTypes: %v", err)
	}

	for _, iri := range got {
		if !isAbsoluteForTest(iri) {
			t.Fatalf("expandedTypes returned the relative IRI %q; only absolute IRIs may satisfy a type constraint (got %v)", iri, got)
		}
	}
	// The base type is defined by the core context, so it must survive as
	// an absolute IRI - otherwise this test would pass on an empty result.
	if !slices.ContainsFunc(got, func(s string) bool { return isAbsoluteForTest(s) }) {
		t.Fatalf("expected at least the expanded VerifiableCredential IRI, got %v", got)
	}
}

// isAbsoluteForTest is the strict rule, restated here so the test does not
// simply call the same helper the code under test uses.
func isAbsoluteForTest(s string) bool {
	for i := range len(s) {
		switch s[i] {
		case ':':
			return i > 0
		case '/', '#', '?':
			return false
		}
	}
	return false
}
