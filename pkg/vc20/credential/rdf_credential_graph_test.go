package credential

import (
	"encoding/json"
	"strings"
	"testing"
)

func presentationWithOneCredential(t *testing.T) *RDFCredential {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"id":       "urn:vp:1",
		"type":     "VerifiablePresentation",
		"holder":   "did:example:holder",
		"verifiableCredential": map[string]any{
			"@context":          "https://www.w3.org/ns/credentials/v2",
			"id":                "urn:vc:a",
			"type":              "VerifiableCredential",
			"issuer":            map[string]any{"id": "did:web:issuer.example", "name": "Issuer"},
			"validFrom":         "2024-01-01T00:00:00Z",
			"credentialSubject": map[string]any{"id": "did:example:holder"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := NewRDFCredentialFromJSON(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

// TestCredentialWithoutProofIsIdempotent: the first pass leaves the document in expanded
// form, where the presentation's verifiableCredential value is a reference to a graph
// defined elsewhere ({"@id": "_:b0"}), not a credential to be put in a graph. Wrapping
// that reference again built a second, empty graph and moved the presentation's link to
// it - which left the document unconvertible, so this failed outright rather than
// quietly.
func TestCredentialWithoutProofIsIdempotent(t *testing.T) {
	first, err := presentationWithOneCredential(t).CredentialWithoutProof()
	if err != nil {
		t.Fatal(err)
	}
	once, err := first.CanonicalForm()
	if err != nil {
		t.Fatal(err)
	}
	second, err := first.CredentialWithoutProof()
	if err != nil {
		t.Fatalf("removing proofs a second time must work: %v", err)
	}
	twice, err := second.CanonicalForm()
	if err != nil {
		t.Fatal(err)
	}
	if once != twice {
		t.Errorf("removing proofs twice changed the canonical document:\n--- once ---\n%s\n--- twice ---\n%s", once, twice)
	}
}

// TestCredentialGraphsHoldTheirOwnDescriptions: a node two credentials describe is
// described in both their graphs, because that is what the document says. The traversal
// this replaced could only put it in one of them.
func TestCredentialGraphsHoldTheirOwnDescriptions(t *testing.T) {
	credentialNamed := func(id, validFrom string) map[string]any {
		return map[string]any{
			"@context":          "https://www.w3.org/ns/credentials/v2",
			"id":                id,
			"type":              "VerifiableCredential",
			"issuer":            map[string]any{"id": "did:web:issuer.example", "name": "Shared Issuer"},
			"validFrom":         validFrom,
			"credentialSubject": map[string]any{"id": "did:example:holder"},
		}
	}
	raw, err := json.Marshal(map[string]any{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"id":       "urn:vp:1",
		"type":     "VerifiablePresentation",
		"holder":   map[string]any{"id": "did:example:holder", "name": "The Holder"},
		"verifiableCredential": []any{
			credentialNamed("urn:vc:a", "2024-01-01T00:00:00Z"),
			credentialNamed("urn:vc:b", "2024-02-01T00:00:00Z"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := NewRDFCredentialFromJSON(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	withoutProof, err := cred.CredentialWithoutProof()
	if err != nil {
		t.Fatal(err)
	}
	nquads, err := withoutProof.CanonicalForm()
	if err != nil {
		t.Fatal(err)
	}

	issuerName := 0
	holderNameInDefaultGraph := 0
	for _, line := range strings.Split(nquads, "\n") {
		if !strings.Contains(line, `<https://schema.org/name>`) {
			continue
		}
		switch {
		case strings.Contains(line, `<did:web:issuer.example>`):
			issuerName++
		case strings.Contains(line, `"The Holder"`) && !strings.Contains(line, ` _:`):
			holderNameInDefaultGraph++
		}
	}
	if issuerName != 2 {
		t.Errorf("the issuer both credentials describe must be described in both graphs, found %d:\n%s", issuerName, nquads)
	}
	if holderNameInDefaultGraph != 1 {
		t.Errorf("the presentation's own description of its holder belongs to the default graph, found %d:\n%s", holderNameInDefaultGraph, nquads)
	}
}
