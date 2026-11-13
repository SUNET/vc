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
	for line := range strings.SplitSeq(nquads, "\n") {
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

func namedGraphCount(t *testing.T, doc string) int {
	t.Helper()
	cred, err := NewRDFCredentialFromJSON([]byte(doc), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cred.NormalizeVerifiableCredentialGraph(); err != nil {
		t.Fatal(err)
	}
	return len(cred.dataset.Graphs) - 1
}

// TestNormalizeFollowsTheActiveContext: the credential term is found by what it means, not
// by how the document spells it.
func TestNormalizeFollowsTheActiveContext(t *testing.T) {
	const embedded = `{"@context":"https://www.w3.org/ns/credentials/v2","type":"VerifiableCredential","issuer":"did:example:i","credentialSubject":{"id":"did:example:s"}}`
	plain := `{"@context":"https://www.w3.org/ns/credentials/v2","type":"VerifiablePresentation","verifiableCredential":` + embedded + `}`
	aliased := `{"@context":["https://www.w3.org/ns/credentials/v2",{"vcs":{"@id":"https://www.w3.org/2018/credentials#verifiableCredential","@type":"@id","@container":"@graph","@context":null}}],"type":"VerifiablePresentation","vcs":` + embedded + `}`

	if got := namedGraphCount(t, plain); got != 1 {
		t.Fatalf("plain term: want 1 named graph, got %d", got)
	}
	if got := namedGraphCount(t, aliased); got != 1 {
		t.Errorf("aliased term: want 1 named graph, got %d", got)
	}
}

// requireNormalizeLeavesAlone fails the test when normalizing the document's embedded
// credential graphs changes its dataset, and returns the credential for further checks.
func requireNormalizeLeavesAlone(t *testing.T, doc, message string) *RDFCredential {
	t.Helper()
	cred, err := NewRDFCredentialFromJSON([]byte(doc), nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := cred.NQuads()
	if err != nil {
		t.Fatal(err)
	}
	if err := cred.NormalizeVerifiableCredentialGraph(); err != nil {
		t.Fatal(err)
	}
	after, err := cred.NQuads()
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Errorf("%s:\n--- before ---\n%s\n--- after ---\n%s", message, before, after)
	}
	return cred
}

// TestNormalizeLeavesJSONLiteralsAlone: a JSON literal that happens to hold a
// verifiableCredential property is signed data, not a credential.
func TestNormalizeLeavesJSONLiteralsAlone(t *testing.T) {
	doc := `{"@context":"https://www.w3.org/ns/credentials/v2","type":"VerifiableCredential","issuer":"did:example:i",
	"credentialSubject":{"id":"did:example:s"},
	"credentialSchema":{"id":"https://example.org/schema","type":"JsonSchema","jsonSchema":{"properties":{"verifiableCredential":{"type":"object","id":"urn:x"}}}}}`
	requireNormalizeLeavesAlone(t, doc, "a JSON literal was rewritten")
}

// TestNormalizeLeavesAppliedContainersAlone: the VC v1 context makes json-gold put the
// credential in its graph itself, so wrapping it again would change the dataset.
func TestNormalizeLeavesAppliedContainersAlone(t *testing.T) {
	doc := `{"@context":"https://www.w3.org/2018/credentials/v1","type":"VerifiablePresentation","verifiableCredential":{"@context":"https://www.w3.org/2018/credentials/v1","type":"VerifiableCredential","issuer":"did:example:i","credentialSubject":{"id":"did:example:s"}}}`
	cred := requireNormalizeLeavesAlone(t, doc, "a v1 presentation changed")
	if got := len(cred.dataset.Graphs) - 1; got != 1 {
		t.Errorf("want 1 named graph, got %d", got)
	}
}
