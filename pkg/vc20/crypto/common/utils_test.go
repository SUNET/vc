package common

import (
	"testing"
)

func TestHasType_SingleString(t *testing.T) {
	m := map[string]any{
		"type": "VerifiableCredential",
	}

	if !HasType(m, "VerifiableCredential") {
		t.Error("expected to find type VerifiableCredential")
	}

	if HasType(m, "VerifiablePresentation") {
		t.Error("should not find type VerifiablePresentation")
	}
}

func TestHasType_StringArray(t *testing.T) {
	m := map[string]any{
		"type": []any{"VerifiableCredential", "UniversityDegreeCredential"},
	}

	if !HasType(m, "VerifiableCredential") {
		t.Error("expected to find type VerifiableCredential")
	}

	if !HasType(m, "UniversityDegreeCredential") {
		t.Error("expected to find type UniversityDegreeCredential")
	}

	if HasType(m, "VerifiablePresentation") {
		t.Error("should not find type VerifiablePresentation")
	}
}

func TestHasType_AtType(t *testing.T) {
	m := map[string]any{
		"@type": "DataIntegrityProof",
	}

	if !HasType(m, "DataIntegrityProof") {
		t.Error("expected to find @type DataIntegrityProof")
	}
}

func TestHasType_NoType(t *testing.T) {
	m := map[string]any{
		"id": "http://example.com/credential",
	}

	if HasType(m, "VerifiableCredential") {
		t.Error("should not find type when type is missing")
	}
}

func TestFindProofNode_Direct(t *testing.T) {
	data := map[string]any{
		"type":         "DataIntegrityProof",
		"proofValue":   "test",
		"cryptosuite":  "ecdsa-rdfc-2019",
		"proofPurpose": "assertionMethod",
	}

	found := FindProofNode(data, "DataIntegrityProof")
	if found == nil {
		t.Fatal("expected to find proof node")
	}

	if found["proofValue"] != "test" {
		t.Error("proofValue mismatch")
	}
}

func TestFindProofNode_Nested(t *testing.T) {
	data := map[string]any{
		"id": "http://example.com/credential",
		"proof": map[string]any{
			"type":         "DataIntegrityProof",
			"proofValue":   "nested_test",
			"cryptosuite":  "ecdsa-rdfc-2019",
			"proofPurpose": "assertionMethod",
		},
	}

	found := FindProofNode(data, "DataIntegrityProof")
	if found == nil {
		t.Fatal("expected to find nested proof node")
	}

	if found["proofValue"] != "nested_test" {
		t.Error("proofValue mismatch")
	}
}

func TestFindProofNode_InArray(t *testing.T) {
	data := map[string]any{
		"id": "http://example.com/credential",
		"proof": []any{
			map[string]any{
				"type":         "DataIntegrityProof",
				"proofValue":   "array_test",
				"cryptosuite":  "ecdsa-rdfc-2019",
				"proofPurpose": "assertionMethod",
			},
		},
	}

	found := FindProofNode(data, "DataIntegrityProof")
	if found == nil {
		t.Fatal("expected to find proof node in array")
	}

	if found["proofValue"] != "array_test" {
		t.Error("proofValue mismatch")
	}
}

func TestFindProofNode_GenericProof(t *testing.T) {
	// Test that "Proof" type is also found
	data := map[string]any{
		"type":       "Proof",
		"proofValue": "generic_proof",
	}

	found := FindProofNode(data, "SomeOtherType")
	if found == nil {
		t.Fatal("expected to find generic Proof node")
	}

	if found["proofValue"] != "generic_proof" {
		t.Error("proofValue mismatch")
	}
}

func TestFindProofNode_NotFound(t *testing.T) {
	data := map[string]any{
		"id":   "http://example.com/credential",
		"type": "VerifiableCredential",
	}

	found := FindProofNode(data, "DataIntegrityProof")
	if found != nil {
		t.Error("expected nil when proof not found")
	}
}

func TestFindProofNode_NilData(t *testing.T) {
	found := FindProofNode(nil, "DataIntegrityProof")
	if found != nil {
		t.Error("expected nil for nil data")
	}
}

func TestFindProofNode_ArrayOfArrays(t *testing.T) {
	data := []any{
		[]any{
			map[string]any{
				"type":       "DataIntegrityProof",
				"proofValue": "deep_nested",
			},
		},
	}

	found := FindProofNode(data, "DataIntegrityProof")
	if found == nil {
		t.Fatal("expected to find deeply nested proof node")
	}

	if found["proofValue"] != "deep_nested" {
		t.Error("proofValue mismatch")
	}
}

// presentationProofObject is the shape a compacted proof object really has
// for a presentation carrying a signed credential: named graphs holding one
// proof each, and nodes linking to them. Taken from a real VPBuilder
// document, with the ISSUER's graph placed first so that an unqualified
// search reaches the wrong proof - which is the accident this function
// exists to stop relying on.
func presentationProofObject() map[string]any {
	return map[string]any{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"@graph": []any{
			map[string]any{
				"id": "_:b3",
				"@graph": []any{map[string]any{
					"id": "_:b4", "type": "DataIntegrityProof",
					"proofPurpose": "assertionMethod", "proofValue": "z-issuer-proof",
				}},
			},
			map[string]any{"id": "_:b2", "https://w3id.org/security#proof": map[string]any{"id": "_:b3"}},
			map[string]any{
				"id": "_:b0",
				"@graph": []any{map[string]any{
					"id": "_:b1", "type": "DataIntegrityProof",
					"proofPurpose": "authentication", "proofValue": "z-holder-proof",
				}},
			},
			map[string]any{"id": "urn:uuid:the-presentation", "https://w3id.org/security#proof": map[string]any{"id": "_:b0"}},
		},
	}
}

// TestFindRootProofNode_SelectsTheDocumentsOwnProof: a presentation holds
// the holder's proof and the embedded credential's issuer proof, and both
// land in the same proof object. Taking the first one found is an accident
// of graph ordering, and verifying the issuer's proofValue with the holder's
// key fails a presentation that is perfectly good.
func TestFindRootProofNode_SelectsTheDocumentsOwnProof(t *testing.T) {
	doc := presentationProofObject()

	// The fixture is only worth anything if the unqualified search really
	// does reach the wrong proof here.
	if got := FindProofNode(doc, "DataIntegrityProof"); got["proofValue"] != "z-issuer-proof" {
		t.Fatalf("fixture no longer exercises the ambiguity: unqualified search returned %v", got["proofValue"])
	}

	got := FindRootProofNode(doc, "DataIntegrityProof", "urn:uuid:the-presentation")
	if got == nil {
		t.Fatal("the root's own proof was not found")
	}
	if got["proofValue"] != "z-holder-proof" {
		t.Fatalf("selected %v, want the presentation's own proof", got["proofValue"])
	}
	if got["proofPurpose"] != "authentication" {
		t.Fatalf("selected a proof with purpose %v, want the presentation's", got["proofPurpose"])
	}
}

// TestFindRootProofNode_FallsBackWhenUnresolvable: a document with no id,
// or one whose graph does not name it, cannot be resolved this way - and is
// also a document with nothing to be ambiguous about. Returning nil lets the
// caller fall back rather than refusing a single-proof document.
func TestFindRootProofNode_FallsBackWhenUnresolvable(t *testing.T) {
	doc := presentationProofObject()

	for name, rootID := range map[string]string{
		"no id at all":           "",
		"an id not in the graph": "urn:uuid:something-else",
	} {
		t.Run(name, func(t *testing.T) {
			if got := FindRootProofNode(doc, "DataIntegrityProof", rootID); got != nil {
				t.Fatalf("want nil so the caller can fall back, got %v", got["proofValue"])
			}
		})
	}

	// A root that names no proof at all, and a proof object that is not a
	// graph, are both "cannot tell" rather than "the first one".
	if got := FindRootProofNode(map[string]any{"@graph": []any{
		map[string]any{"id": "urn:uuid:x"},
	}}, "DataIntegrityProof", "urn:uuid:x"); got != nil {
		t.Fatal("a root naming no proof must not resolve to another node's")
	}
	if got := FindRootProofNode([]any{}, "DataIntegrityProof", "urn:uuid:x"); got != nil {
		t.Fatal("a proof object that is not a graph must not resolve")
	}
}
