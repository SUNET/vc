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

// TestFindProofNodeWithValue_SelectsTheNamedProof: a presentation holds the
// holder's proof and the embedded credential's issuer proof, and both land
// in the same proof object. The caller reads which one it means off the
// document's root and names it by proofValue, because traversal order is
// not a choice.
func TestFindProofNodeWithValue_SelectsTheNamedProof(t *testing.T) {
	doc := presentationProofObject()

	// The fixture is only worth anything if an unqualified search really
	// does reach the wrong proof.
	if got := FindProofNode(doc, "DataIntegrityProof"); got["proofValue"] != "z-issuer-proof" {
		t.Fatalf("fixture no longer exercises the ambiguity: unqualified search returned %v", got["proofValue"])
	}

	got := FindProofNodeWithValue(doc, "DataIntegrityProof", []string{"z-holder-proof"})
	if got == nil {
		t.Fatal("the named proof was not found")
	}
	if got["proofValue"] != "z-holder-proof" {
		t.Fatalf("selected %v, want the named proof", got["proofValue"])
	}
	if got["proofPurpose"] != "authentication" {
		t.Fatalf("selected a proof with purpose %v", got["proofPurpose"])
	}

	// The other one is addressable too, so the selection is by name rather
	// than by a rule that happens to prefer authentication proofs.
	got = FindProofNodeWithValue(doc, "DataIntegrityProof", []string{"z-issuer-proof"})
	if got == nil || got["proofValue"] != "z-issuer-proof" {
		t.Fatal("the issuer's proof must also be addressable by name")
	}
}

// TestFindProofNodeWithValue_RefusesWhatIsNotThere: a proofValue the
// document does not contain must not silently resolve to another proof, and
// naming nothing must not resolve to the first one.
func TestFindProofNodeWithValue_RefusesWhatIsNotThere(t *testing.T) {
	doc := presentationProofObject()

	if got := FindProofNodeWithValue(doc, "DataIntegrityProof", []string{"z-nope"}); got != nil {
		t.Fatalf("a proof that is not present must not resolve to another, got %v", got["proofValue"])
	}
	if got := FindProofNodeWithValue(doc, "DataIntegrityProof", nil); got != nil {
		t.Fatalf("naming no proof must not resolve to the first one, got %v", got["proofValue"])
	}
}
