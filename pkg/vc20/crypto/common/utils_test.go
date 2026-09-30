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

// TestFindProofNodeInGraphs_SelectsTheRootsGraph is the selection Verify
// actually uses.
//
// The fixture puts the ISSUER's graph first, so an unrestricted search
// reaches the wrong proof - and the end-to-end VPBuilder test cannot show
// this, because json-gold happens to order a real document the other way.
// This is where the selection is pinned.
func TestFindProofNodeInGraphs_SelectsTheRootsGraph(t *testing.T) {
	doc := presentationProofObject()

	if got := FindProofNode(doc, "DataIntegrityProof"); got["proofValue"] != "z-issuer-proof" {
		t.Fatalf("fixture no longer exercises the ambiguity: unqualified search returned %v", got["proofValue"])
	}

	// _:b0 is the graph the presentation's own proof lives in.
	got := FindProofNodeInGraphs(doc, "DataIntegrityProof", []string{"_:b0"})
	if got == nil {
		t.Fatal("the root's own proof was not found")
	}
	if got["proofValue"] != "z-holder-proof" {
		t.Fatalf("selected %v, want the presentation's own proof", got["proofValue"])
	}

	// The issuer's graph is addressable too, so the selection follows the
	// name given rather than preferring authentication proofs.
	got = FindProofNodeInGraphs(doc, "DataIntegrityProof", []string{"_:b3"})
	if got == nil || got["proofValue"] != "z-issuer-proof" {
		t.Fatal("the embedded credential's graph must also be addressable")
	}
}

// TestFindProofNodeInGraphs_RefusesWhatIsNotThere: naming no graph, or a
// graph the proof object does not contain, must not fall back to whatever
// proof is present - that fallback is the misplaced-proof attack.
func TestFindProofNodeInGraphs_RefusesWhatIsNotThere(t *testing.T) {
	doc := presentationProofObject()

	if got := FindProofNodeInGraphs(doc, "DataIntegrityProof", nil); got != nil {
		t.Fatalf("naming no graph must select nothing, got %v", got["proofValue"])
	}
	if got := FindProofNodeInGraphs(doc, "DataIntegrityProof", []string{"_:nope"}); got != nil {
		t.Fatalf("an absent graph must select nothing, got %v", got["proofValue"])
	}

	// A graph holding a proofValue but no TYPED proof - the stub half of
	// the misplaced-proof attack - selects nothing either.
	stub := map[string]any{
		"@graph": []any{map[string]any{
			"id":     "_:b9",
			"@graph": []any{map[string]any{"proofValue": "z-holder-proof"}},
		}},
	}
	if got := FindProofNodeInGraphs(stub, "DataIntegrityProof", []string{"_:b9"}); got != nil {
		t.Fatalf("a stub carrying only a value must select nothing, got %v", got["proofValue"])
	}
}
