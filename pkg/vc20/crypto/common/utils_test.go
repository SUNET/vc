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

// twoProofDocument is the shape a verifiable presentation actually has: the
// holder's proof at the top and the embedded credential's issuer proof
// inside. Both are DataIntegrityProof nodes, so "find a proof" is ambiguous.
func twoProofDocument() map[string]any {
	return map[string]any{
		"type": []any{"VerifiablePresentation"},
		// Deliberately ordered so the ISSUER's proof sorts first:
		// "credential" < "proof". A traversal that takes the first node it
		// reaches therefore reaches the wrong one.
		"credential": map[string]any{
			"type": []any{"VerifiableCredential"},
			"proof": map[string]any{
				"type":       "DataIntegrityProof",
				"proofValue": "z-issuer-proof",
			},
		},
		"proof": map[string]any{
			"type":       "DataIntegrityProof",
			"proofValue": "z-holder-proof",
		},
	}
}

// TestFindProofNodeFunc_IsDeterministic: the traversal used to be
// `for _, v := range m`, and Go randomises map iteration, so a document with
// two proof nodes returned a different one between runs of the same input.
// For a presentation that meant the holder's key was sometimes checked
// against the issuer's proofValue, and a legitimate presentation failed
// intermittently.
//
// Repeated on purpose: one run of a coin flip proves nothing.
func TestFindProofNodeFunc_IsDeterministic(t *testing.T) {
	first := FindProofNode(twoProofDocument(), "DataIntegrityProof")
	if first == nil {
		t.Fatal("no proof node found")
	}
	want := first["proofValue"]

	for i := range 50 {
		got := FindProofNode(twoProofDocument(), "DataIntegrityProof")
		if got == nil {
			t.Fatalf("run %d: no proof node found", i)
		}
		if got["proofValue"] != want {
			t.Fatalf("run %d: selection changed between identical inputs: %v then %v",
				i, want, got["proofValue"])
		}
	}
}

// TestFindProofNodeFunc_SelectsTheNamedProof: determinism alone only makes
// the wrong answer stable. A caller that knows which proof it means - a
// verifier that parsed the presentation's own proof out of the original
// JSON - names it by proofValue and gets that one.
func TestFindProofNodeFunc_SelectsTheNamedProof(t *testing.T) {
	doc := twoProofDocument()

	// The unqualified search reaches the issuer's proof here, which is what
	// makes this document worth testing: selecting is not a no-op.
	if got := FindProofNode(doc, "DataIntegrityProof"); got["proofValue"] != "z-issuer-proof" {
		t.Fatalf("fixture no longer exercises the ambiguity: unqualified search returned %v", got["proofValue"])
	}

	holder := FindProofNodeFunc(doc, "DataIntegrityProof", MatchProofValue("z-holder-proof"))
	if holder == nil {
		t.Fatal("the named proof was not found")
	}
	if holder["proofValue"] != "z-holder-proof" {
		t.Fatalf("selected %v, want the holder's proof", holder["proofValue"])
	}

	issuer := FindProofNodeFunc(doc, "DataIntegrityProof", MatchProofValue("z-issuer-proof"))
	if issuer == nil || issuer["proofValue"] != "z-issuer-proof" {
		t.Fatal("the issuer's proof must also be addressable by name")
	}

	// A proofValue that is not in the document is not silently replaced by
	// whichever proof happens to be there.
	if absent := FindProofNodeFunc(doc, "DataIntegrityProof", MatchProofValue("z-nope")); absent != nil {
		t.Fatalf("a proof that is not present must not resolve to another one, got %v", absent["proofValue"])
	}
}
