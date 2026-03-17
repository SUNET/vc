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
