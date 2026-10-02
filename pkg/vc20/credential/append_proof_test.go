package credential

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAppendProofDropsANullProof: "proof": null is a term REMOVAL in JSON-LD,
// so a document carrying one carries no proof. Treating it as an existing
// proof to keep alongside the new one wrote "proof": [null, {...}] into every
// document signed from that shape - it verified here, since expansion drops
// the null, but it is not a document another implementation has to accept.
func TestAppendProofDropsANullProof(t *testing.T) {
	proof := map[string]any{"type": "DataIntegrityProof"}

	t.Run("an explicit null", func(t *testing.T) {
		doc := map[string]any{"proof": nil}
		AppendProof(doc, proof)
		require.Equal(t, proof, doc["proof"],
			"a null proof is no proof, so the new one stands alone")
	})

	t.Run("a null inside a proof set", func(t *testing.T) {
		existing := map[string]any{"type": "DataIntegrityProof", "created": "2020-01-01T00:00:00Z"}
		doc := map[string]any{"proof": []any{nil, existing, nil}}
		AppendProof(doc, proof)
		require.Equal(t, []any{existing, proof}, doc["proof"],
			"the real proof is kept and the nulls are not")
	})

	t.Run("a real proof is still kept", func(t *testing.T) {
		existing := map[string]any{"type": "DataIntegrityProof", "created": "2020-01-01T00:00:00Z"}
		doc := map[string]any{"proof": existing}
		AppendProof(doc, proof)
		require.Equal(t, []any{existing, proof}, doc["proof"],
			"signing twice makes a proof SET, not a replacement")
	})

	t.Run("no proof at all", func(t *testing.T) {
		doc := map[string]any{}
		AppendProof(doc, proof)
		require.Equal(t, proof, doc["proof"])
	})
}

// TestSecuredDocumentIsComputedOnce: reading a document's own proofs and
// canonicalizing what they secure is the expensive half of verification -
// JSON-LD expansion, flattening, RDF serialization, URDNA2015 - and the answer
// is the SAME for every proof in a set, because that is what a proof set
// means. A verifier checking several candidates used to pay for it once per
// candidate, on a document nobody had authenticated yet.
func TestSecuredDocumentIsComputedOnce(t *testing.T) {
	cred, err := NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"},
		"proof": {
			"type": "DataIntegrityProof",
			"cryptosuite": "eddsa-rdfc-2022",
			"created": "2024-01-01T00:00:00Z",
			"verificationMethod": "did:example:issuer#key-1",
			"proofPurpose": "assertionMethod",
			"proofValue": "z3FXQjecWufY46yg5abdVZsXqLhxhueuSoZgNSARiKBk9czhmGQWmzBYdCVSAzeVCTt6QcLnLCHKPkyVpGqu9rWY"
		}
	}`), nil)
	require.NoError(t, err)

	firstHash, err := SecuredDocumentHash(cred)
	require.NoError(t, err)

	answer := cred.secured
	require.NotNil(t, answer, "the answer is kept after the first call")

	secondHash, err := SecuredDocumentHash(cred)
	require.NoError(t, err)
	require.Equal(t, firstHash, secondHash)
	require.Same(t, answer, cred.secured,
		"the second call must reuse the first answer, not recompute it")
}

// A document that cannot be read is not worth re-reading either.
func TestSecuredDocumentRemembersARefusal(t *testing.T) {
	cred, err := NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"}
	}`), nil)
	require.NoError(t, err)

	_, first := SecuredDocumentHash(cred)
	require.Error(t, first, "a document with no proof of its own")
	_, second := SecuredDocumentHash(cred)
	require.Equal(t, first, second, "and the same refusal, from the same answer")
}

// TestCompactedRootProofsIsComputedOnce: finding the proof a caller named used
// to recompact every candidate, so N candidates cost N*N JSON-LD compactions -
// about a thousand for a document at the 32-proof limit, on input nobody has
// authenticated yet. The compaction is memoized beside the secured-document
// answer.
func TestCompactedRootProofsIsComputedOnce(t *testing.T) {
	cred, err := NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"},
		"proof": {
			"type": "DataIntegrityProof",
			"cryptosuite": "eddsa-rdfc-2022",
			"created": "2024-01-01T00:00:00Z",
			"verificationMethod": "did:example:issuer#key-1",
			"proofPurpose": "assertionMethod",
			"proofValue": "z3FXQjecWufY46yg5abdVZsXqLhxhueuSoZgNSARiKBk9czhmGQWmzBYdCVSAzeVCTt6QcLnLCHKPkyVpGqu9rWY"
		}
	}`), nil)
	require.NoError(t, err)

	first, err := CompactedRootProofs(cred)
	require.NoError(t, err)
	require.Len(t, first, 1)

	cached := cred.compactedProofs
	require.NotNil(t, cached, "the compaction is kept after the first call")

	second, err := CompactedRootProofs(cred)
	require.NoError(t, err)
	require.Same(t, cached, cred.compactedProofs,
		"the second call must reuse the first compaction, not repeat it")
	require.Equal(t, first, second, "and give the same answer")

	// Each caller gets its OWN maps, so writing to one cannot reach the
	// cache or another caller. The alternative - sharing the cached maps
	// behind a note asking callers not to write - is a hope, not a
	// guarantee, on an exported function.
	first[0]["proofPurpose"] = "scribbled"
	third, err := CompactedRootProofs(cred)
	require.NoError(t, err)
	require.Equal(t, "assertionMethod", third[0]["proofPurpose"],
		"a caller writing to its copy must not poison the next reader")
	require.NotEqual(t,
		reflect.ValueOf(first[0]).Pointer(), reflect.ValueOf(third[0]).Pointer())
}

// TestCompactedRootProofsCopiesNestedValues: a shallow copy hands back the
// top-level map and shares every slice and nested map inside it - and a
// multi-typed proof already carries a []any, so a caller writing through that
// slice reached the cache anyway.
func TestCompactedRootProofsCopiesNestedValues(t *testing.T) {
	cred, err := NewRDFCredentialFromJSON([]byte(`{
		"@context": ["https://www.w3.org/ns/credentials/v2",
			{"Sealed": "https://example.org/vocab#Sealed"}],
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"},
		"proof": {
			"type": ["DataIntegrityProof", "Sealed"],
			"cryptosuite": "eddsa-rdfc-2022",
			"created": "2024-01-01T00:00:00Z",
			"verificationMethod": "did:example:issuer#key-1",
			"proofPurpose": "assertionMethod",
			"proofValue": "z3FXQjecWufY46yg5abdVZsXqLhxhueuSoZgNSARiKBk9czhmGQWmzBYdCVSAzeVCTt6QcLnLCHKPkyVpGqu9rWY"
		}
	}`), nil)
	require.NoError(t, err)

	first, err := CompactedRootProofs(cred)
	require.NoError(t, err)
	require.Len(t, first, 1)

	types, isList := first[0]["type"].([]any)
	require.True(t, isList, "the proof must really carry a list, or this proves nothing")
	require.Len(t, types, 2)

	// Write THROUGH the slice, which a shallow copy leaves shared.
	types[0] = "scribbled"

	second, err := CompactedRootProofs(cred)
	require.NoError(t, err)
	again, isList := second[0]["type"].([]any)
	require.True(t, isList)
	require.NotContains(t, again, "scribbled",
		"writing through a nested slice must not reach the cache either")
}
