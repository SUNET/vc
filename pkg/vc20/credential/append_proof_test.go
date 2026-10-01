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

	first, firstHash, err := SecuredDocument(cred)
	require.NoError(t, err)
	require.NotEmpty(t, first)

	second, secondHash, err := SecuredDocument(cred)
	require.NoError(t, err)
	require.Equal(t, firstHash, secondHash)

	require.Equal(t,
		reflect.ValueOf(first).Pointer(), reflect.ValueOf(second).Pointer(),
		"the second call must hand back the first answer, not recompute it")
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

	_, _, first := SecuredDocument(cred)
	require.Error(t, first, "a document with no proof of its own")
	_, _, second := SecuredDocument(cred)
	require.Equal(t, first, second, "and the same refusal, from the same answer")
}
