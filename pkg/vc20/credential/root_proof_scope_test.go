package credential

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRelocatingAProofChangesTheSecuredDocument pins the invariant the
// cryptosuites' comments rest on.
//
// While hashing removed EVERY proof, the document a signature covered was
// the same wherever the proof sat - which is what made relocation work at
// all. Root-scoped hashing removes only the root's own proofs, so a proof
// moved onto an embedded credential stays IN the secured document and the
// hash changes.
//
// Selection refuses a moved proof before this matters. The two are
// independent, and this is the half that would still hold if selection were
// wrong.
func TestRelocatingAProofChangesTheSecuredDocument(t *testing.T) {
	const presentation = `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"id": "urn:uuid:the-presentation",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder",
		"verifiableCredential": [{
			"@context": "https://www.w3.org/ns/credentials/v2",
			"id": "urn:uuid:the-credential",
			"type": ["VerifiableCredential"],
			"issuer": "did:example:issuer",
			"credentialSubject": {"id": "did:example:subject"}
		}],
		"proof": {
			"type": "DataIntegrityProof",
			"cryptosuite": "eddsa-rdfc-2022",
			"proofPurpose": "authentication",
			"verificationMethod": "did:example:holder#key-1",
			"proofValue": "z2DXFtnG8nHVsBv5SyJTgGBJYiFTRTpLKqWjDfMVSfdcKYjPfA6QLB7yFCJNtxYJ5aVzAAHNbLbEBL2fxPGZWKbvZ"
		}
	}`

	secured := func(t *testing.T, document string) string {
		t.Helper()
		cred, err := NewRDFCredentialFromJSON([]byte(document), nil)
		require.NoError(t, err)
		_, without, err := cred.RootProofs()
		require.NoError(t, err)
		form, err := without.CanonicalForm()
		require.NoError(t, err)
		return form
	}

	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(presentation), &doc))
	embedded, ok := doc["verifiableCredential"].([]any)
	require.True(t, ok)
	embedded[0].(map[string]any)["proof"] = doc["proof"]
	delete(doc, "proof")
	moved, err := json.Marshal(doc)
	require.NoError(t, err)

	asSigned := secured(t, presentation)
	relocated := secured(t, string(moved))

	require.NotContains(t, asSigned, "security#proofValue",
		"the root's own proof is what the signature does not cover")
	require.Contains(t, relocated, "security#proofValue",
		"a proof moved onto an embedded credential is CONTENT, and stays in")
	require.NotEqual(t, asSigned, relocated,
		"so relocation changes the document the signature covers")
}
