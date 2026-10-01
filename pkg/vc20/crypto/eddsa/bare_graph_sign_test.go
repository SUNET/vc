package eddsa

import (
	"testing"

	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/stretchr/testify/require"
)

// TestSignRootsABareGraphContainer: a document that came back from flattening
// as {"@context": ..., "@graph": [node]} is ABOUT nothing. Root-scoped hashing
// reads the node INSIDE the container - that is the document being signed -
// but appending the proof put it on the container itself. The proof then hung
// on a wrapper rather than on the credential that was hashed, and under the v2
// type-scoped context, where `proof` is defined on credential types rather
// than on nothing, it expands away entirely.
//
// The consequence is the worst shape an API can return: Sign succeeds, and the
// document it hands back does not verify - with THIS library, let alone
// another one.
func TestSignRootsABareGraphContainer(t *testing.T) {
	const container = `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"@graph": [
			{
				"id": "https://example.org/credential",
				"type": ["VerifiableCredential"],
				"issuer": "did:example:issuer",
				"credentialSubject": {"id": "did:example:subject"}
			}
		]
	}`

	signed, pub := signDocument(t, container, "assertionMethod")

	document, err := credential.DocumentAsMap(signed)
	require.NoError(t, err)
	require.NotContains(t, document, "@graph",
		"the signed document is rooted at the credential, not left as a container")
	require.Equal(t, "https://example.org/credential", document["id"],
		"and the proof hangs on the node that was hashed")
	require.Contains(t, document, "proof")

	// The property that actually matters: what Sign returns verifies.
	require.Len(t, rootProofsOf(t, signed), 1,
		"the signed document attaches exactly one proof to itself")
	verified, err := NewSuite().VerifyProof(signed, pub)
	require.NoError(t, err, "a document Sign produced must verify")
	require.NotNil(t, verified)
}
