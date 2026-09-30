package eddsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/stretchr/testify/require"
)

// TestRootProofValues covers both serializations, because the answer has to
// come from the document either way - a re-parsed credential's
// OriginalJSON() is expanded JSON-LD, where members are IRIs and the root's
// proof lives in a named graph.
func TestRootProofValues(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const doc = `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder"
	}`

	cred, err := credential.NewRDFCredentialFromJSON([]byte(doc), nil)
	require.NoError(t, err)
	signed, err := NewSuite().Sign(cred, priv, &SignOptions{
		VerificationMethod: "did:example:holder#key-1",
		ProofPurpose:       "authentication",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	// Compact, as Sign returns it.
	compactValues := rootProofValues(signed)
	require.Len(t, compactValues, 1)

	// Expanded, as a re-parse from MarshalJSON produces. Note this document
	// has NO id, which is the case the previous id-based approach could not
	// resolve - a presentation is not required to have one.
	expanded, err := json.Marshal(signed)
	require.NoError(t, err)
	require.Equal(t, byte('['), expanded[0], "the fixture must really be expanded")
	reparsed, err := credential.NewRDFCredentialFromJSON(expanded, nil)
	require.NoError(t, err)

	expandedValues := rootProofValues(reparsed)
	require.Equal(t, compactValues, expandedValues,
		"both serializations must name the same proof")
}

// TestRootProofValuesIgnoresAnEmbeddedCredentialsProof: the whole point is
// telling the document's own proof from one further down.
func TestRootProofValuesIgnoresAnEmbeddedCredentialsProof(t *testing.T) {
	const vpWithEmbeddedProofOnly = `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiablePresentation"],
		"holder": "did:example:holder",
		"verifiableCredential": [{
			"@context": "https://www.w3.org/ns/credentials/v2",
			"type": ["VerifiableCredential"],
			"issuer": "did:example:issuer",
			"credentialSubject": {"id": "did:example:subject"},
			"proof": {
				"type": "DataIntegrityProof",
				"cryptosuite": "eddsa-rdfc-2022",
				"proofPurpose": "assertionMethod",
				"verificationMethod": "did:example:issuer#key-1",
				"proofValue": "z-embedded-only"
			}
		}]
	}`

	cred, err := credential.NewRDFCredentialFromJSON([]byte(vpWithEmbeddedProofOnly), nil)
	require.NoError(t, err)
	require.Empty(t, rootProofValues(cred),
		"a presentation with no proof of its own names none, whatever it carries")

	// And the same document in expanded form, where the root is identified
	// by elimination rather than by an id.
	expanded, err := json.Marshal(cred)
	require.NoError(t, err)
	reparsed, err := credential.NewRDFCredentialFromJSON(expanded, nil)
	require.NoError(t, err)
	require.Empty(t, rootProofValues(reparsed))
}
