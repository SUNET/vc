package eddsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

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

// expandedDocument: valid JSON-LD already in expanded form. It carries no
// @context, because it does not need one - every name in it is an IRI.
const expandedDocument = `{
	"@id": "https://example.org/credential",
	"@type": ["https://www.w3.org/2018/credentials#VerifiableCredential"],
	"https://example.org/vocab#note": [{"@value": "hello"}]
}`

// TestSignAnExpandedDocumentUsesTheAbsolutePredicate: with no active context
// there is nothing to map the bare term `proof` to the security predicate, so
// writing the signature under that name produced a RELATIVE IRI - which
// expansion drops. Sign returned success and the document carried no root
// proof at all, so this library refused to verify what it had just produced.
//
// The same holds for a context that defines neither `proof` nor a vocabulary
// to read it through; the absolute predicate is the answer in both cases,
// because an IRI expands to itself under any context.
func TestSignAnExpandedDocumentUsesTheAbsolutePredicate(t *testing.T) {
	signed, pub := signDocument(t, expandedDocument, "assertionMethod")

	document, err := credential.DocumentAsMap(signed)
	require.NoError(t, err)
	require.NotContains(t, document, "proof",
		"a bare term no context defines is a relative IRI, and expansion drops it")
	require.Contains(t, document, credential.ProofPredicate)

	require.Len(t, rootProofsOf(t, signed), 1,
		"the signed document attaches exactly one proof to itself")

	verified, err := NewSuite().VerifyProof(signed, pub)
	require.NoError(t, err, "a document Sign produced must verify")
	require.NotNil(t, verified)
}

// TestSignPreservesTheCredentialsOptions: a credential parsed with an
// expandContext gets its terms from the OPTIONS, not from the document. The
// canonical form is computed under those options - that is what the signature
// covers - but the signed document was handed back parsed with fresh defaults,
// where the expandContext is gone and every term in it expands to nothing. So
// Sign returned a credential that this library could not verify, from input it
// had just signed. The same holds for a private document loader, a base, or a
// non-default processing mode.
func TestSignPreservesTheCredentialsOptions(t *testing.T) {
	options := credential.NewJSONLDOptions("")
	options.ExpandContext = map[string]any{
		"@context": map[string]any{
			"id":   "@id",
			"note": "https://example.org/vocab#note",
		},
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON([]byte(`{
		"id": "https://example.org/credential",
		"note": "a term only the expandContext defines"
	}`), options)
	require.NoError(t, err)

	canonical, err := cred.CanonicalForm()
	require.NoError(t, err)
	require.Contains(t, canonical, "https://example.org/vocab#note",
		"the expandContext is what gives this document any triples at all")

	signed, err := NewSuite().Sign(cred, priv, &SignOptions{
		VerificationMethod: "did:example:signer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	verified, err := NewSuite().VerifyProof(signed, pub)
	require.NoError(t, err, "a document Sign produced must verify")
	require.NotNil(t, verified)
}

// TestSignAndVerifyGeneralizedRdf: a credential parsed with
// ProduceGeneralizedRdf carries quads whose PREDICATE is a blank node. Those
// are not valid N-Quads however the dataset was built, and json-gold's parser
// refuses them - so every path that serialized the dataset and read it back
// failed on such a credential. Canonicalization was one; the root-stability
// check, which every suite runs before signing and before verifying, was the
// other, and it refused the document outright. The credential was neither
// signable nor verifiable.
//
// The round trip is the point: canonicalizing generalized RDF is no use if
// nothing can sign it.
func TestSignAndVerifyGeneralizedRdf(t *testing.T) {
	options := credential.NewJSONLDOptions("")
	options.ProduceGeneralizedRdf = true

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON([]byte(`{
		"@context": {"id": "@id", "rel": "_:aBlankNodePredicate"},
		"id": "https://example.org/credential",
		"rel": "a statement made through a blank node predicate"
	}`), options)
	require.NoError(t, err)

	canonical, err := cred.CanonicalForm()
	require.NoError(t, err)
	require.Contains(t, canonical, "a statement made through a blank node predicate",
		"the quad is in what gets signed, or this test secures nothing")

	signed, err := NewSuite().Sign(cred, priv, &SignOptions{
		VerificationMethod: "did:example:signer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err, "a generalized-RDF credential must be signable")

	verified, err := NewSuite().VerifyProof(signed, pub)
	require.NoError(t, err, "and what Sign returns must verify")
	require.NotNil(t, verified)
}

// TestProofAliasWithoutGraphContainerSurvivesARoundTrip: the VC v2 context
// declares `proof` with "@container": "@graph", so a proof becomes a NAMED
// GRAPH once serialized through RDF. A document that aliases the predicate
// WITHOUT that container does not: the round trip flattens its proof into an
// ordinary top-level node, and the root is left holding a bare reference.
//
// Resolving that reference only against named graphs returned the incomplete
// LINK as the proof, and left the real proof node inside the document the
// signature covers - so the document verified straight from Sign and stopped
// verifying once serialized and read back. A signature whose validity depends
// on which serialization the verifier sees is the defect this whole change
// exists to remove.
func TestProofAliasWithoutGraphContainerSurvivesARoundTrip(t *testing.T) {
	const document = `{
		"@context": {
			"id": "@id",
			"note": "https://example.org/vocab#note",
			"proof": {"@id": "https://w3id.org/security#proof"}
		},
		"id": "https://example.org/credential",
		"note": "secured without a graph container"
	}`

	signed, pub := signDocument(t, document, "assertionMethod")
	require.Len(t, rootProofsOf(t, signed), 1,
		"the document attaches one proof to itself as written")

	direct, err := NewSuite().VerifyProof(signed, pub)
	require.NoError(t, err, "it verifies as Sign returned it")
	require.NotNil(t, direct)

	// THROUGH RDF and back, which is what a verifier on the other side of a
	// wire does.
	marshalled, err := signed.MarshalJSON()
	require.NoError(t, err)
	reparsed, err := credential.NewRDFCredentialFromJSON(marshalled, nil)
	require.NoError(t, err)

	require.Len(t, rootProofsOf(t, reparsed), 1,
		"and it still attaches exactly one proof to itself afterwards")

	roundTripped, err := NewSuite().VerifyProof(reparsed, pub)
	require.NoError(t, err, "a signature must not depend on which serialization the verifier sees")
	require.NotNil(t, roundTripped)
}
