package ecdsa

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/stretchr/testify/require"
)

// The container shape both tests below sign: a document that came back from
// flattening as {"@context": ..., "@graph": [node]}, which is ABOUT nothing.
const bareGraphContainer = `{
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

func requireRootedAtTheCredential(t *testing.T, signed *credential.RDFCredential) {
	t.Helper()

	document, err := credential.DocumentAsMap(signed)
	require.NoError(t, err)
	require.NotContains(t, document, "@graph",
		"the signed document is rooted at the credential, not left as a container")
	require.Equal(t, "https://example.org/credential", document["id"],
		"and the proof hangs on the node that was hashed")
	require.Contains(t, document, "proof")
}

// TestSignRootsABareGraphContainer: root-scoped hashing reads the node INSIDE
// the container - that is the document being signed - but appending the proof
// put it on the container itself. The proof then hung on a wrapper rather than
// on the credential that was hashed, and under the v2 type-scoped context,
// where `proof` is defined on credential types rather than on nothing, it
// expands away entirely.
//
// The consequence is the worst shape an API can return: Sign succeeds, and the
// document it hands back does not verify - with THIS library, let alone
// another one.
func TestSignRootsABareGraphContainer(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON([]byte(bareGraphContainer), nil)
	require.NoError(t, err)

	signed, err := NewSuite().Sign(context.Background(), cred, key, &SignOptions{
		VerificationMethod: "did:example:signer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	requireRootedAtTheCredential(t, signed)

	verified, err := NewSuite().VerifyProof(signed, &key.PublicKey)
	require.NoError(t, err, "a document Sign produced must verify")
	require.NotNil(t, verified)
}

// TestSdSignRootsABareGraphContainer: the SD signing path had the same defect,
// and Derive was already doing the right thing - it roots the compacted
// document before attaching the derived proof.
func TestSdSignRootsABareGraphContainer(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON([]byte(bareGraphContainer), nil)
	require.NoError(t, err)

	signed, err := NewSdSuite().Sign(cred, key, &SdSignOptions{
		VerificationMethod: "did:example:signer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
		MandatoryPointers:  []string{"/issuer"},
	})
	require.NoError(t, err)

	requireRootedAtTheCredential(t, signed)

	require.NoError(t, NewSdSuite().Verify(signed, &key.PublicKey),
		"a base proof SdSuite.Sign produced must verify")
}

// expandedDocument: valid JSON-LD already in expanded form. It carries no
// @context, because it does not need one - every name in it is an IRI.
const expandedDocument = `{
	"@id": "https://example.org/credential",
	"@type": ["https://www.w3.org/2018/credentials#VerifiableCredential"],
	"https://example.org/vocab#note": [{"@value": "hello"}]
}`

func requireProofUnderTheAbsolutePredicate(t *testing.T, signed *credential.RDFCredential) {
	t.Helper()

	document, err := credential.DocumentAsMap(signed)
	require.NoError(t, err)
	require.NotContains(t, document, "proof",
		"a bare term no context defines is a relative IRI, and expansion drops it")
	require.Contains(t, document, credential.ProofPredicate)
}

// TestSignAnExpandedDocumentUsesTheAbsolutePredicate: with no active context
// there is nothing to map the bare term `proof` to the security predicate, so
// writing the signature under that name produced a RELATIVE IRI - which
// expansion drops. Sign returned success and the document carried no root
// proof at all, so this library refused to verify what it had just produced.
//
// The key is chosen by credential.ProofKeyFor, which all three suites share;
// a test per suite is what keeps one of them from drifting off it.
func TestSignAnExpandedDocumentUsesTheAbsolutePredicate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON([]byte(expandedDocument), nil)
	require.NoError(t, err)

	signed, err := NewSuite().Sign(context.Background(), cred, key, &SignOptions{
		VerificationMethod: "did:example:signer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	requireProofUnderTheAbsolutePredicate(t, signed)

	verified, err := NewSuite().VerifyProof(signed, &key.PublicKey)
	require.NoError(t, err, "a document Sign produced must verify")
	require.NotNil(t, verified)
}

// TestSdSignAnExpandedDocumentUsesTheAbsolutePredicate: the same for the SD
// base proof, whose mandatory pointers address the expanded member names.
func TestSdSignAnExpandedDocumentUsesTheAbsolutePredicate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON([]byte(expandedDocument), nil)
	require.NoError(t, err)

	signed, err := NewSdSuite().Sign(cred, key, &SdSignOptions{
		VerificationMethod: "did:example:signer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
		MandatoryPointers:  []string{"/@type"},
	})
	require.NoError(t, err)

	requireProofUnderTheAbsolutePredicate(t, signed)

	require.NoError(t, NewSdSuite().Verify(signed, &key.PublicKey),
		"a base proof SdSuite.Sign produced must verify")
}
