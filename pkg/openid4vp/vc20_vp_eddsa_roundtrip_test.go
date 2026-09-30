package openid4vp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"
	eddsaSuite "github.com/SUNET/vc/pkg/vc20/crypto/eddsa"

	"github.com/stretchr/testify/require"
)

// TestVPBuilderEdDSAPresentationVerifies covers the path a real presentation
// takes: VPBuilder signs, returns COMPACT JSON, and a verifier re-parses
// those bytes.
//
// Every presentation this builder produces carries a credential, and that
// is the case eddsa-rdfc-2022 could not verify in ANY serialization - not
// re-parsed, not even straight from Sign's return value - because Verify
// called NormalizeVerifiableCredentialGraph() and Sign did not, so the
// verifiableCredential graph was rewritten between signing and checking.
//
// The suite's own TestSignAndVerify_VerifiablePresentation passes on the old
// code because its presentation carries an EMPTY verifiableCredential array.
// A presentation with nothing in it was the exception, not the rule.
//
// Suite-level verification only. Holder binding - checking the
// presentation's own proof against this session's nonce and verifier - is
// what SUNET/vc#685 adds; on main VC20Handler.VerifyAndExtract verifies the
// credential it extracts, not the holder's presentation proof.
func TestVPBuilderEdDSAPresentationVerifies(t *testing.T) {
	holderPub, holderKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	const unsignedVC = `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"}
	}`

	for name, embedded := range map[string][][]byte{
		// Both, because they exercise different amounts of the graph: the
		// signed one adds a second proof node to the document, which is what
		// the proof-removal half of the fix is about.
		"unsigned embedded credential": {[]byte(unsignedVC)},
		"signed embedded credential":   {signedEdDSACredential(t, issuerKey, unsignedVC)},
	} {
		t.Run(name, func(t *testing.T) {
			vpBytes, buildErr := NewVPBuilder().BuildVC20Presentation(embedded, holderKey, &VPBuildOptions{
				HolderDID:          "did:example:holder",
				VerificationMethod: "did:example:holder#key-1",
				Nonce:              "test-nonce",
				Domain:             "https://verifier.example.com",
				Cryptosuite:        CryptosuiteEdDSA2022,
				Created:            time.Now().UTC(),
			})
			require.NoError(t, buildErr)

			// The builder emits compact JSON; re-parsing those bytes is what
			// a verifier does, and it is where the old code diverged.
			var compact map[string]any
			require.NoError(t, json.Unmarshal(vpBytes, &compact),
				"the builder's output is a compact JSON object")
			require.Contains(t, compact, "verifiableCredential")

			reparsed, parseErr := credential.NewRDFCredentialFromJSON(vpBytes, nil)
			require.NoError(t, parseErr)

			require.NoError(t, eddsaSuite.NewSuite().Verify(reparsed, holderPub),
				"a presentation this builder produced must verify")
		})
	}
}

// TestVPBuilderEdDSAPresentationRejectsTampering keeps the round trip from
// passing for the wrong reason.
func TestVPBuilderEdDSAPresentationRejectsTampering(t *testing.T) {
	holderPub, holderKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	vpBytes, err := NewVPBuilder().BuildVC20Presentation(
		[][]byte{[]byte(`{"@context":"https://www.w3.org/ns/credentials/v2","type":["VerifiableCredential"],"issuer":"did:example:issuer","credentialSubject":{"id":"did:example:original-subject"}}`)},
		holderKey,
		&VPBuildOptions{
			HolderDID:          "did:example:holder",
			VerificationMethod: "did:example:holder#key-1",
			Nonce:              "test-nonce",
			Domain:             "https://verifier.example.com",
			Cryptosuite:        CryptosuiteEdDSA2022,
			Created:            time.Now().UTC(),
		},
	)
	require.NoError(t, err)

	tampered := bytes.ReplaceAll(vpBytes, []byte("original-subject"), []byte("someone-else"))
	require.NotEqual(t, string(vpBytes), string(tampered), "the tamper must change the document")

	reparsed, err := credential.NewRDFCredentialFromJSON(tampered, nil)
	require.NoError(t, err)
	require.Error(t, eddsaSuite.NewSuite().Verify(reparsed, holderPub))
}

// signedEdDSACredential returns a credential carrying its issuer's proof.
func signedEdDSACredential(t *testing.T, issuerKey ed25519.PrivateKey, raw string) []byte {
	t.Helper()

	cred, err := credential.NewRDFCredentialFromJSON([]byte(raw), nil)
	require.NoError(t, err)

	signed, err := eddsaSuite.NewSuite().Sign(cred, issuerKey, &eddsaSuite.SignOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	out, err := signed.ToCompactJSON()
	require.NoError(t, err)
	return out
}

// TestVPBuilderEdDSASelectsTheHolderProof pins the PROPERTY end to end: a
// presentation carrying a signed credential has two proofs, and the one
// verified has to be the presentation's own - checked by the key that must
// NOT work as well as the one that must.
//
// Honest about what it cannot do: it passes with the unqualified search
// too, because json-gold happens to order a real VPBuilder document so that
// the holder's proof is reached first. That is exactly why relying on the
// ordering was wrong, and why the selection is pinned where the ambiguity
// can be forced - common.TestFindRootProofNode_SelectsTheDocumentsOwnProof
// builds the graph with the ISSUER's proof first and fails without it.
func TestVPBuilderEdDSASelectsTheHolderProof(t *testing.T) {
	holderPub, holderKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	issuerPub, issuerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	vpBytes, err := NewVPBuilder().BuildVC20Presentation(
		[][]byte{signedEdDSACredential(t, issuerKey, `{
			"@context": "https://www.w3.org/ns/credentials/v2",
			"type": ["VerifiableCredential"],
			"issuer": "did:example:issuer",
			"credentialSubject": {"id": "did:example:subject"}
		}`)},
		holderKey,
		&VPBuildOptions{
			HolderDID:          "did:example:holder",
			VerificationMethod: "did:example:holder#key-1",
			Nonce:              "test-nonce",
			Domain:             "https://verifier.example.com",
			Cryptosuite:        CryptosuiteEdDSA2022,
			Created:            time.Now().UTC(),
		},
	)
	require.NoError(t, err)

	// Both proofs really are in the document.
	var vp map[string]any
	require.NoError(t, json.Unmarshal(vpBytes, &vp))
	require.Contains(t, vp, "proof", "the presentation's own proof")
	embedded, err := json.Marshal(vp["verifiableCredential"])
	require.NoError(t, err)
	require.Contains(t, string(embedded), "proofValue", "and the issuer's")

	reparsed, err := credential.NewRDFCredentialFromJSON(vpBytes, nil)
	require.NoError(t, err)
	require.NoError(t, eddsaSuite.NewSuite().Verify(reparsed, holderPub),
		"the presentation's own proof is the one verified")

	reparsed, err = credential.NewRDFCredentialFromJSON(vpBytes, nil)
	require.NoError(t, err)
	require.Error(t, eddsaSuite.NewSuite().Verify(reparsed, issuerPub),
		"the embedded credential's issuer key must not verify the presentation")
}

// TestVPBuilderEdDSARefusesAMisplacedProof is the forgery this selection
// exists to stop, and it is not theoretical.
//
// Verify removes EVERY proof when hashing, so moving a proof from the
// presentation onto the embedded credential leaves the canonical form - and
// therefore the hash - unchanged. Someone holding a legitimately signed
// presentation can move the holder's proof down onto the credential, delete
// the presentation's own proof, and offer a document the holder never
// signed in that shape. "Verify whichever proof is in there" accepts it with
// the holder's key.
//
// So a document that attaches no proof to ITSELF is refused, whatever it
// carries further down.
func TestVPBuilderEdDSARefusesAMisplacedProof(t *testing.T) {
	holderPub, holderKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	vpBytes, err := NewVPBuilder().BuildVC20Presentation(
		[][]byte{[]byte(`{
			"@context": "https://www.w3.org/ns/credentials/v2",
			"type": ["VerifiableCredential"],
			"issuer": "did:example:issuer",
			"credentialSubject": {"id": "did:example:subject"}
		}`)},
		holderKey,
		&VPBuildOptions{
			HolderDID:          "did:example:holder",
			VerificationMethod: "did:example:holder#key-1",
			Nonce:              "test-nonce",
			Domain:             "https://verifier.example.com",
			Cryptosuite:        CryptosuiteEdDSA2022,
			Created:            time.Now().UTC(),
		},
	)
	require.NoError(t, err)

	// Sanity: as issued, it verifies.
	asIssued, err := credential.NewRDFCredentialFromJSON(vpBytes, nil)
	require.NoError(t, err)
	require.NoError(t, eddsaSuite.NewSuite().Verify(asIssued, holderPub))

	// Now move the holder's proof onto the embedded credential and remove
	// the presentation's own.
	var vp map[string]any
	require.NoError(t, json.Unmarshal(vpBytes, &vp))
	holderProof, ok := vp["proof"]
	require.True(t, ok, "the presentation must start out with its own proof")
	delete(vp, "proof")

	embedded, ok := vp["verifiableCredential"].([]any)
	require.True(t, ok)
	require.Len(t, embedded, 1)
	credentialNode, ok := embedded[0].(map[string]any)
	require.True(t, ok, "the builder embeds the credential as an object")
	credentialNode["proof"] = holderProof

	moved, err := json.Marshal(vp)
	require.NoError(t, err)

	reparsed, err := credential.NewRDFCredentialFromJSON(moved, nil)
	require.NoError(t, err)
	require.Error(t, eddsaSuite.NewSuite().Verify(reparsed, holderPub),
		"a proof that is not the document's own must not verify it")
}
