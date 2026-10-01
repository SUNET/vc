package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

// nestedProofCredential is a credential whose subject carries a credential of
// its own, with that credential's issuer proof still attached - a shape the SD
// suite accepts and has no way to refuse.
func nestedProofCredential() map[string]any {
	return map[string]any{
		"@context":  []any{"https://www.w3.org/ns/credentials/v2"},
		"id":        "https://example.org/credentials/outer",
		"type":      []any{"VerifiableCredential"},
		"issuer":    "did:example:outer-issuer",
		"validFrom": "2023-01-01T00:00:00Z",
		"credentialSubject": map[string]any{
			"id": "did:example:holder",
			"https://example.org/vocab#attachment": map[string]any{
				"id":        "https://example.org/credentials/inner",
				"type":      []any{"VerifiableCredential"},
				"issuer":    "did:example:inner-issuer",
				"validFrom": "2022-01-01T00:00:00Z",
				"credentialSubject": map[string]any{
					"id": "did:example:holder",
				},
				"proof": map[string]any{
					"type":               "DataIntegrityProof",
					"cryptosuite":        "eddsa-rdfc-2022",
					"created":            "2022-01-01T00:00:00Z",
					"verificationMethod": "did:example:inner-issuer#key-1",
					"proofPurpose":       "assertionMethod",
					"proofValue":         "z3FXQjecWufY46yg5abdVZsXqLhxhueuSoZgNSARiKBk9czhmGQWmzBYdCVSAzeVCTt6QcLnLCHKPkyVpGqu9rWY",
				},
			},
		},
	}
}

func signNestedProofCredential(t *testing.T) (*SdSuite, *ecdsa.PrivateKey, *credential.RDFCredential) {
	t.Helper()

	suite := NewSdSuite()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	credBytes, err := json.Marshal(nestedProofCredential())
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON(credBytes, ld.NewJsonLdOptions(""))
	require.NoError(t, err)

	signed, err := suite.Sign(cred, key, &SdSignOptions{
		VerificationMethod: "did:example:outer-issuer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	require.NoError(t, err)

	require.NoError(t, suite.Verify(signed, &key.PublicKey),
		"the credential as signed must verify, or the tampering below proves nothing")

	return suite, key, signed
}

// tamperWithNestedProof reparses the signed credential with mutate applied to
// the nested credential's proof object.
func tamperWithNestedProof(t *testing.T, signed *credential.RDFCredential, mutate func(attachment map[string]any)) *credential.RDFCredential {
	t.Helper()

	var document map[string]any
	require.NoError(t, json.Unmarshal([]byte(signed.OriginalJSON()), &document))

	subject, ok := document["credentialSubject"].(map[string]any)
	require.True(t, ok, "credentialSubject must survive signing as an object")
	attachment, ok := subject["https://example.org/vocab#attachment"].(map[string]any)
	require.True(t, ok, "the nested credential must survive signing as an object")
	require.Contains(t, attachment, "proof", "the nested proof must be there to tamper with")

	mutate(attachment)

	tamperedBytes, err := json.Marshal(document)
	require.NoError(t, err)
	tampered, err := credential.NewRDFCredentialFromJSON(tamperedBytes, ld.NewJsonLdOptions(""))
	require.NoError(t, err)
	return tampered
}

// TestSDBaseProofCoversANestedProof: an ecdsa-sd-2023 base proof secures the
// document with the ROOT's proofs removed and nested proofs left in place, so
// a nested credential's own proof is content the base signature covers.
//
// While the suite removed EVERY proof in the graph, the nested proof was
// outside the signed quad set entirely and could be stripped or replaced with
// another issuer's - the outer signature still verified, and the attachment it
// vouched for was no longer the one the issuer saw.
func TestSDBaseProofCoversANestedProof(t *testing.T) {
	t.Run("stripping it", func(t *testing.T) {
		suite, key, signed := signNestedProofCredential(t)

		stripped := tamperWithNestedProof(t, signed, func(attachment map[string]any) {
			delete(attachment, "proof")
		})

		require.Error(t, suite.Verify(stripped, &key.PublicKey),
			"removing the nested credential's proof must break the outer signature")
	})

	t.Run("swapping it", func(t *testing.T) {
		suite, key, signed := signNestedProofCredential(t)

		swapped := tamperWithNestedProof(t, signed, func(attachment map[string]any) {
			proof, ok := attachment["proof"].(map[string]any)
			require.True(t, ok)
			proof["verificationMethod"] = "did:example:someone-else#key-1"
		})

		require.Error(t, suite.Verify(swapped, &key.PublicKey),
			"re-pointing the nested proof at another key must break the outer signature")
	})
}

// TestVerifyRootProofIsBoundToTheProofItIsGiven: a caller that selects a
// proof, resolves a key from it and then asks the suite to go and find a proof
// of its own gets two independent choices that need not agree. The proof that
// verified and the proof whose metadata the caller reports would then be two
// different proofs - which is all it takes to have a forged proof described
// back to a relying party as the one that verified.
func TestVerifyRootProofIsBoundToTheProofItIsGiven(t *testing.T) {
	suite, key, signed := signNestedProofCredential(t)

	var document map[string]any
	require.NoError(t, json.Unmarshal([]byte(signed.OriginalJSON()), &document))
	genuine, ok := document["proof"].(map[string]any)
	require.True(t, ok)

	t.Run("the document's own proof verifies", func(t *testing.T) {
		require.NoError(t, suite.VerifyRootProof(signed, &key.PublicKey, genuine))
	})

	t.Run("another proof is refused, not quietly replaced", func(t *testing.T) {
		forged := map[string]any{}
		for k, v := range genuine {
			forged[k] = v
		}
		forged["proofValue"] = "uZm9yZ2Vk"
		forged["proofPurpose"] = "authentication"

		err := suite.VerifyRootProof(signed, &key.PublicKey, forged)
		require.ErrorContains(t, err, "is not an ecdsa-sd-2023 proof this document attaches to itself",
			"the suite must not verify its own pick and let the caller report this one")
	})

	t.Run("a nil proof is refused", func(t *testing.T) {
		require.Error(t, suite.VerifyRootProof(signed, &key.PublicKey, nil))
	})
}

// TestVerifyRootProofAcceptsOneOfSeveralRootProofs: binding verification to
// the proof the caller named must not also demand that it be the only one.
// Signing appends rather than replaces, so a document secured by two parties
// carries two root proofs - and a handler that resolved a key from the second
// would be refused a document the suite's own Verify accepts.
func TestVerifyRootProofAcceptsOneOfSeveralRootProofs(t *testing.T) {
	suite, firstKey, signed := signNestedProofCredential(t)

	secondKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	twice, err := suite.Sign(signed, secondKey, &SdSignOptions{
		VerificationMethod: "did:example:second#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	require.NoError(t, err)

	var document map[string]any
	require.NoError(t, json.Unmarshal([]byte(twice.OriginalJSON()), &document))
	proofs, ok := document["proof"].([]any)
	require.True(t, ok, "signing twice must make a proof SET")
	require.Len(t, proofs, 2)

	first, ok := proofs[0].(map[string]any)
	require.True(t, ok)
	second, ok := proofs[1].(map[string]any)
	require.True(t, ok)

	require.NoError(t, suite.VerifyRootProof(twice, &firstKey.PublicKey, first),
		"the first signer's proof verifies with the first signer's key")
	require.NoError(t, suite.VerifyRootProof(twice, &secondKey.PublicKey, second),
		"and the second's with the second's, without either being the only proof")

	require.Error(t, suite.VerifyRootProof(twice, &firstKey.PublicKey, second),
		"a proof is still only verified against the key that made it")
}
