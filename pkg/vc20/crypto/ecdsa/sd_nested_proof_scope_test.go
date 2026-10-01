package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
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
		verified, err := suite.VerifyRootProof(signed, &key.PublicKey, genuine)
		require.NoError(t, err)
		require.True(t, credential.SameProof(genuine, verified),
			"the candidate that verified is handed back")
	})

	t.Run("another proof is refused, not quietly replaced", func(t *testing.T) {
		forged := map[string]any{}
		for k, v := range genuine {
			forged[k] = v
		}
		forged["proofValue"] = "uZm9yZ2Vk"
		forged["proofPurpose"] = "authentication"

		_, err := suite.VerifyRootProof(signed, &key.PublicKey, forged)
		require.ErrorContains(t, err, "is not an ecdsa-sd-2023 proof this document attaches to itself",
			"the suite must not verify its own pick and let the caller report this one")
	})

	t.Run("a nil proof is refused", func(t *testing.T) {
		_, err := suite.VerifyRootProof(signed, &key.PublicKey, nil)
		require.Error(t, err)
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

	verifiedFirst, err := suite.VerifyRootProof(twice, &firstKey.PublicKey, first)
	require.NoError(t, err, "the first signer's proof verifies with the first signer's key")
	require.True(t, credential.SameProof(first, verifiedFirst))

	verifiedSecond, err := suite.VerifyRootProof(twice, &secondKey.PublicKey, second)
	require.NoError(t, err, "and the second's with the second's, without either being the only proof")
	require.True(t, credential.SameProof(second, verifiedSecond))

	_, err = suite.VerifyRootProof(twice, &firstKey.PublicKey, second)
	require.Error(t, err, "a proof is still only verified against the key that made it")
}

// TestDeriveRefusesAnAnonymousRoot: which node a derived credential is about
// has to come from the BASE credential. A root carrying no identifier cannot
// say - derivation rewrites blank node labels, so nothing is left to match it
// by - and the fallback, the node nothing refers to, is precisely what a
// disclosure gets to choose.
//
// Drop every triple of an anonymous root and the subject is the only
// unreferenced node left, so the credential's proof ends up attached to the
// subject: the re-rooting the whole root-scoping change exists to stop.
func TestDeriveRefusesAnAnonymousRoot(t *testing.T) {
	suite := NewSdSuite()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// No "id" on the credential itself.
	anonymous, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:example:issuer",
		"validFrom":         "2023-01-01T00:00:00Z",
		"credentialSubject": map[string]any{"id": "did:example:subject"},
	})
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON(anonymous, ld.NewJsonLdOptions(""))
	require.NoError(t, err)

	signed, err := suite.Sign(cred, key, &SdSignOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	require.NoError(t, err, "signing an anonymous-root credential is still fine")

	rootID, err := signed.RootID()
	require.NoError(t, err)
	require.Empty(t, rootID, "the root must really be anonymous, or this proves nothing")

	withoutProof, err := signed.CredentialWithoutProof()
	require.NoError(t, err)
	canonical, err := withoutProof.CanonicalForm()
	require.NoError(t, err)
	quads := parseNQuads(canonical)
	require.NotEmpty(t, quads)

	reveal := make([]int, len(quads))
	for i := range reveal {
		reveal[i] = i
	}

	_, err = suite.Derive(signed, reveal, "")
	require.ErrorContains(t, err, "root carries no identifier",
		"deriving must refuse rather than let the disclosure pick a root")
}

// TestVerifyRootProofMatchesTheWholeProofNotTheSignature: a forged proof may
// copy a genuine proof's signature bytes verbatim and change only its
// metadata. Matching the offered proof by proofValue alone would find the
// genuine candidate, verify THAT, and answer success - handing the caller
// exactly the binding guarantee it asked for while the metadata it goes on to
// report is the forged one's.
func TestVerifyRootProofMatchesTheWholeProofNotTheSignature(t *testing.T) {
	suite, key, signed := signNestedProofCredential(t)

	var document map[string]any
	require.NoError(t, json.Unmarshal([]byte(signed.OriginalJSON()), &document))
	genuine, ok := document["proof"].(map[string]any)
	require.True(t, ok)

	forged := map[string]any{}
	for k, v := range genuine {
		forged[k] = v
	}
	// The SAME signature, different metadata.
	forged["proofPurpose"] = "authentication"
	forged["verificationMethod"] = "did:example:someone-else#key-1"
	require.Equal(t, genuine["proofValue"], forged["proofValue"],
		"the forgery must keep the genuine signature, or this proves nothing")

	_, err := suite.VerifyRootProof(signed, &key.PublicKey, forged)
	require.Error(t, err,
		"a proof that only shares a signature is a different proof")

	// And the proof handed back for the genuine one still carries its
	// signature: verification must not strip the caller's map in passing.
	verified, err := suite.VerifyRootProof(signed, &key.PublicKey, genuine)
	require.NoError(t, err)
	require.Equal(t, genuine["proofValue"], verified["proofValue"])
	require.Equal(t, "assertionMethod", verified["proofPurpose"])
}

// TestSdSignRefusesToExceedTheProofLimit: the rdfc suites get this cap from
// UnsecuredDocumentHash, which SD does not use - it does its own root-scoped
// removal - so SD would append a 33rd proof, return success, and hand back a
// document sdRootProofs refuses before checking any signature.
//
// The cap is on SIGNING only: verification must still read a document that
// carries the full limit, or signing the 32nd proof would produce something
// unverifiable too.
func TestSdSignRefusesToExceedTheProofLimit(t *testing.T) {
	suite := NewSdSuite()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	document, err := json.Marshal(map[string]any{
		"@context":          []any{"https://www.w3.org/ns/credentials/v2"},
		"id":                "https://example.org/credentials/full",
		"type":              []any{"VerifiableCredential"},
		"issuer":            "did:example:issuer",
		"credentialSubject": map[string]any{"id": "did:example:subject"},
	})
	require.NoError(t, err)

	// Fill the document to the limit with proofs the suite will read back.
	var asMap map[string]any
	require.NoError(t, json.Unmarshal(document, &asMap))
	proofs := make([]any, 0, credential.MaxRootProofs)
	for i := range credential.MaxRootProofs {
		proofs = append(proofs, map[string]any{
			"type":               "DataIntegrityProof",
			"cryptosuite":        CryptosuiteSd2023,
			"proofPurpose":       "assertionMethod",
			"verificationMethod": "did:example:issuer#key-1",
			"created":            "2024-01-01T00:00:00Z",
			"domain":             fmt.Sprintf("https://example.org/%d", i),
			"proofValue":         "uZmlsbGVy",
		})
	}
	asMap["proof"] = proofs

	full, err := json.Marshal(asMap)
	require.NoError(t, err)
	atLimit, err := credential.NewRDFCredentialFromJSON(full, ld.NewJsonLdOptions(""))
	require.NoError(t, err)

	carried, _, err := atLimit.RootProofs()
	require.NoError(t, err)
	require.Len(t, carried, credential.MaxRootProofs, "the document must really be at the limit")

	_, err = suite.Sign(atLimit, key, &SdSignOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	require.ErrorContains(t, err, "is the most this will verify")

	// One fewer is still signable, so the cap is not simply refusing work.
	asMap["proof"] = proofs[:credential.MaxRootProofs-1]
	under, err := json.Marshal(asMap)
	require.NoError(t, err)
	below, err := credential.NewRDFCredentialFromJSON(under, ld.NewJsonLdOptions(""))
	require.NoError(t, err)

	_, err = suite.Sign(below, key, &SdSignOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	require.NoError(t, err, "one below the limit still signs")
}

// TestSdVerifyStillRefusesAnUnstableRoot: the root-stability check moved out
// of sdRootProofs, which was running it before CompactedRootProofs - the one
// place that performs it and memoizes the answer. Removing a check because
// something else does it is only safe if that something else really does, so
// this says the SD path still refuses a document whose root moves.
func TestSdVerifyStillRefusesAnUnstableRoot(t *testing.T) {
	suite := NewSdSuite()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// A blank root with an @included node pointing back at it: the root
	// moves once flattened, which is what the check is for.
	unstable, err := credential.NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"@id": "_:root",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"},
		"@included": [{"https://example.org/vocab#about": {"@id": "_:root"}}],
		"proof": {
			"type": "DataIntegrityProof",
			"cryptosuite": "ecdsa-sd-2023",
			"created": "2024-01-01T00:00:00Z",
			"verificationMethod": "did:example:issuer#key-1",
			"proofPurpose": "assertionMethod",
			"proofValue": "uZmFrZQ"
		}
	}`), ld.NewJsonLdOptions(""))
	require.NoError(t, err)

	err = suite.Verify(unstable, &key.PublicKey)
	require.ErrorContains(t, err, "refers to that node",
		"the stability check must still run, wherever it lives")
}

// TestRemoveRootProofKeepsEmbeddedProofsUnderAnAliasedID: root selection
// resolves any alias of @id, but the fragment comparison here read only the
// spellings @id and id. A flattened document aliasing it returned "" for the
// root AND for every other node, so every node compared equal to the root and
// the embedded credential's proof was removed along with the root's - the
// exact failure this change exists to remove, reached through the alias.
func TestRemoveRootProofKeepsEmbeddedProofsUnderAnAliasedID(t *testing.T) {
	context := map[string]any{
		"identifier": "@id",
		"carries":    map[string]any{"@id": "https://example.org/vocab#carries", "@type": "@id"},
		"proof":      map[string]any{"@id": "https://w3id.org/security#proof", "@type": "@id"},
	}

	data := []any{
		map[string]any{
			"identifier": "https://example.org/presentation",
			"carries":    "https://example.org/credential",
			"proof":      map[string]any{"type": "DataIntegrityProof", "proofValue": "zROOT"},
		},
		map[string]any{
			"identifier": "https://example.org/credential",
			"proof":      map[string]any{"type": "DataIntegrityProof", "proofValue": "zEMBEDDED"},
		},
	}

	stripped, err := removeRootProofUnder(data, context, nil)
	require.NoError(t, err)

	encoded, err := json.Marshal(stripped)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "zROOT",
		"the root's own proof is the one removed")
	require.Contains(t, string(encoded), "zEMBEDDED",
		"and the embedded credential's proof is content the signature covers")
}
