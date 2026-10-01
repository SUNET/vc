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
