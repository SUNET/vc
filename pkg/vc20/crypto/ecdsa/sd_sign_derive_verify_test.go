package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

// signDeriveVerifyCredential has two blank nodes under one subject (degree and address
// are objects with no id), so canonicalisation labels them and the HMAC relabelling can
// move them past one another. One blank node is not enough to show an ordering bug:
// every quad with a blank node subject sorts after every quad with an IRI subject
// whatever the label is, so a single label cannot change the order of anything.
func signDeriveVerifyCredential(t *testing.T) *credential.RDFCredential {
	t.Helper()
	credential.GetGlobalLoader().AddContext("https://www.w3.org/ns/credentials/examples/v2", `{
		"@context": {
			"@vocab": "https://www.w3.org/ns/credentials/examples/v2#",
			"UniversityDegreeCredential": "https://example.org/examples#UniversityDegreeCredential",
			"BachelorDegree": "https://example.org/examples#BachelorDegree",
			"degree": "https://example.org/examples#degree",
			"address": "https://example.org/examples#address",
			"name": "https://schema.org/name"
		}
	}`)

	raw, err := json.Marshal(map[string]any{
		"@context": []any{
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2",
		},
		"id":        "http://example.gov/credentials/3732",
		"type":      []any{"VerifiableCredential", "UniversityDegreeCredential"},
		"issuer":    "did:example:123",
		"validFrom": "2023-01-01T00:00:00Z",
		"credentialSubject": map[string]any{
			"id": "did:example:456",
			"degree": map[string]any{
				"type": "BachelorDegree",
				"name": "Bachelor of Science and Arts",
			},
			"address": map[string]any{
				"name": "12 Example Street",
			},
		},
	})
	require.NoError(t, err)
	cred, err := credential.NewRDFCredentialFromJSON(raw, ld.NewJsonLdOptions(""))
	require.NoError(t, err)
	return cred
}

func signWithMandatory(t *testing.T, key *ecdsa.PrivateKey) (*SdSuite, *credential.RDFCredential, int) {
	t.Helper()
	suite := NewSdSuite()
	signed, err := suite.Sign(signDeriveVerifyCredential(t), key, &SdSignOptions{
		VerificationMethod: "did:example:123#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
		MandatoryPointers:  []string{"/issuer", "/validFrom"},
	})
	require.NoError(t, err)

	withoutProof, err := signed.CredentialWithoutProof()
	require.NoError(t, err)
	nquads, err := withoutProof.CanonicalForm()
	require.NoError(t, err)
	return suite, signed, len(parseNQuads(nquads))
}

// TestSdSuite_SignDeriveVerifyWithMandatoryPointers: a credential this package signs,
// derives from and verifies, with mandatory pointers - the whole round trip in one
// implementation, which is the one thing the external fixtures cannot cover.
//
// The rounds are not redundant. Each Sign draws a fresh random HMAC key, and the key is
// what decides where the relabelled blank nodes sort; an ordering that signs one quad
// and checks another therefore fails for some keys and passes for others. One round is
// a coin toss, and this failed about half of them before the orders were aligned.
func TestSdSuite_SignDeriveVerifyWithMandatoryPointers(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for round := range 20 {
		suite, signed, quadCount := signWithMandatory(t, key)
		require.NoError(t, suite.Verify(signed, &key.PublicKey), "round %d: the base proof must verify", round)

		reveal := make([]int, quadCount)
		for i := range reveal {
			reveal[i] = i
		}
		derived, err := suite.Derive(signed, reveal, "")
		require.NoError(t, err, "round %d", round)
		require.NoError(t, suite.Verify(derived, &key.PublicKey),
			"round %d: a derived proof this package produced must verify here", round)
	}
}

// TestSdSuite_DeriveRevealsASubset: the point of the cryptosuite. The holder discloses
// some of the non-mandatory quads; the mandatory ones come along, and the result still
// verifies under the issuer's key.
func TestSdSuite_DeriveRevealsASubset(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	for round := range 20 {
		suite, signed, _ := signWithMandatory(t, key)
		derived, err := suite.Derive(signed, []int{0}, "")
		require.NoError(t, err, "round %d", round)
		require.NoError(t, suite.Verify(derived, &key.PublicKey),
			"round %d: a partially disclosed credential must verify", round)

		require.Contains(t, derived.OriginalJSON(), "did:example:123", "round %d: the mandatory issuer is disclosed", round)
	}
}

// TestSdSuite_DerivedProofRefusesAChangedMandatoryClaim: a mandatory claim is covered by
// the issuer's base signature through the mandatory hash, so changing one in the
// disclosed document must fail a signature check. It holds on both sides of the ordering
// fix - it guards that tampering is caught at all, not the order the quads are read in,
// which is what the round trips above cover.
func TestSdSuite_DerivedProofRefusesAChangedMandatoryClaim(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	suite, signed, quadCount := signWithMandatory(t, key)
	reveal := make([]int, quadCount)
	for i := range reveal {
		reveal[i] = i
	}
	derived, err := suite.Derive(signed, reveal, "")
	require.NoError(t, err)

	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(derived.OriginalJSON()), &doc))
	doc["issuer"] = "did:example:someone-else"
	tampered, err := json.Marshal(doc)
	require.NoError(t, err)
	forged, err := credential.NewRDFCredentialFromJSON(tampered, ld.NewJsonLdOptions(""))
	require.NoError(t, err)

	err = suite.Verify(forged, &key.PublicKey)
	require.Error(t, err, "a changed mandatory claim must not verify")
	require.True(t, strings.Contains(err.Error(), "base signature") || strings.Contains(err.Error(), "N-Quad"),
		"the failure must be a signature check, got %v", err)
}
