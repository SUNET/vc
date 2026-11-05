package openid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"
	ecdsaSuite "github.com/SUNET/vc/pkg/vc20/crypto/ecdsa"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

// signedTestCredential returns a credential carrying its ISSUER's Data
// Integrity proof, which is the second proof a presentation ends up holding.
func signedTestCredential(t *testing.T, issuerKey *ecdsa.PrivateKey) []byte {
	t.Helper()

	raw := `{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"}
	}`

	cred, err := credential.NewRDFCredentialFromJSON([]byte(raw), nil)
	require.NoError(t, err)

	signed, err := ecdsaSuite.NewSuite().Sign(t.Context(), cred, issuerKey, &ecdsaSuite.SignOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	out, err := json.Marshal(signed)
	require.NoError(t, err)
	return out
}

// TestVerifyPresentationProof_SelectsTheHolderProof exercises the shape the
// selection exists for: a presentation carrying TWO Data Integrity proofs,
// the holder's over the presentation and the embedded credential's from the
// issuer.
//
// Both reach the suite. ProofObject() collects proof quads from every graph,
// and the compacted result holds two DataIntegrityProof nodes - measured,
// not assumed; the assertions below fail if a change ever stops producing
// both, because then this test would be about nothing.
//
// Which one an unqualified search returns is decided by the order json-gold
// happens to assign the blank nodes. Today that puts the holder's proof
// first, so the old code worked by luck rather than by construction; there
// is nothing in the pipeline that promises it, and a document shaped
// differently gets a different answer. This test pins the working case
// against the selection change; the selection itself is pinned directly in
// pkg/vc20/crypto/common (TestFindProofNodeFunc_SelectsTheNamedProof), on a
// document ordered so that the unqualified search reaches the wrong proof.
func TestVerifyPresentationProof_SelectsTheHolderProof(t *testing.T) {
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	const (
		nonce  = "test-nonce-12345"
		domain = "https://verifier.example.com"
		holder = "did:key:z6MkHolder"
	)

	vpBytes, err := NewVPBuilder().BuildVC20Presentation(
		[][]byte{signedTestCredential(t, issuerKey)},
		holderKey,
		&VPBuildOptions{
			HolderDID:          holder,
			VerificationMethod: holder + "#key-1",
			Nonce:              nonce,
			Domain:             domain,
			Cryptosuite:        CryptosuiteECDSA2019,
			Created:            time.Now().UTC(),
		},
	)
	require.NoError(t, err)

	var vpMap map[string]any
	require.NoError(t, json.Unmarshal(vpBytes, &vpMap))

	// Both proofs really do reach the selection - otherwise this test is
	// about nothing. Counted where it matters: in the compacted proof
	// object the suite searches, not in the VP JSON, where the embedded
	// credential is an opaque string.
	require.Contains(t, vpMap, "proof", "the presentation carries the holder's proof")
	require.Len(t, compactedProofValues(t, vpBytes), 2,
		"the suite sees the holder's proof and the issuer's")

	h := &VC20Handler{
		keyResolver:          &StaticVC20KeyResolver{Key: &holderKey.PublicKey},
		requireHolderBinding: true,
		expectedChallenge:    nonce,
		expectedDomain:       domain,
	}

	got, err := h.verifyPresentationProof(t.Context(), vpBytes, vpMap)
	require.NoError(t, err, "the holder's own proof must be the one verified")
	require.Equal(t, holder, got)
}

// compactedProofValues returns every proofValue in the compacted proof
// object a Data Integrity suite searches, mirroring the steps Verify takes.
func compactedProofValues(t *testing.T, vpBytes []byte) []string {
	t.Helper()

	vpCred, err := credential.NewRDFCredentialFromJSON(vpBytes, nil)
	require.NoError(t, err)
	proofCred, err := vpCred.ProofObject()
	require.NoError(t, err)

	proofJSONBytes, err := json.Marshal(proofCred)
	require.NoError(t, err)
	var proofJSON any
	require.NoError(t, json.Unmarshal(proofJSONBytes, &proofJSON))

	compacted, err := ld.NewJsonLdProcessor().Compact(proofJSON,
		map[string]any{"@context": credential.ContextV2}, credential.NewJSONLDOptions(""))
	require.NoError(t, err)

	var found []string
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if pv, ok := t["proofValue"].(string); ok {
				found = append(found, pv)
			}
			for _, x := range t {
				walk(x)
			}
		case []any:
			for _, x := range t {
				walk(x)
			}
		}
	}
	walk(compacted)
	return found
}
