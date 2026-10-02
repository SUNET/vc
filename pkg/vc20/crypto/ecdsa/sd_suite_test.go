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

func TestSdSuite_SignVerifyDerive(t *testing.T) {
	// 1. Setup
	// Preload example context to avoid network requests
	loader := credential.GetGlobalLoader()
	exampleContext := `{
		"@context": {
			"@vocab": "https://www.w3.org/ns/credentials/examples/v2#",
			"UniversityDegreeCredential": "https://example.org/examples#UniversityDegreeCredential",
			"BachelorDegree": "https://example.org/examples#BachelorDegree",
			"degree": "https://example.org/examples#degree",
			"name": "https://schema.org/name"
		}
	}`
	loader.AddContext("https://www.w3.org/ns/credentials/examples/v2", exampleContext)

	suite := NewSdSuite()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create a simple credential
	credJSON := map[string]any{
		"@context": []any{
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2",
		},
		"id": "http://example.gov/credentials/3732",
		"type": []any{
			"VerifiableCredential",
			"UniversityDegreeCredential",
		},
		"issuer":    "did:example:123",
		"validFrom": "2023-01-01T00:00:00Z",
		"credentialSubject": map[string]any{
			"id": "did:example:456",
			"degree": map[string]any{
				"type": "BachelorDegree",
				"name": "Bachelor of Science and Arts",
			},
		},
	}

	credBytes, err := json.Marshal(credJSON)
	require.NoError(t, err)

	ldOpts := ld.NewJsonLdOptions("")
	cred, err := credential.NewRDFCredentialFromJSON(credBytes, ldOpts)
	require.NoError(t, err)

	// 2. Sign (Base Proof)
	opts := &SdSignOptions{
		VerificationMethod: "did:example:123#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	}

	signedCred, err := suite.Sign(cred, key, opts)
	require.NoError(t, err)
	require.NotNil(t, signedCred)

	// Verify Base Proof
	err = suite.Verify(signedCred, &key.PublicKey)
	require.NoError(t, err, "Base Proof verification failed")

	// 3. Derive (Derived Proof)
	// We need to know indices.
	// Since we don't know the order easily, let's try to reveal everything first.
	// Or we can inspect the signed credential to see how many quads there are.

	// Get quads count
	credWithoutProof, _ := signedCred.CredentialWithoutProof()
	nquadsStr, _ := credWithoutProof.CanonicalForm()
	quads := parseNQuads(nquadsStr)
	t.Logf("Total quads: %d", len(quads))

	// Reveal all
	revealIndices := make([]int, len(quads))
	for i := range quads {
		revealIndices[i] = i
	}

	derivedCred, err := suite.Derive(signedCred, revealIndices, "")
	require.NoError(t, err)
	require.NotNil(t, derivedCred)

	// Verify Derived Proof (Full Disclosure)
	err = suite.Verify(derivedCred, &key.PublicKey)
	require.NoError(t, err, "Derived Proof (Full) verification failed")

	// 4. Derive (Partial Disclosure)
	//
	// Reveal the credential's OWN quads and withhold the degree. A derived
	// credential has to keep the node it is about: a disclosure that drops
	// every triple of the credential leaves a document about the subject
	// instead, carrying the credential's proof, and a proof must not end up
	// securing a document nobody meant to sign. That case is the subtest
	// below.
	const credentialIRI = "<http://example.gov/credentials/3732>"
	var partialIndices []int
	for i, quad := range quads {
		if strings.HasPrefix(quad, credentialIRI) {
			partialIndices = append(partialIndices, i)
		}
	}
	require.NotEmpty(t, partialIndices, "the credential must have quads of its own to reveal")
	require.Less(t, len(partialIndices), len(quads), "and something must be left to withhold")

	derivedPartial, err := suite.Derive(signedCred, partialIndices, "")
	require.NoError(t, err)
	require.NotNil(t, derivedPartial)

	err = suite.Verify(derivedPartial, &key.PublicKey)
	require.NoError(t, err, "Derived Proof (Partial) verification failed")

	partialJSON, err := derivedPartial.ToJSON()
	require.NoError(t, err)
	require.NotContains(t, string(partialJSON), "Bachelor of Science and Arts",
		"the withheld degree must not survive the derivation")

	// Dropping the credential node itself is refused rather than derived.
	t.Run("a disclosure that drops the credential is refused", func(t *testing.T) {
		var subjectOnly []int
		for i, quad := range quads {
			if !strings.HasPrefix(quad, credentialIRI) {
				subjectOnly = append(subjectOnly, i)
			}
		}
		require.NotEmpty(t, subjectOnly)

		_, err := suite.Derive(signedCred, subjectOnly, "")
		require.ErrorContains(t, err, "no longer holds the node",
			"a derived credential must keep the node the base credential was about")
	})
}
