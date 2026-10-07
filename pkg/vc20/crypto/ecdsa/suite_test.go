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

func TestSignAndVerify(t *testing.T) {
	// 1. Generate key pair
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// 2. Create credential
	credentialJSON := []byte(`{
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			"https://www.w3.org/ns/credentials/examples/v2"
		],
		"id": "http://university.example/credentials/3732",
		"type": ["VerifiableCredential", "ExampleDegreeCredential"],
		"issuer": "https://university.example/issuers/14",
		"validFrom": "2010-01-01T19:23:24Z",
		"credentialSubject": {
			"id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
			"degree": {
				"type": "ExampleBachelorDegree",
				"name": "Bachelor of Science and Arts"
			}
		}
	}`)

	cred, err := credential.NewRDFCredentialFromJSON(credentialJSON, nil)
	if err != nil {
		t.Fatalf("Failed to create credential: %v", err)
	}

	// 3. Sign
	suite := NewSuite()
	opts := &SignOptions{
		VerificationMethod: "https://university.example/issuers/14#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	}

	signedCred, err := suite.Sign(context.Background(), cred, key, opts)
	if err != nil {
		t.Fatalf("Failed to sign credential: %v", err)
	}

	// 4. Verify
	err = suite.Verify(signedCred, &key.PublicKey)
	if err != nil {
		t.Fatalf("Failed to verify credential: %v", err)
	}
}

// TestVerifyProofSelectsByProofValue pins the mechanism the OpenID4VP handler
// now relies on: VerifyProof checks the proof carrying exactly the value it is
// given, and an empty value means "whichever proof is found first".
//
// Without this, passing a selector through from the handler would be
// ceremony - the suite has to actually honour it.
func TestVerifyProofSelectsByProofValue(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cred, err := credential.NewRDFCredentialFromJSON([]byte(`{
		"@context": "https://www.w3.org/ns/credentials/v2",
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject"}
	}`), nil)
	require.NoError(t, err)

	signed, err := NewSuite().Sign(context.Background(), cred, key, &SignOptions{
		VerificationMethod: "did:example:issuer#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	})
	require.NoError(t, err)

	suite := NewSuite()
	require.NoError(t, suite.Verify(signed, &key.PublicKey),
		"the empty selector takes the only proof there is")

	require.Error(t, suite.VerifyProof(signed, &key.PublicKey, "zNotTheProofValueOnThisDocument"),
		"a selector naming no proof in the document must not fall back to one that is there")
}
