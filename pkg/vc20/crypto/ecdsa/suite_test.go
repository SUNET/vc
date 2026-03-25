package ecdsa

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"
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
