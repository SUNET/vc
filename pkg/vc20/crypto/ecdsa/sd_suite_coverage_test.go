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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSdSuite_Sign_InputValidation(t *testing.T) {
	suite := NewSdSuite()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cred := &credential.RDFCredential{} // Empty credential
	opts := &SdSignOptions{
		VerificationMethod: "did:example:123#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	}

	t.Run("Nil Credential", func(t *testing.T) {
		_, err := suite.Sign(nil, key, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "credential is nil")
	})

	t.Run("Nil Key", func(t *testing.T) {
		_, err := suite.Sign(cred, nil, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "private key is nil")
	})

	t.Run("Nil Options", func(t *testing.T) {
		_, err := suite.Sign(cred, key, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "sign options are nil")
	})
}

func TestSdSuite_Verify_InputValidation(t *testing.T) {
	suite := NewSdSuite()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cred := &credential.RDFCredential{}

	t.Run("Nil Credential", func(t *testing.T) {
		err := suite.Verify(nil, &key.PublicKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "credential is nil")
	})

	t.Run("Nil Key", func(t *testing.T) {
		err := suite.Verify(cred, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "public key is nil")
	})
}

func TestSdSuite_Derive_InputValidation(t *testing.T) {
	suite := NewSdSuite()

	t.Run("Nil Credential", func(t *testing.T) {
		_, err := suite.Derive(nil, []int{}, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "credential is nil")
	})
}

func TestSdSuite_Verify_TamperedProof(t *testing.T) {
	// Setup
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
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

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
	credBytes, _ := json.Marshal(credJSON)
	ldOpts := ld.NewJsonLdOptions("")
	cred, _ := credential.NewRDFCredentialFromJSON(credBytes, ldOpts)

	opts := &SdSignOptions{
		VerificationMethod: "did:example:123#key-1",
		ProofPurpose:       "assertionMethod",
		Created:            time.Now().UTC(),
	}

	signedCred, err := suite.Sign(cred, key, opts)
	require.NoError(t, err)

	// Debug: print signed credential
	signedJSON, _ := json.Marshal(signedCred)
	// t.Logf("Signed Credential: %s", string(signedJSON))

	// Tamper with the proof
	// 1. Get proof object
	// Instead of GetProofObject, let's work with the map directly
	var signedObj any
	err = json.Unmarshal(signedJSON, &signedObj)
	require.NoError(t, err)

	// Find proof in the object structure
	// It could be a map or a list of maps
	var proof map[string]any

	// Helper to find proof
	var findProof func(any) map[string]any
	findProof = func(obj any) map[string]any {
		if m, ok := obj.(map[string]any); ok {
			// Check if this is the proof
			if types, ok := m["@type"].([]any); ok {
				for _, t := range types {
					if t == "https://w3id.org/security#DataIntegrityProof" || t == "DataIntegrityProof" {
						return m
					}
				}
			}
			// Check properties
			if p, ok := m["proof"]; ok {
				if found := findProof(p); found != nil {
					return found
				}
			}
			if p, ok := m["https://w3id.org/security#proof"]; ok {
				if found := findProof(p); found != nil {
					return found
				}
			}
			// Check graph
			if g, ok := m["@graph"]; ok {
				if found := findProof(g); found != nil {
					return found
				}
			}
		} else if list, ok := obj.([]any); ok {
			for _, item := range list {
				if found := findProof(item); found != nil {
					return found
				}
			}
		}
		return nil
	}

	proof = findProof(signedObj)
	require.NotNil(t, proof, "Proof not found in signed credential")

	proofJSON := proof

	// 2. Tamper with proofValue
	var proofValue string

	// Helper to extract string value
	getString := func(v any) string {
		if s, ok := v.(string); ok {
			return s
		}
		if list, ok := v.([]any); ok && len(list) > 0 {
			if m, ok := list[0].(map[string]any); ok {
				if val, ok := m["@value"].(string); ok {
					return val
				}
			}
		}
		return ""
	}

	if v, ok := proofJSON["proofValue"]; ok {
		proofValue = getString(v)
	} else if v, ok := proofJSON["https://w3id.org/security#proofValue"]; ok {
		proofValue = getString(v)
	} else if v, ok := proofJSON["https://www.w3.org/ns/credentials#proofValue"]; ok {
		proofValue = getString(v)
	}

	if proofValue == "" {
		t.Fatalf("proofValue not found in proof JSON: %v", proofJSON)
	}

	// Tamper with a character in the middle of the base signature region
	// The proof value format is: multibase prefix (u) + base64url(CBOR tag + [baseSignature, ...])
	// We change a character around position 10 to affect the base signature
	var tamperedProofValue string
	if len(proofValue) > 15 {
		// Change character at position 10 (in the base signature region)
		tamperedRunes := []rune(proofValue)
		// Toggle a bit by changing the character
		if tamperedRunes[10] == 'A' {
			tamperedRunes[10] = 'B'
		} else {
			tamperedRunes[10] = 'A'
		}
		tamperedProofValue = string(tamperedRunes)
	} else {
		tamperedProofValue = proofValue[:len(proofValue)-1] + "A"
	}

	// Update proofJSON
	// We need to preserve the structure
	if _, ok := proofJSON["proofValue"]; ok {
		proofJSON["proofValue"] = tamperedProofValue
	} else if _, ok := proofJSON["https://w3id.org/security#proofValue"]; ok {
		// It's a list of objects
		list := proofJSON["https://w3id.org/security#proofValue"].([]any)
		obj := list[0].(map[string]any)
		obj["@value"] = tamperedProofValue
		// No need to reassign list/obj as they are references (maps/slices)
	} else if _, ok := proofJSON["https://www.w3.org/ns/credentials#proofValue"]; ok {
		list := proofJSON["https://www.w3.org/ns/credentials#proofValue"].([]any)
		obj := list[0].(map[string]any)
		obj["@value"] = tamperedProofValue
	}

	// 3. Update credential with tampered proof
	// We use signedObj which has been modified in place (maps/slices are references)
	tamperedCredBytes, _ := json.Marshal(signedObj)
	tamperedCred, _ := credential.NewRDFCredentialFromJSON(tamperedCredBytes, ldOpts)

	// Verify should fail
	err = suite.Verify(tamperedCred, &key.PublicKey)
	assert.Error(t, err)
	// The error might be decoding error or verification error depending on how we broke it
}
