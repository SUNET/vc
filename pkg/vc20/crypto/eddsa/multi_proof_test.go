package eddsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/vc20/credential"
)

// A verifiable presentation carries TWO proofs: the holder's over the
// presentation, and the embedded credential's issuer proof. Verify used to
// take whichever FindProofNodeFunc reached first, so it could check the
// holder's key against the issuer's proofValue - or report the embedded
// credential's issuer proof as if it were the presentation's.
//
// The traversal was made deterministic earlier, which stopped that
// FLAPPING between runs. It did not make it right: a stable wrong answer is
// worse than an unstable one, because nothing surfaces it.
func TestVerifyRefusesAMultiProofDocument(t *testing.T) {
	suite := NewSuite()

	holderPub, holderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key: %v", err)
	}
	_, issuerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate issuer key: %v", err)
	}

	sign := func(t *testing.T, doc []byte, key ed25519.PrivateKey, vm string) *credential.RDFCredential {
		t.Helper()
		cred, err := credential.NewRDFCredentialFromJSON(doc, nil)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		signed, err := suite.Sign(cred, key, &SignOptions{
			VerificationMethod: vm,
			ProofPurpose:       "assertionMethod",
			Created:            time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		})
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return signed
	}

	signedCred := sign(t, []byte(`{
		"@context": ["https://www.w3.org/ns/credentials/v2"],
		"type": ["VerifiableCredential"],
		"issuer": "did:example:issuer",
		"credentialSubject": {"id": "did:example:subject", "name": "Test Subject"}
	}`), issuerPriv, "did:example:issuer#key-1")

	credJSON, err := signedCred.ToCompactJSON()
	if err != nil {
		t.Fatalf("serialize signed credential: %v", err)
	}
	var embedded map[string]any
	if err := json.Unmarshal(credJSON, &embedded); err != nil {
		t.Fatalf("decode signed credential: %v", err)
	}

	presentation, err := json.Marshal(map[string]any{
		"@context":             []string{"https://www.w3.org/ns/credentials/v2"},
		"type":                 []string{"VerifiablePresentation"},
		"holder":               "did:example:holder",
		"verifiableCredential": []any{embedded},
	})
	if err != nil {
		t.Fatalf("build presentation: %v", err)
	}
	signedVP := sign(t, presentation, holderPriv, "did:example:holder#key-1")

	// The fixture's own precondition. Without this the assertion below
	// could pass against a presentation that never embedded anything.
	vpJSON, err := signedVP.ToCompactJSON()
	if err != nil {
		t.Fatalf("serialize presentation: %v", err)
	}
	if got := strings.Count(string(vpJSON), "proofValue"); got != 2 {
		t.Fatalf("the fixture must carry two proofs, found %d proofValue members in %s", got, vpJSON)
	}

	err = suite.Verify(signedVP, holderPub)
	if err == nil {
		t.Fatal("Verify must refuse a document holding more than one proof")
	}
	// The SPECIFIC refusal, not merely an error: this document could fail
	// for several unrelated reasons, and any of them would make a bare
	// require.Error vacuous.
	if !strings.Contains(err.Error(), "none was named") {
		t.Fatalf("wrong refusal, so this test is not exercising the guard: %v", err)
	}

	// The control: naming a proof gets PAST this guard. Without it, a
	// Verify that refused every document would satisfy the assertion above.
	//
	// It does NOT assert the signature checks out. On this branch a
	// presentation's signature does not cover the embedded credential's
	// proof correctly - canonicalization removes every proof in the graph
	// rather than only the one being secured - so this returns
	// "signature verification failed". That is SUNET/vc#720's fix, not
	// this PR's, and asserting success here would be asserting behaviour
	// this branch does not have. What matters for this guard is that the
	// refusal is specifically about naming.
	var vp map[string]any
	if err := json.Unmarshal(vpJSON, &vp); err != nil {
		t.Fatalf("decode presentation: %v", err)
	}
	proof, ok := vp["proof"].(map[string]any)
	if !ok {
		t.Fatalf("presentation has no top-level proof: %v", vp["proof"])
	}
	holderProofValue, _ := proof["proofValue"].(string)
	if holderProofValue == "" {
		t.Fatal("no holder proofValue to name")
	}
	if err := suite.VerifyProof(signedVP, holderPub, holderProofValue); err != nil &&
		strings.Contains(err.Error(), "none was named") {
		t.Fatalf("naming a proof must get past the multi-proof guard, got: %v", err)
	}
}
