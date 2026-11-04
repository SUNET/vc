package eddsa

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/multiformats/go-multibase"

	"github.com/SUNET/vc/pkg/vc20/credential"
)

// The fixture was signed by a second implementation (pyld URDNA2015 + PyNaCl), not by this
// package: a presentation carrying a credential whose subject, issuer and status entry are
// all named by IRI. verifiableCredential is an @graph container, so the credential's quads
// belong in a graph of their own in the document the holder signs.
const presentationFixture = "testdata/presentation_embedded_credential.json"

func fixtureKeys(t *testing.T) (ed25519.PrivateKey, []byte, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(presentationFixture)
	if err != nil {
		t.Fatal(err)
	}
	var vp map[string]any
	if err := json.Unmarshal(raw, &vp); err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("sirosid-fixture-holder"))
	return ed25519.NewKeyFromSeed(seed[:]), raw, vp
}

func TestVerifyProof_PresentationSignedElsewhere(t *testing.T) {
	priv, raw, vp := fixtureKeys(t)
	cred, err := credential.NewRDFCredentialFromJSON(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	pv := vp["proof"].(map[string]any)["proofValue"].(string)
	if err := NewSuite().VerifyProof(cred, priv.Public().(ed25519.PublicKey), pv); err != nil {
		t.Fatalf("a presentation signed by another implementation must verify: %v", err)
	}
}

func TestVerifyProof_PresentationTamperedCredential(t *testing.T) {
	priv, _, vp := fixtureKeys(t)
	vp["verifiableCredential"].(map[string]any)["issuer"] = map[string]any{"id": "did:web:other.example"}
	raw, _ := json.Marshal(vp)
	cred, err := credential.NewRDFCredentialFromJSON(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	pv := vp["proof"].(map[string]any)["proofValue"].(string)
	if err := NewSuite().VerifyProof(cred, priv.Public().(ed25519.PublicKey), pv); err == nil {
		t.Fatal("a presentation whose embedded credential changed must not verify")
	}
}

// Ed25519 is deterministic, so signing the same presentation with the same key and options
// must reproduce the other implementation's proofValue byte for byte.
func TestSign_PresentationMatchesOtherImplementation(t *testing.T) {
	priv, _, vp := fixtureKeys(t)
	want := vp["proof"].(map[string]any)
	unsigned := map[string]any{}
	for k, v := range vp {
		if k != "proof" {
			unsigned[k] = v
		}
	}
	raw, _ := json.Marshal(unsigned)
	cred, err := credential.NewRDFCredentialFromJSON(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	created, err := time.Parse(time.RFC3339, want["created"].(string))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := NewSuite().Sign(cred, priv, &SignOptions{
		VerificationMethod: want["verificationMethod"].(string),
		ProofPurpose:       want["proofPurpose"].(string),
		Created:            created,
		Domain:             want["domain"].(string),
		Challenge:          want["challenge"].(string),
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(signed.OriginalJSON()), &got); err != nil {
		t.Fatal(err)
	}
	gotProof, _ := got["proof"].(map[string]any)
	if gotProof == nil {
		t.Fatalf("signed presentation has no proof: %s", signed.OriginalJSON())
	}
	if _, _, err := multibase.Decode(gotProof["proofValue"].(string)); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(gotProof["proofValue"].(string), want["proofValue"].(string)) {
		t.Fatalf("proofValue differs from the other implementation's:\n got %v\nwant %v", gotProof["proofValue"], want["proofValue"])
	}
}
