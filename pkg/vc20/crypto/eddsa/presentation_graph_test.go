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

// Both fixtures were signed by a second implementation (pyld URDNA2015 + PyNaCl), not by
// this package. verifiableCredential is an @graph container, so each embedded credential's
// quads belong in a graph of their own in the document the holder signs.
const (
	// presentationFixture carries one credential whose subject, issuer and status entry
	// are all named by IRI.
	presentationFixture = "testdata/presentation_embedded_credential.json"
	// sharedIssuerFixture is the case a traversal of the flattened dataset cannot get
	// right: TWO credentials that name the same issuer by IRI and describe it, over a
	// holder the presentation itself also describes. Every description belongs to
	// whichever graph the document put it in - the issuer's name in both credential
	// graphs, the presentation's own description of the holder in the default graph -
	// and no walk of the merged quads can recover that, because flattening has already
	// put one copy of each description in one place.
	sharedIssuerFixture = "testdata/presentation_shared_issuer_iri.json"
)

func fixtureKeys(t *testing.T, path string) (ed25519.PrivateKey, []byte, map[string]any) {
	t.Helper()
	raw, err := os.ReadFile(path)
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
	for name, path := range map[string]string{
		"one embedded credential":   presentationFixture,
		"two sharing an issuer IRI": sharedIssuerFixture,
	} {
		t.Run(name, func(t *testing.T) {
			priv, raw, vp := fixtureKeys(t, path)
			cred, err := credential.NewRDFCredentialFromJSON(raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			pv := vp["proof"].(map[string]any)["proofValue"].(string)
			if err := NewSuite().VerifyProof(cred, priv.Public().(ed25519.PublicKey), pv); err != nil {
				t.Fatalf("a presentation signed by another implementation must verify: %v", err)
			}
		})
	}
}

func TestVerifyProof_PresentationTamperedCredential(t *testing.T) {
	priv, _, vp := fixtureKeys(t, presentationFixture)
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
// must reproduce the other implementation's proofValue byte for byte. That pins the graph
// placement, where verification alone could only show this package agreeing with itself.
func TestSign_PresentationMatchesOtherImplementation(t *testing.T) {
	for name, path := range map[string]string{
		"one embedded credential":   presentationFixture,
		"two sharing an issuer IRI": sharedIssuerFixture,
	} {
		t.Run(name, func(t *testing.T) {
			priv, _, vp := fixtureKeys(t, path)
			want := vp["proof"].(map[string]any)
			gotProof := signLikeFixture(t, priv, vp)
			if _, _, err := multibase.Decode(gotProof["proofValue"].(string)); err != nil {
				t.Fatal(err)
			}
			if !strings.EqualFold(gotProof["proofValue"].(string), want["proofValue"].(string)) {
				t.Fatalf("proofValue differs from the other implementation's:\n got %v\nwant %v", gotProof["proofValue"], want["proofValue"])
			}
		})
	}
}

// signLikeFixture signs the fixture presentation, minus its proof, with the options its own
// proof carries, and returns the proof this package produced.
func signLikeFixture(t *testing.T, priv ed25519.PrivateKey, vp map[string]any) map[string]any {
	t.Helper()
	want := vp["proof"].(map[string]any)
	unsigned := map[string]any{}
	for k, v := range vp {
		if k != "proof" {
			unsigned[k] = v
		}
	}
	raw, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatal(err)
	}
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
	return gotProof
}
