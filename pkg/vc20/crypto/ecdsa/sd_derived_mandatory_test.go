package ecdsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/multiformats/go-multibase"

	"github.com/SUNET/vc/pkg/vc20/credential"
)

// The fixture is a derived ecdsa-sd-2023 credential produced by a second implementation (pyld URDNA2015,
// cbor2, cryptography), not by this package. Five of its six N-Quads are mandatory, so the issuer's
// base signature covers a hash of them: a verifier that hashes none (a derived proof from a credential
// issued with no mandatory pointers) cannot check it.
type sdMandatoryFixture struct {
	IssuerPublicKeyMultibase string         `json:"issuerPublicKeyMultibase"`
	MandatoryIndexes         []int          `json:"mandatoryIndexes"`
	Credential               map[string]any `json:"credential"`
}

func loadSdMandatoryFixture(t *testing.T) (*sdMandatoryFixture, *ecdsa.PublicKey) {
	t.Helper()
	raw, err := os.ReadFile("testdata/sd_derived_mandatory.json")
	if err != nil {
		t.Fatal(err)
	}
	var f sdMandatoryFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	_, keyBytes, err := multibase.Decode(f.IssuerPublicKeyMultibase)
	if err != nil {
		t.Fatal(err)
	}
	if len(keyBytes) != 35 || keyBytes[0] != 0x80 || keyBytes[1] != 0x24 {
		t.Fatalf("fixture key is not a P-256 Multikey: % x", keyBytes[:2])
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), keyBytes[2:])
	if x == nil {
		t.Fatal("fixture issuer key is not a P-256 point")
	}
	return &f, &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
}

func verifySdFixture(t *testing.T, f *sdMandatoryFixture, key *ecdsa.PublicKey) error {
	t.Helper()
	raw, err := json.Marshal(f.Credential)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := credential.NewRDFCredentialFromJSON(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	return NewSdSuite().Verify(cred, key)
}

func TestSdVerify_DerivedProofWithMandatoryQuads(t *testing.T) {
	f, key := loadSdMandatoryFixture(t)
	if len(f.MandatoryIndexes) == 0 {
		t.Fatal("the fixture is only meaningful with mandatory quads")
	}
	if err := verifySdFixture(t, f, key); err != nil {
		t.Fatalf("a derived proof made elsewhere, with mandatory quads, must verify: %v", err)
	}
}

func TestSdVerify_DerivedProofRefusesChangedMandatoryClaim(t *testing.T) {
	f, key := loadSdMandatoryFixture(t)
	f.Credential["issuer"].(map[string]any)["name"] = "Someone Else"
	err := verifySdFixture(t, f, key)
	if err == nil || !strings.Contains(err.Error(), "base signature") {
		t.Fatalf("a changed mandatory claim must fail the base signature, got %v", err)
	}
}

func TestSdVerify_DerivedProofRefusesChangedDisclosedClaim(t *testing.T) {
	f, key := loadSdMandatoryFixture(t)
	f.Credential["credentialSubject"].(map[string]any)["description"] = "Forged description"
	err := verifySdFixture(t, f, key)
	if err == nil || !strings.Contains(err.Error(), "N-Quad") {
		t.Fatalf("a changed disclosed claim must fail its own signature, got %v", err)
	}
}

func TestSdVerify_DerivedProofRefusesWrongIssuerKey(t *testing.T) {
	f, _ := loadSdMandatoryFixture(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifySdFixture(t, f, &other.PublicKey); err == nil {
		t.Fatal("a derived proof must not verify under a key that is not the issuer's")
	}
}
