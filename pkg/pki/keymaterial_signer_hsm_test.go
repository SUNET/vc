package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// opaqueECDSAKey is shaped like a PKCS#11 key: it implements crypto.Signer
// and nothing else, so its private half is unreachable through the
// interface. That is how pkg/pki holds an HSM key - see signer_config.go's
// PrivateKey.(crypto.Signer) assertions - and it is the shape every branch
// here used to fall through to "unsupported key type".
type opaqueECDSAKey struct{ inner *ecdsa.PrivateKey }

func (o opaqueECDSAKey) Public() crypto.PublicKey { return o.inner.Public() }
func (o opaqueECDSAKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return o.inner.Sign(r, digest, opts)
}

func newHSMKeyMaterial(t *testing.T) (*KeyMaterial, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &KeyMaterial{
		PrivateKey:    opaqueECDSAKey{inner: key},
		SigningMethod: jwt.SigningMethodES256,
	}, &key.PublicKey
}

// The public half has to be reachable, or every caller that asks - the
// status-service startup check, and determineKeyID's kid derivation - sees
// an HSM key as having no public key at all.
func TestKeyMaterialSigner_HSMPublicKey(t *testing.T) {
	km, want := newHSMKeyMaterial(t)
	got, ok := NewKeyMaterialSigner(km).PublicKey().(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("an HSM key's public half must be reachable")
	}
	if !got.Equal(want) {
		t.Fatal("wrong public key")
	}
}

// And it has to actually sign. Exposing the public key while Sign still
// rejects the key type would start cleanly and fail on the first signature,
// which is worse than refusing at startup.
func TestKeyMaterialSigner_HSMSigns(t *testing.T) {
	km, pub := newHSMKeyMaterial(t)
	signer := NewKeyMaterialSigner(km)

	data := []byte("client assertion signing input")
	sig, err := signer.Sign(context.Background(), data)
	if err != nil {
		t.Fatalf("an HSM key must be able to sign: %v", err)
	}

	// Verified against the public half, so this checks the signature rather
	// than merely that no error came back. crypto.Signer returns ASN.1 DER
	// for ECDSA, which the Signer interface documents and jose.MakeJWT
	// converts for JWS.
	digest := sha256.Sum256(data)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("signature does not verify against the key's public half")
	}
}

func TestKeyMaterialSigner_HSMSignsDigest(t *testing.T) {
	km, pub := newHSMKeyMaterial(t)
	signer := NewKeyMaterialSigner(km)

	digest := sha256.Sum256([]byte("pre-computed"))
	sig, err := signer.SignDigest(context.Background(), digest[:])
	if err != nil {
		t.Fatalf("an HSM key must be able to sign a digest: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("digest signature does not verify")
	}
}

// The review finding named PKCS11PrivateKey specifically: "PublicKey()
// returns nil for PKCS11PrivateKey (and its signing switch does not handle
// that type)". These use the real type rather than a stand-in, so the claim
// is tested where it was made.
func realPKCS11KeyMaterial(t *testing.T) (*KeyMaterial, *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &KeyMaterial{
		PrivateKey: &PKCS11PrivateKey{
			// A real HSM fills these from the device. The public half is a
			// plain field, so the type can be exercised without one.
			Config:    &PKCS11Config{ModulePath: "/nonexistent/module.so"},
			KeyLabel:  "test-key",
			PublicKey: &key.PublicKey,
		},
		SigningMethod: jwt.SigningMethodES256,
	}, &key.PublicKey
}

func TestKeyMaterialSigner_RealPKCS11KeyExposesItsPublicHalf(t *testing.T) {
	km, want := realPKCS11KeyMaterial(t)

	got, ok := NewKeyMaterialSigner(km).PublicKey().(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("PublicKey() must not return nil for a PKCS11PrivateKey")
	}
	if !got.Equal(want) {
		t.Fatal("wrong public key")
	}
}

// Signing needs a real device, so this asserts the ROUTING rather than a
// signature: the type switch must reach the crypto.Signer branch and fail
// inside the HSM call, not bounce off "unsupported key type" before getting
// there. Those two failures look alike in a log and are not alike at all -
// one is a missing module, the other is the key being unusable by design.
func TestKeyMaterialSigner_RealPKCS11KeyReachesTheSigningPath(t *testing.T) {
	km, _ := realPKCS11KeyMaterial(t)
	signer := NewKeyMaterialSigner(km)

	_, err := signer.Sign(context.Background(), []byte("data"))
	if err == nil {
		t.Skip("signing unexpectedly succeeded; a real PKCS#11 module must be present")
	}
	if strings.Contains(err.Error(), "unsupported key type") {
		t.Fatalf("the type switch rejected a PKCS11PrivateKey before reaching the HSM: %v", err)
	}
}
