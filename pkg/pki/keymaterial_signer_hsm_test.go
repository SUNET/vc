package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"io"
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
