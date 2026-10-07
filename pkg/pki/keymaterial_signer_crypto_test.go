package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"io"
	"math/big"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// opaqueKey is a crypto.Signer that is neither *ecdsa.PrivateKey nor
// *rsa.PrivateKey - the shape a PKCS#11 key has. encoding chooses what its
// Sign returns, because the two real implementations disagree: Go's own
// ecdsa returns ASN.1 DER, PKCS#11's CKM_ECDSA returns IEEE P1363.
type opaqueKey struct {
	inner    *ecdsa.PrivateKey
	encoding string // "der" or "p1363"
	signs    int
}

func (k *opaqueKey) Public() crypto.PublicKey { return k.inner.Public() }

func (k *opaqueKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	k.signs++
	r, s, err := ecdsa.Sign(rand.Reader, k.inner, digest)
	if err != nil {
		return nil, err
	}
	if k.encoding == "p1363" {
		return EncodeECDSASignature(r, s, k.inner.Curve)
	}
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

func newOpaqueKey(t *testing.T, encoding string) *opaqueKey {
	t.Helper()
	inner, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &opaqueKey{inner: inner, encoding: encoding}
}

func opaqueSigner(t *testing.T, key *opaqueKey) *KeyMaterialSigner {
	t.Helper()
	return NewKeyMaterialSigner(&KeyMaterial{
		PrivateKey:    key,
		SigningMethod: jwt.SigningMethodES256,
	})
}

// A key the signer cannot see inside - an HSM key over PKCS#11 - used to
// hit the default branch of every type switch in KeyMaterialSigner, so an
// HSM-backed issuer could not sign at all. initSigner's comment says
// "software or PKCS#11"; LoadSigner's says it "handles both software and
// HSM keys".
func TestKeyMaterialSignerSignsWithAnOpaqueKey(t *testing.T) {
	for _, encoding := range []string{"der", "p1363"} {
		t.Run(encoding, func(t *testing.T) {
			key := newOpaqueKey(t, encoding)
			signer := opaqueSigner(t, key)

			sig, err := signer.Sign(t.Context(), []byte("payload to sign"))
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			if key.signs == 0 {
				t.Fatal("the key was never asked to sign")
			}

			// JWT wants IEEE P1363 whatever the key returned, and it has
			// to verify against the key's own public half.
			if len(sig) != 64 {
				t.Fatalf("signature is %d bytes, want 64 (IEEE P1363 for P-256)", len(sig))
			}
			digest := sha256.Sum256([]byte("payload to sign"))
			r := new(big.Int).SetBytes(sig[:32])
			s := new(big.Int).SetBytes(sig[32:])
			if !ecdsa.Verify(&key.inner.PublicKey, digest[:], r, s) {
				t.Error("the signature does not verify against the key's public half")
			}
		})
	}
}

func TestKeyMaterialSignerSignDigestWithAnOpaqueKey(t *testing.T) {
	key := newOpaqueKey(t, "p1363")
	signer := opaqueSigner(t, key)

	digest := sha256.Sum256([]byte("pre-computed"))
	sig, err := signer.SignDigest(t.Context(), digest[:])
	if err != nil {
		t.Fatalf("SignDigest() error = %v", err)
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&key.inner.PublicKey, digest[:], r, s) {
		t.Error("the signature does not verify against the key's public half")
	}
}

// PublicKey returning nil published a JWK with no key in it (see
// internal/issuer/apiv1/jwk.go, which builds the JWKS entry from exactly
// this and KeyID).
func TestKeyMaterialSignerExposesAnOpaqueKeysPublicHalf(t *testing.T) {
	key := newOpaqueKey(t, "p1363")

	got := opaqueSigner(t, key).PublicKey()
	if got == nil {
		t.Fatal("PublicKey() = nil; the JWKS entry would carry no key")
	}
	pub, ok := got.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey() = %T, want *ecdsa.PublicKey", got)
	}
	if !pub.Equal(&key.inner.PublicKey) {
		t.Error("PublicKey() is not this key's public half")
	}
}

// Every certificate-less HSM key got the same kid, "default-key", so a
// JWKS consumer could not tell two of them apart and picked the wrong one
// after a rotation. Two distinct keys must get two distinct ids.
func TestDetermineKeyIDDistinguishesOpaqueKeys(t *testing.T) {
	first := opaqueSigner(t, newOpaqueKey(t, "p1363")).KeyID()
	second := opaqueSigner(t, newOpaqueKey(t, "p1363")).KeyID()

	for name, kid := range map[string]string{"first": first, "second": second} {
		if kid == "default-key" {
			t.Fatalf("%s key: KeyID() = %q - every HSM key would share it", name, kid)
		}
	}
	if first == second {
		t.Errorf("two different keys share the kid %q", first)
	}
}

// A key that can do nothing at all still has to produce something rather
// than panic.
func TestDetermineKeyIDFallsBackForAKeyThatCannotSign(t *testing.T) {
	signer := NewKeyMaterialSigner(&KeyMaterial{
		PrivateKey:    "not a key at all",
		SigningMethod: jwt.SigningMethodES256,
	})
	if got := signer.KeyID(); got != "default-key" {
		t.Errorf("KeyID() = %q, want the fallback", got)
	}
	if got := signer.PublicKey(); got != nil {
		t.Errorf("PublicKey() = %v, want nil", got)
	}
	if _, err := signer.Sign(t.Context(), []byte("x")); err == nil {
		t.Error("expected an error for a key that cannot sign")
	}
}

// normalizeECDSASignature discriminates by LENGTH, never by sniffing the
// first byte for 0x30. A P1363 signature starts with 0x30 once in 256
// tries, so a sniffing implementation has a one-in-256 failure that only
// shows up in production - this repo has already shipped that bug once.
func TestNormalizeECDSASignatureDoesNotSniffTheFirstByte(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// A valid 64-byte P1363 signature whose first byte is 0x30, which a
	// first-byte check would mistake for an ASN.1 SEQUENCE.
	var r, s *big.Int
	for range 100000 {
		digest := make([]byte, 32)
		if _, err := rand.Read(digest); err != nil {
			t.Fatal(err)
		}
		cr, cs, err := ecdsa.Sign(rand.Reader, key, digest)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeECDSASignature(cr, cs, key.Curve)
		if err != nil {
			t.Fatal(err)
		}
		if encoded[0] == 0x30 {
			r, s = cr, cs
			break
		}
	}
	if r == nil {
		t.Skip("no 0x30-leading signature found; the point still stands")
	}

	p1363, err := EncodeECDSASignature(r, s, key.Curve)
	if err != nil {
		t.Fatal(err)
	}
	got, err := normalizeECDSASignature(p1363, key.Curve)
	if err != nil {
		t.Fatalf("a P1363 signature beginning 0x30 was refused: %v", err)
	}
	if string(got) != string(p1363) {
		t.Error("a P1363 signature was altered")
	}
}

func TestNormalizeECDSASignatureRefusesRubbish(t *testing.T) {
	for name, sig := range map[string][]byte{
		"empty":            {},
		"short":            make([]byte, 10),
		"not DER":          append(make([]byte, 70), 0xff),
		"DER with trailer": derWithTrailer(t),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeECDSASignature(sig, elliptic.P256()); err == nil {
				t.Fatal("expected a refusal")
			}
		})
	}
}

func derWithTrailer(t *testing.T) []byte {
	t.Helper()
	der, err := asn1.Marshal(struct{ R, S *big.Int }{big.NewInt(1), big.NewInt(2)})
	if err != nil {
		t.Fatal(err)
	}
	return append(der, 0x00)
}
