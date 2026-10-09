package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"io"
	"math/big"
	"strings"
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

// Neither shortcut is safe, and the tests have to pin both.
//
// A P1363 signature begins 0x30 once in 256 tries, so sniffing the first
// byte is a one-in-256 failure. And a DER SEQUENCE of two INTEGERs costs 6
// bytes of overhead, so for P-256 any |r|+|s| == 58 gives a DER signature
// exactly 64 bytes long - which is also the P1363 length. Deciding by
// length returns those DER bytes as if they were P1363, and the signature
// fails verification wherever it lands.
func TestNormalizeECDSASignatureDoesNotSniffTheFirstByte(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// A valid 64-byte P1363 signature whose first byte is 0x30, which a
	// first-byte check would mistake for an ASN.1 SEQUENCE.
	var digest, p1363 []byte
	for range 100000 {
		candidate := make([]byte, 32)
		if _, err := rand.Read(candidate); err != nil {
			t.Fatal(err)
		}
		r, s, err := ecdsa.Sign(rand.Reader, key, candidate)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeECDSASignature(r, s, key.Curve)
		if err != nil {
			t.Fatal(err)
		}
		if encoded[0] == 0x30 {
			digest, p1363 = candidate, encoded
			break
		}
	}
	if p1363 == nil {
		t.Skip("no 0x30-leading signature found; the point still stands")
	}

	got, err := normalizeECDSASignature(p1363, &key.PublicKey, digest)
	if err != nil {
		t.Fatalf("a P1363 signature beginning 0x30 was refused: %v", err)
	}
	if string(got) != string(p1363) {
		t.Error("a P1363 signature was altered")
	}
}

// The other shortcut: a 64-byte input that is valid DER must not be
// returned as if it were P1363.
//
// Built by hand rather than sampled. A real one needs r and s together
// three bytes short of the curve, which happens about once in 4e13
// signatures - too rare to find and exactly why deciding by length is the
// kind of rule that holds until it does not.
func TestNormalizeECDSASignatureRefusesA64ByteDER(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		t.Fatal(err)
	}

	// 0x30 0x3e | 0x02 0x1d <29 bytes> | 0x02 0x1d <29 bytes> = 64 bytes.
	der := []byte{0x30, 0x3e, 0x02, 0x1d}
	der = append(der, bytes.Repeat([]byte{0x11}, 29)...)
	der = append(der, 0x02, 0x1d)
	der = append(der, bytes.Repeat([]byte{0x22}, 29)...)
	if len(der) != 64 {
		t.Fatalf("hand-built DER is %d bytes, want 64", len(der))
	}
	var parsed struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		t.Fatalf("hand-built DER does not parse: %v", err)
	}

	got, err := normalizeECDSASignature(der, &key.PublicKey, digest)
	if err == nil {
		t.Fatalf("a 64-byte DER was accepted and returned as %x", got)
	}
	// Refused because nothing verified, not because the length was wrong -
	// the length is the thing that used to be trusted.
	if !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("error = %v, want it refused on verification", err)
	}
}

// A normal-length DER signature from a software signer is still converted.
func TestNormalizeECDSASignatureConvertsDER(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		t.Fatal(err)
	}
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatal(err)
	}

	got, err := normalizeECDSASignature(der, &key.PublicKey, digest)
	if err != nil {
		t.Fatalf("normalizeECDSASignature() error = %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("converted signature is %d bytes, want 64", len(got))
	}
	if !ecdsa.Verify(&key.PublicKey, digest,
		new(big.Int).SetBytes(got[:32]), new(big.Int).SetBytes(got[32:])) {
		t.Error("the converted signature does not verify")
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

// opaqueRSAKey is a crypto.Signer that behaves the way the PKCS#11 binding
// does for an RSA key: it pads only, and relies on the caller having
// wrapped the digest in a DigestInfo. It records the opts it was handed,
// because passing them through is the thing being checked - the binding
// used to ignore them entirely and sign the bare digest.
type opaqueRSAKey struct {
	inner    *rsa.PrivateKey
	gotHash  crypto.Hash
	gotOpts  crypto.SignerOpts
	signs    int
	wrapFunc func([]byte, crypto.SignerOpts) ([]byte, error)
}

func (k *opaqueRSAKey) Public() crypto.PublicKey { return k.inner.Public() }

func (k *opaqueRSAKey) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	k.signs++
	k.gotOpts = opts
	k.gotHash = opts.HashFunc()

	toSign, err := k.wrapFunc(digest, opts)
	if err != nil {
		return nil, err
	}
	// crypto.Hash(0) pads only, which is exactly CKM_RSA_PKCS.
	return rsa.SignPKCS1v15(rand.Reader, k.inner, crypto.Hash(0), toSign)
}

// An RSA key behind the crypto.Signer fallback has to produce a signature
// a standard RS256 verifier accepts, and the hash has to reach it - the
// PKCS#11 binding ignored SignerOpts and signed the bare digest, which
// verifies as nothing.
func TestKeyMaterialSignerRSAThroughAnOpaqueKey(t *testing.T) {
	inner, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key := &opaqueRSAKey{inner: inner, wrapFunc: pkcs1v15DigestInfo}

	signer := NewKeyMaterialSigner(&KeyMaterial{
		PrivateKey:    key,
		SigningMethod: jwt.SigningMethodRS256,
	})

	sig, err := signer.Sign(t.Context(), []byte("payload to sign"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	if key.signs == 0 {
		t.Fatal("the key was never asked to sign")
	}
	if key.gotHash != crypto.SHA256 {
		t.Errorf("the key was handed hash %v, want SHA-256 - RS256 needs it to build the DigestInfo", key.gotHash)
	}

	digest := sha256.Sum256([]byte("payload to sign"))
	if err := rsa.VerifyPKCS1v15(&inner.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Errorf("a standard RS256 verifier rejects the signature: %v", err)
	}
}
