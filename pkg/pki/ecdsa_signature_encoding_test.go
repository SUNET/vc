package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"testing"
)

// derOfExactly64Bytes builds a well-formed P-256 DER ECDSA signature that is
// exactly 2*keySize bytes long, which is the case length alone cannot tell
// apart from IEEE P1363.
//
// DER is 6 bytes of framing plus r and s, so 64 total needs len(r)+len(s)=58.
// Two 29-byte scalars with a high bit clear (no sign padding) give that.
func derOfExactly64Bytes(t *testing.T) ([]byte, *big.Int, *big.Int) {
	t.Helper()

	rb := make([]byte, 29)
	sb := make([]byte, 29)
	for i := range rb {
		rb[i] = byte(i + 1)
		sb[i] = byte(200 - i)
	}
	rb[0] &= 0x7f // keep DER from adding a 0x00 sign byte
	sb[0] &= 0x7f

	r := new(big.Int).SetBytes(rb)
	s := new(big.Int).SetBytes(sb)

	der, err := asn1.Marshal(ecdsaASN1Signature{R: r, S: s})
	if err != nil {
		t.Fatalf("asn1.Marshal: %v", err)
	}
	if len(der) != 64 {
		t.Fatalf("fixture is %d bytes, needed exactly 64 to exercise the ambiguity", len(der))
	}
	return der, r, s
}

// TestECDSASignatureToP1363_DEROfP1363Length is the regression test: a valid
// DER signature that happens to be exactly 64 bytes used to be returned
// UNCHANGED, because the length check ran first. The result is the right
// length and simply does not verify - a silent wrong answer, not an error.
func TestECDSASignatureToP1363_DEROfP1363Length(t *testing.T) {
	der, r, s := derOfExactly64Bytes(t)

	got, err := ECDSASignatureToP1363(der, elliptic.P256())
	if err != nil {
		t.Fatalf("ECDSASignatureToP1363: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("got %d bytes, want 64", len(got))
	}

	// The conversion must be a real one: r and s left-padded to the curve
	// width, not the DER bytes handed back.
	wantR := make([]byte, 32)
	wantS := make([]byte, 32)
	r.FillBytes(wantR)
	s.FillBytes(wantS)

	for i := 0; i < 32; i++ {
		if got[i] != wantR[i] {
			t.Fatalf("R half was not converted: got %x, want %x (the DER bytes were returned verbatim)", got[:32], wantR)
		}
		if got[32+i] != wantS[i] {
			t.Fatalf("S half was not converted: got %x, want %x", got[32:], wantS)
		}
	}
}

// TestECDSASignatureToP1363_RealP1363IsUntouched keeps the other direction
// honest: trying DER first must not break an ordinary raw signature.
func TestECDSASignatureToP1363_RealP1363IsUntouched(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := sha256.Sum256([]byte("payload"))

	for range 200 {
		r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		raw := make([]byte, 64)
		r.FillBytes(raw[:32])
		s.FillBytes(raw[32:])

		got, err := ECDSASignatureToP1363(raw, elliptic.P256())
		if err != nil {
			t.Fatalf("a raw P1363 signature must be accepted: %v", err)
		}
		if string(got) != string(raw) {
			t.Fatalf("a raw P1363 signature was altered:\n got %x\nwant %x", got, raw)
		}
	}
}

// TestECDSASignatureToP1363_RealDERRoundTrips covers the ordinary DER case,
// which is what an HSM actually returns.
func TestECDSASignatureToP1363_RealDERRoundTrips(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := sha256.Sum256([]byte("payload"))

	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}
	got, err := ECDSASignatureToP1363(der, elliptic.P256())
	if err != nil {
		t.Fatalf("ECDSASignatureToP1363: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("got %d bytes, want 64", len(got))
	}
	if !ecdsa.Verify(&key.PublicKey,
		digest[:],
		new(big.Int).SetBytes(got[:32]),
		new(big.Int).SetBytes(got[32:])) {
		t.Fatal("converted signature does not verify")
	}
}

// TestECDSASignatureToP1363_OutOfRangeScalarsAreNotDER: the scalar range
// check is what stops a raw signature that happens to parse as DER from
// being "converted". Without it the ambiguity would be decided by parse
// success alone.
func TestECDSASignatureToP1363_OutOfRangeScalarsAreNotDER(t *testing.T) {
	n := elliptic.P256().Params().N
	if validECDSAScalars(new(big.Int).Set(n), big.NewInt(1), elliptic.P256()) {
		t.Fatal("r == N must be rejected: valid scalars are [1, N-1]")
	}
	if validECDSAScalars(big.NewInt(0), big.NewInt(1), elliptic.P256()) {
		t.Fatal("r == 0 must be rejected")
	}
	if !validECDSAScalars(big.NewInt(1), new(big.Int).Sub(n, big.NewInt(1)), elliptic.P256()) {
		t.Fatal("the endpoints of [1, N-1] must be accepted")
	}
}

// declaringSigner reports a fixed ECDSA encoding, the way a PKCS#11 signer
// using CKM_ECDSA does.
type declaringSigner struct {
	pub      *ecdsa.PublicKey
	encoding ECDSASignatureEncoding
}

func (d declaringSigner) Public() crypto.PublicKey { return d.pub }
func (d declaringSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("not used")
}
func (d declaringSigner) ECDSASignatureEncoding() ECDSASignatureEncoding { return d.encoding }

// TestECDSASignatureToP1363For_DeclaredRawIsNeverReparsed is the HSM case.
// CKM_ECDSA returns raw R||S, and a raw 64-byte signature can be
// structurally valid DER - inference would then "convert" it into different
// R/S values and the resulting JWS or Data Integrity proof would simply not
// verify. A signer that knows must be believed.
func TestECDSASignatureToP1363For_DeclaredRawIsNeverReparsed(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := declaringSigner{pub: &key.PublicKey, encoding: ECDSAEncodingP1363}

	// A raw signature whose bytes ALSO happen to be well-formed DER: the
	// exact collision inference cannot resolve.
	raw, _, _ := derOfExactly64Bytes(t)

	got, err := ECDSASignatureToP1363For(signer, raw, elliptic.P256())
	if err != nil {
		t.Fatalf("ECDSASignatureToP1363For: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("a declared-raw signature was reinterpreted:\n got %x\nwant %x", got, raw)
	}
}

// TestECDSASignatureToP1363For_DeclaredRawWrongLengthIsAnError: the signer
// said what it produces, so a mismatch is a fault to report rather than a
// case to fall back from.
func TestECDSASignatureToP1363For_DeclaredRawWrongLengthIsAnError(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := declaringSigner{pub: &key.PublicKey, encoding: ECDSAEncodingP1363}

	if _, err := ECDSASignatureToP1363For(signer, make([]byte, 70), elliptic.P256()); err == nil {
		t.Fatal("a declared-raw signature of the wrong length must be an error")
	}
}

// TestECDSASignatureToP1363For_UndeclaredFallsBackToInference keeps the
// generic crypto.Signer path working - most backends say nothing.
func TestECDSASignatureToP1363For_UndeclaredFallsBackToInference(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	digest := sha256.Sum256([]byte("payload"))
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}

	got, err := ECDSASignatureToP1363For(key, der, elliptic.P256())
	if err != nil {
		t.Fatalf("ECDSASignatureToP1363For: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("got %d bytes, want 64", len(got))
	}
}

// TestNormalizeHSMECDSASignature_AsksTheSigner covers the CALL SITE, not
// just the helper: normalizeHSMECDSASignature must consult the signer's
// declared encoding rather than inferring, or an HSM's raw output whose
// bytes happen to parse as DER is silently converted to different R/S.
func TestNormalizeHSMECDSASignature_AsksTheSigner(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer := declaringSigner{pub: &key.PublicKey, encoding: ECDSAEncodingP1363}

	raw, _, _ := derOfExactly64Bytes(t)

	got, err := normalizeHSMECDSASignature(signer, raw)
	if err != nil {
		t.Fatalf("normalizeHSMECDSASignature: %v", err)
	}
	if string(got) != string(raw) {
		t.Fatalf("the HSM path reinterpreted a declared-raw signature:\n got %x\nwant %x", got, raw)
	}
}
