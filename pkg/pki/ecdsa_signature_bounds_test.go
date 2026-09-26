package pki

import (
	"crypto/elliptic"
	"encoding/asn1"
	"math/big"
	"testing"
)

// EncodeECDSASignature sizes its buffer from the curve and then copies R and
// S in right-aligned. A component wider than the curve makes that offset
// negative and the copy panics with "slice bounds out of range" - reachable
// from any DER signature ECDSASignatureToP1363 is asked to convert, so a
// malformed or hostile one took the process down instead of being rejected.
func TestEncodeECDSASignature_RefusesOversizedComponents(t *testing.T) {
	wide := new(big.Int).SetBytes(bytesOf(0xff, 33)) // P-256 holds 32
	ok := big.NewInt(1)

	for _, tt := range []struct {
		name string
		r, s *big.Int
	}{
		{"R too wide", wide, ok},
		{"S too wide", ok, wide},
		{"both too wide", wide, wide},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// A panic here fails the test rather than being recovered: the
			// point is that it no longer happens.
			if _, err := EncodeECDSASignature(tt.r, tt.s, elliptic.P256()); err == nil {
				t.Fatal("want a refusal for a component wider than the curve")
			}
		})
	}
}

// asn1.Unmarshal leaves R or S nil for a truncated DER sequence, and
// (*big.Int)(nil).Bytes() dereferences nil - so the width check had to move
// ahead of those calls, not merely exist.
func TestEncodeECDSASignature_RefusesNilComponents(t *testing.T) {
	var missing *big.Int

	for _, tt := range []struct {
		name string
		r, s *big.Int
	}{
		{"R missing", missing, big.NewInt(1)},
		{"S missing", big.NewInt(1), missing},
		{"both missing", missing, missing},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := EncodeECDSASignature(tt.r, tt.s, elliptic.P256()); err == nil {
				t.Fatal("want a refusal for a missing component")
			}
		})
	}
}

// The shape asn1 actually produces: a SEQUENCE with nothing in it. It errors
// on unmarshal, so the converter returns before encoding - this pins that
// the encoder would survive it anyway, since it is exported and other
// callers do not have that guard.
func TestECDSASignatureToP1363_TruncatedSequence(t *testing.T) {
	if _, err := ECDSASignatureToP1363([]byte{0x30, 0x00}, elliptic.P256()); err == nil {
		t.Fatal("a truncated DER sequence must be refused, not panic")
	}
}

// big.Int.Bytes() discards the sign, so -1 and 1 would encode identically.
func TestEncodeECDSASignature_RefusesNegativeComponents(t *testing.T) {
	if _, err := EncodeECDSASignature(big.NewInt(-1), big.NewInt(1), elliptic.P256()); err == nil {
		t.Fatal("want a refusal for a negative R")
	}
	if _, err := EncodeECDSASignature(big.NewInt(1), big.NewInt(-1), elliptic.P256()); err == nil {
		t.Fatal("want a refusal for a negative S")
	}
}

// And the same through the conversion entry point, which is how a signature
// off the wire actually arrives.
func TestECDSASignatureToP1363_RefusesMalformedDER(t *testing.T) {
	der, err := asn1.Marshal(ecdsaASN1Signature{
		R: new(big.Int).SetBytes(bytesOf(0xff, 33)),
		S: big.NewInt(1),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if _, err := ECDSASignatureToP1363(der, elliptic.P256()); err == nil {
		t.Fatal("a DER signature with an oversized R must be refused, not panic")
	}
}

// A well-formed signature still round-trips, so the guard has not swallowed
// the normal case.
func TestECDSASignatureToP1363_AcceptsWellFormedDER(t *testing.T) {
	r, s := big.NewInt(0x1234), big.NewInt(0x5678)
	der, err := asn1.Marshal(ecdsaASN1Signature{R: r, S: s})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	got, err := ECDSASignatureToP1363(der, elliptic.P256())
	if err != nil {
		t.Fatalf("ECDSASignatureToP1363: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("got %d bytes, want 64", len(got))
	}
	gotR, gotS, err := DecodeECDSASignature(got, elliptic.P256())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gotR.Cmp(r) != 0 || gotS.Cmp(s) != 0 {
		t.Fatalf("round trip changed the values: got (%v,%v)", gotR, gotS)
	}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
