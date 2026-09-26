package pki

import (
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// EncodeECDSASignature converts ECDSA signature components (r, s) to IEEE P1363 format.
// This is the fixed-size R||S concatenation format required by JWT (RFC 7518 section 3.4).
// ASN.1 DER encoding is NOT used for JWT ECDSA signatures.
func EncodeECDSASignature(r, s *big.Int, curve elliptic.Curve) ([]byte, error) {
	// Determine the key size based on curve
	keySize := GetKeySizeForCurve(curve)
	if keySize == 0 {
		return nil, fmt.Errorf("unsupported curve: %s", curve.Params().Name)
	}

	// Create fixed-size signature buffer
	signature := make([]byte, 2*keySize)

	// Encode R and S as fixed-size big-endian integers
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Copy R into first half (right-aligned, zero-padded on left)
	copy(signature[keySize-len(rBytes):keySize], rBytes)

	// Copy S into second half (right-aligned, zero-padded on left)
	copy(signature[2*keySize-len(sBytes):], sBytes)

	return signature, nil
}

// GetKeySizeForCurve returns the key size in bytes for a given curve.
func GetKeySizeForCurve(curve elliptic.Curve) int {
	switch curve.Params().Name {
	case "P-256":
		return 32 // ES256
	case "P-384":
		return 48 // ES384
	case "P-521":
		return 66 // ES512
	default:
		return 0
	}
}

// DecodeECDSASignature decodes an IEEE P1363 format ECDSA signature to (r, s) big integers.
// This is the inverse of EncodeECDSASignature.
func DecodeECDSASignature(signature []byte, curve elliptic.Curve) (*big.Int, *big.Int, error) {
	keySize := GetKeySizeForCurve(curve)
	if keySize == 0 {
		return nil, nil, fmt.Errorf("unsupported curve: %s", curve.Params().Name)
	}

	if len(signature) != 2*keySize {
		return nil, nil, fmt.Errorf("invalid signature length: expected %d, got %d", 2*keySize, len(signature))
	}

	r := new(big.Int).SetBytes(signature[:keySize])
	s := new(big.Int).SetBytes(signature[keySize:])

	return r, s, nil
}

// ecdsaASN1Signature is the DER structure crypto.Signer backends return for
// ECDSA: SEQUENCE { r INTEGER, s INTEGER }.
type ecdsaASN1Signature struct {
	R, S *big.Int
}

// ECDSASignatureToP1363 converts an ECDSA signature to IEEE P1363, accepting
// either form.
//
// HSM and other crypto.Signer backends return ASN.1 DER, while JWS (RFC 7518
// §3.4) and pki.RawSigner both require the fixed-size R||S concatenation. A
// signature already of the expected length is returned unchanged, so a
// backend that does the right thing costs nothing.
func ECDSASignatureToP1363(signature []byte, curve elliptic.Curve) ([]byte, error) {
	keySize := GetKeySizeForCurve(curve)
	if keySize == 0 {
		return nil, fmt.Errorf("unsupported curve: %s", curve.Params().Name)
	}
	if len(signature) == 2*keySize {
		return signature, nil
	}

	var parsed ecdsaASN1Signature
	rest, err := asn1.Unmarshal(signature, &parsed)
	if err != nil {
		return nil, fmt.Errorf("ECDSA signature is %d bytes (expected %d) and is not valid ASN.1 DER: %w",
			len(signature), 2*keySize, err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("ECDSA signature has %d trailing bytes after ASN.1 DER decoding", len(rest))
	}

	return EncodeECDSASignature(parsed.R, parsed.S, curve)
}
