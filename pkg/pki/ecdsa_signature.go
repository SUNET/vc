package pki

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

// encodeECDSASignature converts ECDSA signature components (r, s) to IEEE P1363 format.
// This is the fixed-size R||S concatenation format required by JWT (RFC 7518 section 3.4).
// ASN.1 DER encoding is NOT used for JWT ECDSA signatures.
func encodeECDSASignature(r, s *big.Int, curve elliptic.Curve) ([]byte, error) {
	// Determine the key size based on curve
	keySize := getKeySizeForCurve(curve)
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

// getKeySizeForCurve returns the key size in bytes for a given curve.
func getKeySizeForCurve(curve elliptic.Curve) int {
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
