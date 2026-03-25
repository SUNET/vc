package jose

import (
	"crypto/elliptic"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
)

// ecdsaASN1Signature represents an ASN.1 DER-encoded ECDSA signature.
type ecdsaASN1Signature struct {
	R, S *big.Int
}

// jwsECKeySizes maps JWS algorithm names to the expected byte size of each
// R/S component in IEEE P1363 format.
var jwsECKeySizes = map[string]int{
	"ES256": 32, // P-256
	"ES384": 48, // P-384
	"ES512": 66, // P-521
}

// ensureJWSSignature normalizes an ECDSA signature to JWS format (IEEE P1363: fixed-size R||S).
//
// Many crypto.Signer implementations (including PKCS#11 HSMs and Go's standard library)
// return ASN.1 DER-encoded ECDSA signatures. JWS (RFC 7518 §3.4) requires the raw
// fixed-size R||S concatenation instead. This function detects DER-encoded signatures
// and converts them; signatures already in JWS format pass through unchanged.
//
// For non-ECDSA algorithms (RS256, RS384, etc.), the signature is returned as-is.
func ensureJWSSignature(signature []byte, algorithm string) ([]byte, error) {
	keySize, isEC := jwsECKeySizes[algorithm]
	if !isEC {
		// Not an EC algorithm — no conversion needed (RSA, EdDSA, etc.)
		return signature, nil
	}

	expectedLen := 2 * keySize

	// If the signature is already the expected JWS length, assume it's correct.
	if len(signature) == expectedLen {
		return signature, nil
	}

	// Attempt to parse as ASN.1 DER-encoded ECDSA signature.
	var parsed ecdsaASN1Signature
	rest, err := asn1.Unmarshal(signature, &parsed)
	if err != nil {
		return nil, fmt.Errorf("ECDSA signature for %s has unexpected length %d (expected %d) and is not valid ASN.1 DER: %w",
			algorithm, len(signature), expectedLen, err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("ECDSA signature for %s has %d trailing bytes after ASN.1 DER decoding",
			algorithm, len(rest))
	}

	// Convert from ASN.1 {R, S} to IEEE P1363 fixed-size R||S.
	return encodeFixedSizeRS(parsed.R, parsed.S, keySize)
}

// encodeFixedSizeRS encodes R and S as fixed-size big-endian integers, each
// zero-padded to keySize bytes, and concatenated as R||S.
func encodeFixedSizeRS(r, s *big.Int, keySize int) ([]byte, error) {
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	if len(rBytes) > keySize || len(sBytes) > keySize {
		return nil, fmt.Errorf("r or s component exceeds expected key size %d", keySize)
	}

	sig := make([]byte, 2*keySize)
	copy(sig[keySize-len(rBytes):keySize], rBytes)
	copy(sig[2*keySize-len(sBytes):], sBytes)

	return sig, nil
}

// curveForAlgorithm returns the elliptic curve for a JWS EC algorithm name.
// Returns nil if the algorithm is not a recognized EC algorithm.
func curveForAlgorithm(algorithm string) elliptic.Curve {
	switch strings.ToUpper(algorithm) {
	case "ES256":
		return elliptic.P256()
	case "ES384":
		return elliptic.P384()
	case "ES512":
		return elliptic.P521()
	default:
		return nil
	}
}
