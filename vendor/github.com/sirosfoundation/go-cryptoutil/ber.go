package cryptoutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// NormalizeECDSASignature takes an ECDSA signature that may be BER-encoded
// (with unnecessary leading zeros, wrong padding, etc.) and returns a
// strictly DER-encoded signature. This is needed because some authenticators
// (notably YubiKey 5.8 firmware) produce BER-encoded signatures that Go's
// strict DER parser in crypto/x509 rejects.
//
// BER (Basic Encoding Rules) is more permissive than DER (Distinguished
// Encoding Rules). While both are valid ASN.1, X.509 signatures should
// use DER. This function normalizes BER to DER by:
// 1. Leniently parsing the BER-encoded ASN.1 SEQUENCE
// 2. Extracting the raw r and s integer values
// 3. Re-encoding as strict DER
//
// Returns the original signature unchanged if it's already valid DER,
// or an error if it cannot be parsed as an ECDSA signature at all.
func NormalizeECDSASignature(sig []byte) ([]byte, error) {
	// Try lenient BER parsing first
	r, s, err := parseBERSignature(sig)
	if err != nil {
		return nil, fmt.Errorf("cryptoutil: failed to parse ECDSA signature: %w", err)
	}

	if r.Sign() < 0 || s.Sign() < 0 {
		return nil, errors.New("cryptoutil: ECDSA signature has negative component")
	}

	// Re-encode as strict DER
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return nil, fmt.Errorf("cryptoutil: failed to re-encode ECDSA signature: %w", err)
	}
	return der, nil
}

// parseBERSignature parses a BER-encoded ECDSA signature, tolerating
// common BER variations like non-minimally encoded integers.
func parseBERSignature(sig []byte) (r, s *big.Int, err error) {
	if len(sig) < 6 {
		return nil, nil, errors.New("signature too short")
	}

	// Check for SEQUENCE tag
	if sig[0] != 0x30 {
		return nil, nil, errors.New("expected SEQUENCE tag")
	}

	// Parse length (simple case only - short form)
	seqLen := int(sig[1])
	if seqLen&0x80 != 0 {
		// Long form length encoding
		numLenBytes := seqLen & 0x7f
		if numLenBytes > 2 || len(sig) < 2+numLenBytes {
			return nil, nil, errors.New("invalid length encoding")
		}
		seqLen = 0
		for i := 0; i < numLenBytes; i++ {
			seqLen = seqLen<<8 | int(sig[2+i])
		}
		sig = sig[2+numLenBytes:]
	} else {
		sig = sig[2:]
	}

	if len(sig) < seqLen {
		return nil, nil, errors.New("sequence truncated")
	}
	sig = sig[:seqLen]

	// Parse first INTEGER (r)
	r, sig, err = parseBERInteger(sig)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing r: %w", err)
	}

	// Parse second INTEGER (s)
	s, sig, err = parseBERInteger(sig)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing s: %w", err)
	}

	if len(sig) > 0 {
		return nil, nil, errors.New("trailing data after signature")
	}

	return r, s, nil
}

// parseBERInteger parses a BER-encoded INTEGER, tolerating non-minimal encoding
func parseBERInteger(data []byte) (*big.Int, []byte, error) {
	if len(data) < 2 {
		return nil, nil, errors.New("integer too short")
	}

	// Check for INTEGER tag
	if data[0] != 0x02 {
		return nil, nil, errors.New("expected INTEGER tag")
	}

	// Parse length
	intLen := int(data[1])
	rest := data[2:]
	if intLen&0x80 != 0 {
		// Long form length
		numLenBytes := intLen & 0x7f
		if numLenBytes > 2 || len(rest) < numLenBytes {
			return nil, nil, errors.New("invalid integer length encoding")
		}
		intLen = 0
		for i := 0; i < numLenBytes; i++ {
			intLen = intLen<<8 | int(rest[i])
		}
		rest = rest[numLenBytes:]
	}

	if len(rest) < intLen {
		return nil, nil, errors.New("integer truncated")
	}

	intBytes := rest[:intLen]
	rest = rest[intLen:]

	// Skip leading zeros (BER allows them, DER doesn't)
	for len(intBytes) > 1 && intBytes[0] == 0x00 && (intBytes[1]&0x80) == 0 {
		intBytes = intBytes[1:]
	}

	// Convert to big.Int
	val := new(big.Int).SetBytes(intBytes)

	return val, rest, nil
}

// BERTolerantECDSAVerifier returns a SignatureVerifier that handles ECDSA
// signatures with BER encoding. It normalizes the signature to DER before
// verification. This is useful as a fallback when the standard x509
// CheckSignature fails due to BER-encoded signatures.
//
// Usage:
//
//	ext := cryptoutil.New()
//	ext.Verifiers = append(ext.Verifiers, cryptoutil.BERTolerantECDSAVerifier())
func BERTolerantECDSAVerifier() SignatureVerifier {
	return func(cert *x509.Certificate, algo x509.SignatureAlgorithm, signed, signature []byte) error {
		// Only handle ECDSA algorithms
		if !isECDSAAlgorithm(algo) {
			return ErrNotHandled
		}

		// Check if the certificate has an ECDSA public key
		ecPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return ErrNotHandled
		}

		// Determine hash from algorithm
		hashFunc, err := hashFromSignatureAlgorithm(algo)
		if err != nil {
			return ErrNotHandled
		}

		// Try to normalize the signature (handles BER -> DER conversion)
		normalizedSig, err := NormalizeECDSASignature(signature)
		if err != nil {
			// If we can't parse it at all, let someone else handle it
			return ErrNotHandled
		}

		// Hash the signed data
		h := hashFunc.New()
		h.Write(signed)
		digest := h.Sum(nil)

		// Parse the normalized signature
		var parsedSig struct {
			R, S *big.Int
		}
		if _, err := asn1.Unmarshal(normalizedSig, &parsedSig); err != nil {
			return ErrNotHandled
		}

		// Verify
		if !ecdsa.Verify(ecPub, digest, parsedSig.R, parsedSig.S) {
			return errors.New("cryptoutil: ECDSA verification failed")
		}
		return nil
	}
}

// isECDSAAlgorithm returns true if the algorithm is an ECDSA variant.
func isECDSAAlgorithm(algo x509.SignatureAlgorithm) bool {
	switch algo {
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return true
	default:
		return false
	}
}

// hashFromSignatureAlgorithm extracts the hash function from an x509 signature algorithm.
func hashFromSignatureAlgorithm(algo x509.SignatureAlgorithm) (crypto.Hash, error) {
	switch algo {
	case x509.ECDSAWithSHA1, x509.SHA1WithRSA, x509.DSAWithSHA1:
		return crypto.SHA1, nil
	case x509.ECDSAWithSHA256, x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.DSAWithSHA256:
		return crypto.SHA256, nil
	case x509.ECDSAWithSHA384, x509.SHA384WithRSA, x509.SHA384WithRSAPSS:
		return crypto.SHA384, nil
	case x509.ECDSAWithSHA512, x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
		return crypto.SHA512, nil
	case x509.PureEd25519:
		return 0, nil // Ed25519 doesn't use pre-hashing
	default:
		return 0, fmt.Errorf("cryptoutil: unsupported signature algorithm %v", algo)
	}
}
