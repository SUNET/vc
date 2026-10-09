package pki

import (
	"crypto"
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

	// Every check below has to come BEFORE r.Bytes(), because those calls
	// are themselves the hazard:
	//
	//   nil    - asn1.Unmarshal leaves R or S nil for a truncated DER
	//            sequence, and (*big.Int)(nil).Bytes() dereferences nil.
	//   sign   - big.Int.Bytes() discards it, so -1 and 1 encode alike.
	//   width  - a value wider than the curve makes keySize-len(bytes)
	//            negative, and the copy below panics with "slice bounds out
	//            of range".
	//
	// All three are reachable from any DER signature this package is asked
	// to convert, so a malformed or hostile one would take the process down
	// rather than be rejected.
	if r == nil || s == nil {
		return nil, fmt.Errorf("ECDSA signature is missing its R or S component")
	}
	if r.Sign() < 0 || s.Sign() < 0 {
		return nil, fmt.Errorf("ECDSA signature components must be non-negative")
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()

	if len(rBytes) > keySize || len(sBytes) > keySize {
		return nil, fmt.Errorf("ECDSA signature component is %d/%d bytes, too wide for curve %s (%d bytes)",
			len(rBytes), len(sBytes), curve.Params().Name, keySize)
	}

	// Create fixed-size signature buffer
	signature := make([]byte, 2*keySize)

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
// §3.4) and pki.RawSigner both require the fixed-size R||S concatenation.
//
// DER is tried FIRST, and length is only the fallback. Length cannot decide
// this: a valid P-256 DER signature is exactly 64 bytes whenever r and s
// together are six bytes short of full width, which happens for roughly one
// signature in 2^48 - and the old order returned those unchanged, handing
// back DER bytes labelled as P1363. That is silent: the value is the right
// length and simply does not verify. This repository has already been bitten
// by the mirror image of it (go-cryptoutil's RawSigToASN1 treating a leading
// 0x30 as proof of DER), which is why the decision is structural here.
//
// The residual ambiguity runs the other way - a raw R||S that happens to
// parse as well-formed DER - and is far smaller: it needs the first byte to
// be 0x30, the second to be the exact remaining length, the interior tags to
// line up, AND both integers to land in [1, N-1]. The range check below is
// what closes most of that gap, so it is not merely a sanity check.
func ECDSASignatureToP1363(signature []byte, curve elliptic.Curve) ([]byte, error) {
	keySize := GetKeySizeForCurve(curve)
	if keySize == 0 {
		return nil, fmt.Errorf("unsupported curve: %s", curve.Params().Name)
	}

	var parsed ecdsaASN1Signature
	rest, derErr := asn1.Unmarshal(signature, &parsed)
	if derErr == nil && len(rest) == 0 && validECDSAScalars(parsed.R, parsed.S, curve) {
		return EncodeECDSASignature(parsed.R, parsed.S, curve)
	}

	if len(signature) == 2*keySize {
		return signature, nil
	}

	if derErr != nil {
		return nil, fmt.Errorf("ECDSA signature is %d bytes (expected %d) and is not valid ASN.1 DER: %w",
			len(signature), 2*keySize, derErr)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("ECDSA signature has %d trailing bytes after ASN.1 DER decoding", len(rest))
	}
	return nil, fmt.Errorf("ECDSA signature is %d bytes (expected %d) and its ASN.1 DER R/S are not valid scalars for %s",
		len(signature), 2*keySize, curve.Params().Name)
}

// validECDSAScalars reports whether r and s are in [1, N-1], the range a
// signature's components must occupy. Anything outside it did not come from
// signing with this curve, so a "DER" parse that produces one is a raw
// signature that happened to look like DER.
func validECDSAScalars(r, s *big.Int, curve elliptic.Curve) bool {
	if r == nil || s == nil {
		return false
	}
	n := curve.Params().N
	for _, v := range []*big.Int{r, s} {
		if v.Sign() <= 0 || v.Cmp(n) >= 0 {
			return false
		}
	}
	return true
}

// ECDSASignatureEncoding names the wire form a signer produces for ECDSA.
type ECDSASignatureEncoding int

const (
	// ECDSAEncodingUnknown means the signer does not say, and the encoding
	// has to be inferred. Everything that does not implement
	// ECDSASignatureEncodingReporter is this.
	ECDSAEncodingUnknown ECDSASignatureEncoding = iota
	// ECDSAEncodingP1363 is the fixed-width R||S concatenation.
	ECDSAEncodingP1363
	// ECDSAEncodingDER is the ASN.1 SEQUENCE of two INTEGERs.
	ECDSAEncodingDER
)

// ECDSASignatureEncodingReporter is implemented by signers that know which
// encoding they emit.
//
// Inference cannot be made exact in either direction - a DER signature can
// be exactly 2*keySize bytes, and a raw R||S can be structurally valid DER -
// so where the answer is actually known, it must be stated rather than
// guessed. A PKCS#11 signer using CKM_ECDSA knows: that mechanism is defined
// to return raw R||S.
type ECDSASignatureEncodingReporter interface {
	ECDSASignatureEncoding() ECDSASignatureEncoding
}

// ECDSASignatureToP1363For converts a signature to IEEE P1363, honouring an
// encoding the signer declares and falling back to inference only when it
// declares none.
//
// This is what ECDSASignatureToP1363 should be called with wherever the
// signer is to hand. The inference in ECDSASignatureToP1363 is a best effort
// for callers holding nothing but bytes.
func ECDSASignatureToP1363For(signer crypto.Signer, signature []byte, curve elliptic.Curve) ([]byte, error) {
	keySize := GetKeySizeForCurve(curve)
	if keySize == 0 {
		return nil, fmt.Errorf("unsupported curve: %s", curve.Params().Name)
	}

	reporter, ok := signer.(ECDSASignatureEncodingReporter)
	if !ok {
		return ECDSASignatureToP1363(signature, curve)
	}

	switch reporter.ECDSASignatureEncoding() {
	case ECDSAEncodingP1363:
		// Declared raw: never reinterpreted as DER, however its bytes
		// happen to look. A wrong length is an error rather than something
		// to fall back from - the signer said what it produces.
		if len(signature) != 2*keySize {
			return nil, fmt.Errorf("signer declares IEEE P1363 ECDSA signatures but produced %d bytes (expected %d for %s)",
				len(signature), 2*keySize, curve.Params().Name)
		}
		return signature, nil

	case ECDSAEncodingDER:
		var parsed ecdsaASN1Signature
		rest, err := asn1.Unmarshal(signature, &parsed)
		if err != nil {
			return nil, fmt.Errorf("signer declares ASN.1 DER ECDSA signatures but its output does not parse: %w", err)
		}
		if len(rest) > 0 {
			return nil, fmt.Errorf("signer declares ASN.1 DER ECDSA signatures but left %d trailing bytes", len(rest))
		}
		if !validECDSAScalars(parsed.R, parsed.S, curve) {
			return nil, fmt.Errorf("signer declares ASN.1 DER ECDSA signatures but its R/S are not valid scalars for %s", curve.Params().Name)
		}
		return EncodeECDSASignature(parsed.R, parsed.S, curve)

	default:
		return ECDSASignatureToP1363(signature, curve)
	}
}
