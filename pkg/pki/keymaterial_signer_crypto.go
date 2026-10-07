package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// This file is what makes KeyMaterialSigner work for a key it cannot see
// inside - an HSM key reached over PKCS#11.
//
// KeyMaterialSigner type-switched on *ecdsa.PrivateKey and *rsa.PrivateKey
// everywhere, and KeyMaterial.PrivateKey for a PKCS#11 key is a
// *PKCS11PrivateKey. It is a perfectly good crypto.Signer - Public() and
// Sign() both work - but it is neither of those two concrete types, so
// every method fell to its default branch:
//
//   - Sign and SignDigest returned "unsupported key type"
//   - PublicKey returned nil, so the published JWK carried no key
//   - determineKeyID returned "default-key", so every certificate-less HSM
//     key had the SAME kid and every JWT was signed with it
//
// initSigner's own comment says "software or PKCS#11" and LoadSigner's says
// it "handles both software and HSM keys". They do now.

// cryptoSigner returns the key as a crypto.Signer, which every key type
// here satisfies - *ecdsa.PrivateKey and *rsa.PrivateKey by construction,
// *PKCS11PrivateKey by implementing it.
func cryptoSigner(key crypto.PrivateKey) (crypto.Signer, bool) {
	signer, ok := key.(crypto.Signer)
	return signer, ok
}

// signWithCryptoSigner signs digest through the crypto.Signer interface and
// returns a JWT-shaped signature.
//
// opts carries the hash for RSA PKCS#1 v1.5, which needs to know which one
// was used; ECDSA ignores it.
//
// The ECDSA encoding is the part worth care. JWT (RFC 7518 §3.4) wants
// IEEE P1363: R and S as fixed-width big-endian halves. crypto.Signer does
// not promise that - Go's own ecdsa returns ASN.1 DER, while PKCS#11's
// CKM_ECDSA returns P1363 already - so the result is normalised rather
// than assumed.
//
// Normalised by LENGTH, not by sniffing the first byte for 0x30. A P1363
// signature is a pair of random-looking integers and starts with 0x30 once
// in 256 tries; code that tests for it has a one-in-256 failure that only
// shows up in production. A DER SEQUENCE of two P-256 integers cannot be
// exactly 64 bytes, so the length is an exact discriminator.
func signWithCryptoSigner(signer crypto.Signer, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	raw, err := signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		return nil, err
	}

	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		// RSA and anything else: the signature is already what the
		// algorithm defines, with no alternative encoding to pick between.
		return raw, nil
	}

	return normalizeECDSASignature(raw, pub.Curve)
}

// normalizeECDSASignature returns an IEEE P1363 signature for curve,
// accepting either P1363 or ASN.1 DER input.
func normalizeECDSASignature(sig []byte, curve elliptic.Curve) ([]byte, error) {
	keySize := GetKeySizeForCurve(curve)
	if keySize == 0 {
		return nil, fmt.Errorf("unsupported curve: %s", curve.Params().Name)
	}

	if len(sig) == 2*keySize {
		return sig, nil
	}

	var parsed struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(sig, &parsed)
	if err != nil {
		return nil, fmt.Errorf("signature is neither %d-byte IEEE P1363 nor ASN.1 DER for curve %s: %w",
			2*keySize, curve.Params().Name, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("ASN.1 signature for curve %s has %d trailing byte(s)", curve.Params().Name, len(rest))
	}
	if parsed.R == nil || parsed.S == nil {
		return nil, fmt.Errorf("ASN.1 signature for curve %s is missing r or s", curve.Params().Name)
	}
	if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
		return nil, fmt.Errorf("ASN.1 signature for curve %s has a non-positive r or s", curve.Params().Name)
	}
	if parsed.R.BitLen() > keySize*8 || parsed.S.BitLen() > keySize*8 {
		return nil, fmt.Errorf("ASN.1 signature for curve %s has an r or s wider than the curve", curve.Params().Name)
	}

	return EncodeECDSASignature(parsed.R, parsed.S, curve)
}
