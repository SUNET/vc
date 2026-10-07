package pki

import (
	"crypto"
	"crypto/ecdsa"
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
// The ECDSA encoding is the part worth care. JWT (RFC 7518 3.4) wants IEEE
// P1363: R and S as fixed-width big-endian halves. crypto.Signer does not
// promise that - Go's own ecdsa returns ASN.1 DER, while PKCS#11's
// CKM_ECDSA returns P1363 already - so the result is normalised rather
// than assumed.
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

	return normalizeECDSASignature(raw, pub, digest)
}

// normalizeECDSASignature returns an IEEE P1363 signature, accepting either
// P1363 or ASN.1 DER input.
//
// Decided by VERIFICATION, not by length and certainly not by sniffing the
// first byte for 0x30. Both shortcuts are wrong, for different reasons:
//
//   - A P1363 signature is a pair of random-looking integers and begins
//     0x30 once in 256 tries. This repo has already shipped that
//     one-in-256 bug once (pkcs11pool's RawSigToASN1).
//   - Length is not an exact discriminator either, which I had claimed it
//     was. A DER SEQUENCE of two INTEGERs costs 6 bytes of tag and length,
//     so for P-256 any |r|+|s| == 58 - seven combinations, |r|=26..32 -
//     produces a DER signature exactly 64 bytes long, the same as P1363.
//     Rare (around one in 4e13, since each combination needs r or s to be
//     several bytes short of the curve) and not zero, and a rule that is
//     true "almost always" is the shape of bug that surfaces once in
//     production and never in a test.
//
// So the P1363 reading is tried and CHECKED against the public key and the
// digest, and only accepted if it verifies; otherwise the bytes are parsed
// as DER. One ECDSA verification per signature, which is tens of
// microseconds against an HSM round trip of milliseconds.
func normalizeECDSASignature(sig []byte, pub *ecdsa.PublicKey, digest []byte) ([]byte, error) {
	keySize := GetKeySizeForCurve(pub.Curve)
	if keySize == 0 {
		return nil, fmt.Errorf("unsupported curve: %s", pub.Curve.Params().Name)
	}

	if len(sig) == 2*keySize {
		r := new(big.Int).SetBytes(sig[:keySize])
		s := new(big.Int).SetBytes(sig[keySize:])
		if ecdsa.Verify(pub, digest, r, s) {
			return sig, nil
		}
		// Falls through: either the signature is bad, or it is one of the
		// DER encodings that happen to be this length.
	}

	var parsed struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(sig, &parsed)
	if err != nil {
		return nil, fmt.Errorf("signature is neither a verifiable %d-byte IEEE P1363 nor ASN.1 DER for curve %s: %w",
			2*keySize, pub.Curve.Params().Name, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("ASN.1 signature for curve %s has %d trailing byte(s)", pub.Curve.Params().Name, len(rest))
	}
	if parsed.R == nil || parsed.S == nil {
		return nil, fmt.Errorf("ASN.1 signature for curve %s is missing r or s", pub.Curve.Params().Name)
	}
	if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
		return nil, fmt.Errorf("ASN.1 signature for curve %s has a non-positive r or s", pub.Curve.Params().Name)
	}
	if parsed.R.BitLen() > keySize*8 || parsed.S.BitLen() > keySize*8 {
		return nil, fmt.Errorf("ASN.1 signature for curve %s has an r or s wider than the curve", pub.Curve.Params().Name)
	}
	if !ecdsa.Verify(pub, digest, parsed.R, parsed.S) {
		return nil, fmt.Errorf("signature for curve %s does not verify as IEEE P1363 or as ASN.1 DER", pub.Curve.Params().Name)
	}

	return EncodeECDSASignature(parsed.R, parsed.S, pub.Curve)
}
