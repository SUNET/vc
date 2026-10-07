package openid4vci

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
)

// KeyAgreementKey is one of this Credential Issuer's request-decryption
// keys: the ECDH-ES side of §8.3, reduced to the two things vc needs from a
// private key it may never see.
//
// The interface exists so that a key held in a file and a key held in an HSM
// can sit in the same list. A file key is an *ecdsa.PrivateKey and could be
// handed to jwe.Decrypt directly; a PKCS#11 key cannot be, because the
// decrypter wants a concrete *ecdh.PrivateKey to call ECDH on and a token
// will not hand one over. Both can answer "what is Z for this ephemeral
// public key", so that is what is asked of them, and the Concat KDF, key
// unwrap and content decryption around it are the same either way.
type KeyAgreementKey interface {
	// PublicKey returns the public half, which is what gets published in
	// credential_request_encryption.jwks and what the kid is a thumbprint
	// of. *ecdsa.PublicKey rather than *ecdh.PublicKey because that is what
	// jwk.Import turns into an EC JWK with a crv.
	PublicKey() *ecdsa.PublicKey

	// ECDH returns the raw shared secret Z for the wallet's ephemeral public
	// key - the x coordinate of the agreed point, left-padded to the field
	// size, with no KDF applied. RFC 7518 §4.6.2 applies the Concat KDF to
	// it; doing that here instead would make an HSM that only exposes a
	// derived key impossible to tell apart from one that does not.
	//
	// The parameter is an *ecdh.PublicKey because constructing one is what
	// rejects a point that is not on the curve, and an implementation that
	// forwards the point to an HSM has no other opportunity to check.
	ECDH(peer *ecdh.PublicKey) ([]byte, error)
}

// softwareKeyAgreement is a KeyAgreementKey backed by a private key in this
// process's memory, loaded from a PEM file.
type softwareKeyAgreement struct {
	private *ecdh.PrivateKey
	public  *ecdsa.PublicKey
}

// NewSoftwareKeyAgreementKey adapts a P-256 private key read from a file to
// the KeyAgreementKey interface.
func NewSoftwareKeyAgreementKey(key *ecdsa.PrivateKey) (KeyAgreementKey, error) {
	if key == nil {
		return nil, fmt.Errorf("no private key")
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("want curve P-256, got %s", key.Curve.Params().Name)
	}
	private, err := key.ECDH()
	if err != nil {
		return nil, fmt.Errorf("the key cannot perform ECDH: %w", err)
	}
	return &softwareKeyAgreement{private: private, public: &key.PublicKey}, nil
}

func (k *softwareKeyAgreement) PublicKey() *ecdsa.PublicKey { return k.public }

func (k *softwareKeyAgreement) ECDH(peer *ecdh.PublicKey) ([]byte, error) {
	return k.private.ECDH(peer)
}

// concatKDF is the NIST SP 800-56A Concatenation KDF in the shape RFC 7518
// §4.6.2 fixes it to: SuppPrivInfo empty, SuppPubInfo the key length in
// bits, and every other input carried as a 32-bit big-endian length
// followed by its bytes.
//
// Reimplemented rather than reused: jwx has this, in
// jwe/internal/concatkdf, and "internal" means it cannot be imported from
// here. It is thirty lines with a worked example in the RFC, which
// TestConcatKDF_RFC7518AppendixC runs as a known-answer test.
func concatKDF(hash crypto.Hash, z, algorithmID, partyUInfo, partyVInfo []byte, keyLen int) []byte {
	var otherInfo []byte
	otherInfo = appendLengthPrefixed(otherInfo, algorithmID)
	otherInfo = appendLengthPrefixed(otherInfo, partyUInfo)
	otherInfo = appendLengthPrefixed(otherInfo, partyVInfo)
	otherInfo = binary.BigEndian.AppendUint32(otherInfo, uint32(keyLen)*8)

	h := hash.New()
	out := make([]byte, 0, keyLen)
	// Rounds are counted from 1 and the counter is hashed first, so a key
	// longer than one digest is the concatenation of successive hashes. A
	// 256-bit key out of SHA-256 is a single round, but writing the loop is
	// cheaper than writing down why there is no loop.
	for round := uint32(1); len(out) < keyLen; round++ {
		h.Reset()
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], round)
		// hash.Hash never returns an error from Write.
		h.Write(counter[:])
		h.Write(z)
		h.Write(otherInfo)
		out = h.Sum(out)
	}

	return out[:keyLen]
}

func appendLengthPrefixed(dst, value []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(value)))
	return append(dst, value...)
}
