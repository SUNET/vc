//go:build didcomm && vc20

package crypto

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// ECDH1PU implements the ECDH-1PU key agreement algorithm as specified in
// draft-madden-jose-ecdh-1pu (https://datatracker.ietf.org/doc/draft-madden-jose-ecdh-1pu/).
//
// ECDH-1PU provides authenticated key agreement where the sender's identity
// is cryptographically bound to the derived key material. This is used for
// DIDComm "authcrypt" mode.
//
// The algorithm works as follows:
// 1. Generate ephemeral key pair (epk)
// 2. Compute Z_es = ECDH(ephemeral_private, recipient_public) - Ephemeral-Static
// 3. Compute Z_ss = ECDH(sender_private, recipient_public) - Static-Static
// 4. Concatenate: Z = Z_es || Z_ss
// 5. Derive CEK using Concat KDF (or HKDF for A256KW)
//
// References:
//   - draft-madden-jose-ecdh-1pu-04
//   - RFC 7518 (JWA) for ECDH-ES
//   - DIDComm v2.1 Specification

// ECDH1PUKeyAgreement performs ECDH-1PU key agreement.
type ECDH1PUKeyAgreement struct {
	// SenderPrivateKey is the sender's static private key
	SenderPrivateKey jwk.Key

	// RecipientPublicKey is the recipient's static public key
	RecipientPublicKey jwk.Key

	// EphemeralPrivateKey is the sender's ephemeral private key (generated per message)
	EphemeralPrivateKey jwk.Key

	// Algorithm is the key wrapping algorithm (e.g., "ECDH-1PU+A256KW")
	Algorithm string

	// ContentEncryption is the content encryption algorithm (e.g., "A256CBC-HS512")
	ContentEncryption string

	// APU is Agreement PartyU Info (sender identifier, typically base64url-encoded DID)
	APU []byte

	// APV is Agreement PartyV Info (recipient identifier)
	APV []byte

	// CCTag is the content ciphertext authentication tag (used in ECDH-1PU KDF per draft-madden-jose-ecdh-1pu)
	// This binds the key derivation to the specific ciphertext, providing key commitment.
	CCTag []byte
}

// NewECDH1PU creates a new ECDH-1PU key agreement instance.
// For encryption: senderKey must be the sender's private key, recipientKey is recipient's public key.
// For decryption: senderKey can be nil, recipientKey must be the recipient's private key.
func NewECDH1PU(senderKey, recipientKey jwk.Key, algorithm, contentEnc string) (*ECDH1PUKeyAgreement, error) {
	if recipientKey == nil {
		return nil, fmt.Errorf("%w: recipient key is required for ECDH-1PU", ErrInvalidKey)
	}

	return &ECDH1PUKeyAgreement{
		SenderPrivateKey:   senderKey,
		RecipientPublicKey: recipientKey,
		Algorithm:          algorithm,
		ContentEncryption:  contentEnc,
	}, nil
}

// getCurveFromKey extracts the curve name from a JWK as a string.
func getCurveFromKey(key jwk.Key) (string, error) {
	var crv jwa.EllipticCurveAlgorithm
	if err := key.Get("crv", &crv); err != nil {
		return "", fmt.Errorf("failed to get curve from key: %w", err)
	}
	return crv.String(), nil
}

// GenerateEphemeralKey generates a new ephemeral key pair for the key agreement.
// The curve is determined by the recipient's public key.
func (e *ECDH1PUKeyAgreement) GenerateEphemeralKey() error {
	// Get the curve from the recipient's key
	crv, err := getCurveFromKey(e.RecipientPublicKey)
	if err != nil {
		return err
	}

	// Generate ephemeral key on the same curve
	ephemeralKey, err := generateECDHKey(crv)
	if err != nil {
		return fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	e.EphemeralPrivateKey = ephemeralKey
	return nil
}

// DeriveKey derives the content encryption key using ECDH-1PU.
// Returns the derived key and the ephemeral public key (for inclusion in JWE header).
// Note: This method does NOT include the cc_tag. Use DeriveKeyWithTag for ECDH-1PU key commitment.
func (e *ECDH1PUKeyAgreement) DeriveKey() ([]byte, jwk.Key, error) {
	if e.SenderPrivateKey == nil {
		return nil, nil, fmt.Errorf("%w: sender private key is required for ECDH-1PU encryption", ErrInvalidKey)
	}

	if e.EphemeralPrivateKey == nil {
		if err := e.GenerateEphemeralKey(); err != nil {
			return nil, nil, err
		}
	}

	// Extract raw keys for ECDH operations
	ephemeralPriv, err := extractECDHPrivateKey(e.EphemeralPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract ephemeral private key: %w", err)
	}

	senderPriv, err := extractECDHPrivateKey(e.SenderPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract sender private key: %w", err)
	}

	recipientPub, err := extractECDHPublicKey(e.RecipientPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract recipient public key: %w", err)
	}

	// Compute Z_es = ECDH(ephemeral_private, recipient_public)
	zES, err := ephemeralPriv.ECDH(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute Z_es: %w", err)
	}

	// Compute Z_ss = ECDH(sender_private, recipient_public)
	zSS, err := senderPriv.ECDH(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute Z_ss: %w", err)
	}

	// Concatenate: Z = Z_es || Z_ss
	z := append(zES, zSS...)

	// Get the required key size for the content encryption algorithm
	keySize, err := getKeyWrapKeySize(e.Algorithm)
	if err != nil {
		return nil, nil, err
	}

	// Derive the key wrapping key using Concat KDF
	// For ECDH-1PU+A256KW, we use the same KDF as ECDH-ES
	derivedKey, err := concatKDF(z, e.Algorithm, e.APU, e.APV, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// Get ephemeral public key for inclusion in JWE header
	ephemeralPubKey, err := e.EphemeralPrivateKey.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get ephemeral public key: %w", err)
	}

	return derivedKey, ephemeralPubKey, nil
}

// DeriveKeyWithTag derives the key using ECDH-1PU with key commitment (cc_tag).
// This includes the content ciphertext authentication tag in the KDF per draft-madden-jose-ecdh-1pu.
// Returns the derived key and the ephemeral public key.
func (e *ECDH1PUKeyAgreement) DeriveKeyWithTag(ccTag []byte) ([]byte, jwk.Key, error) {
	if e.SenderPrivateKey == nil {
		return nil, nil, fmt.Errorf("%w: sender private key is required for ECDH-1PU encryption", ErrInvalidKey)
	}

	if e.EphemeralPrivateKey == nil {
		if err := e.GenerateEphemeralKey(); err != nil {
			return nil, nil, err
		}
	}

	// Extract raw keys for ECDH operations
	ephemeralPriv, err := extractECDHPrivateKey(e.EphemeralPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract ephemeral private key: %w", err)
	}

	senderPriv, err := extractECDHPrivateKey(e.SenderPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract sender private key: %w", err)
	}

	recipientPub, err := extractECDHPublicKey(e.RecipientPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to extract recipient public key: %w", err)
	}

	// Compute Z_es = ECDH(ephemeral_private, recipient_public)
	zES, err := ephemeralPriv.ECDH(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute Z_es: %w", err)
	}

	// Compute Z_ss = ECDH(sender_private, recipient_public)
	zSS, err := senderPriv.ECDH(recipientPub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute Z_ss: %w", err)
	}

	// Concatenate: Z = Z_es || Z_ss
	z := append(zES, zSS...)

	// Get the required key size for the content encryption algorithm
	keySize, err := getKeyWrapKeySize(e.Algorithm)
	if err != nil {
		return nil, nil, err
	}

	// Derive the key wrapping key using Concat KDF with cc_tag (key commitment)
	derivedKey, err := concatKDF1PU(z, e.Algorithm, e.APU, e.APV, ccTag, keySize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive key with tag: %w", err)
	}

	// Get ephemeral public key for inclusion in JWE header
	ephemeralPubKey, err := e.EphemeralPrivateKey.PublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get ephemeral public key: %w", err)
	}

	return derivedKey, ephemeralPubKey, nil
}

// DeriveKeyForDecryption derives the key for decryption given the ephemeral public key.
func (e *ECDH1PUKeyAgreement) DeriveKeyForDecryption(ephemeralPubKey jwk.Key, senderPubKey jwk.Key) ([]byte, error) {
	// For decryption, we need:
	// - Recipient's private key (to compute both Z_es and verify sender)
	// - Sender's public key (to compute Z_ss from recipient's perspective)
	// - Ephemeral public key (from JWE header)

	recipientPriv, err := extractECDHPrivateKey(e.RecipientPublicKey) // This should be private for decryption
	if err != nil {
		return nil, fmt.Errorf("failed to extract recipient private key: %w", err)
	}

	ephemeralPub, err := extractECDHPublicKey(ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract ephemeral public key: %w", err)
	}

	senderPub, err := extractECDHPublicKey(senderPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to extract sender public key: %w", err)
	}

	// Compute Z_es = ECDH(recipient_private, ephemeral_public)
	zES, err := recipientPriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("failed to compute Z_es: %w", err)
	}

	// Compute Z_ss = ECDH(recipient_private, sender_public)
	zSS, err := recipientPriv.ECDH(senderPub)
	if err != nil {
		return nil, fmt.Errorf("failed to compute Z_ss: %w", err)
	}

	// Concatenate: Z = Z_es || Z_ss
	z := append(zES, zSS...)

	// Get the required key size
	keySize, err := getKeyWrapKeySize(e.Algorithm)
	if err != nil {
		return nil, err
	}

	// Derive the key wrapping key
	// Use concatKDF1PU if CCTag is set (for ECDH-1PU key commitment)
	var derivedKey []byte
	if len(e.CCTag) > 0 {
		derivedKey, err = concatKDF1PU(z, e.Algorithm, e.APU, e.APV, e.CCTag, keySize)
	} else {
		derivedKey, err = concatKDF(z, e.Algorithm, e.APU, e.APV, keySize)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return derivedKey, nil
}

// generateECDHKey generates an ECDH key pair for the specified curve.
func generateECDHKey(curve string) (jwk.Key, error) {
	var ecdhCurve ecdh.Curve

	switch curve {
	case CurveX25519:
		ecdhCurve = ecdh.X25519()
	case CurveP256:
		ecdhCurve = ecdh.P256()
	case CurveP384:
		ecdhCurve = ecdh.P384()
	case CurveP521:
		ecdhCurve = ecdh.P521()
	default:
		return nil, fmt.Errorf("%w: unsupported curve %s", ErrUnsupportedAlgorithm, curve)
	}

	privateKey, err := ecdhCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Convert to JWK
	key, err := jwk.Import(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to JWK: %w", err)
	}

	return key, nil
}

// extractECDHPrivateKey extracts the raw ECDH private key from a JWK.
func extractECDHPrivateKey(key jwk.Key) (*ecdh.PrivateKey, error) {
	var raw interface{}
	if err := jwk.Export(key, &raw); err != nil {
		return nil, fmt.Errorf("failed to get raw key: %w", err)
	}

	switch k := raw.(type) {
	case *ecdh.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		// Convert ECDSA to ECDH
		return k.ECDH()
	case []byte:
		// For X25519, the raw key might be bytes
		crv, err := getCurveFromKey(key)
		if err != nil {
			return nil, err
		}
		if crv == CurveX25519 {
			return ecdh.X25519().NewPrivateKey(k)
		}
		return nil, fmt.Errorf("unexpected raw key type for curve %s", crv)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", raw)
	}
}

// extractECDHPublicKey extracts the raw ECDH public key from a JWK.
func extractECDHPublicKey(key jwk.Key) (*ecdh.PublicKey, error) {
	var raw interface{}
	if err := jwk.Export(key, &raw); err != nil {
		return nil, fmt.Errorf("failed to get raw key: %w", err)
	}

	switch k := raw.(type) {
	case *ecdh.PublicKey:
		return k, nil
	case *ecdh.PrivateKey:
		return k.PublicKey(), nil
	case *ecdsa.PublicKey:
		// Convert ECDSA to ECDH
		return k.ECDH()
	case *ecdsa.PrivateKey:
		// Convert ECDSA to ECDH and get public key
		ecdhKey, err := k.ECDH()
		if err != nil {
			return nil, err
		}
		return ecdhKey.PublicKey(), nil
	case []byte:
		// For X25519, the raw key might be bytes
		crv, err := getCurveFromKey(key)
		if err != nil {
			return nil, err
		}
		if crv == CurveX25519 {
			return ecdh.X25519().NewPublicKey(k)
		}
		return nil, fmt.Errorf("unexpected raw key type for curve %s", crv)
	default:
		return nil, fmt.Errorf("unsupported key type: %T", raw)
	}
}

// getKeyWrapKeySize returns the key size for the key wrapping algorithm.
func getKeyWrapKeySize(algorithm string) (int, error) {
	switch algorithm {
	case AlgECDH1PUA256KW, AlgECDHESA256KW:
		return 32, nil // 256 bits
	case AlgECDHESA128KW, "ECDH-1PU+A128KW":
		return 16, nil // 128 bits
	default:
		return 0, fmt.Errorf("%w: unknown key wrap algorithm %s", ErrUnsupportedAlgorithm, algorithm)
	}
}

// concatKDF implements the Concat KDF as specified in NIST SP 800-56A and RFC 7518.
// This is used for JOSE key derivation (ECDH-ES).
//
// The KDF is: DerivedKey = Hash(counter || Z || OtherInfo)
// where OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
func concatKDF(z []byte, algorithm string, apu, apv []byte, keySize int) ([]byte, error) {
	// Build OtherInfo per RFC 7518 Section 4.6.2
	//
	// AlgorithmID = len(algorithm) || algorithm
	// PartyUInfo = len(apu) || apu
	// PartyVInfo = len(apv) || apv
	// SuppPubInfo = keydatalen (big-endian 32-bit)

	algorithmBytes := []byte(algorithm)
	otherInfo := make([]byte, 0, 4+len(algorithmBytes)+4+len(apu)+4+len(apv)+4)

	// AlgorithmID
	otherInfo = appendLengthPrefixed(otherInfo, algorithmBytes)

	// PartyUInfo (APU)
	otherInfo = appendLengthPrefixed(otherInfo, apu)

	// PartyVInfo (APV)
	otherInfo = appendLengthPrefixed(otherInfo, apv)

	// SuppPubInfo (key length in bits, big-endian)
	keySizeBits := make([]byte, 4)
	binary.BigEndian.PutUint32(keySizeBits, uint32(keySize*8))
	otherInfo = append(otherInfo, keySizeBits...)

	// Concat KDF per NIST SP 800-56A / RFC 7518:
	// DerivedKey = Hash(counter || Z || OtherInfo) for each round
	hashSize := sha256.Size
	rounds := (keySize + hashSize - 1) / hashSize

	derivedKey := make([]byte, 0, rounds*hashSize)

	for counter := uint32(1); counter <= uint32(rounds); counter++ {
		h := sha256.New()

		// Write counter as big-endian 32-bit
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, counter)
		h.Write(counterBytes)

		// Write Z (shared secret)
		h.Write(z)

		// Write OtherInfo
		h.Write(otherInfo)

		derivedKey = append(derivedKey, h.Sum(nil)...)
	}

	// Return only the required key size
	return derivedKey[:keySize], nil
}

// appendLengthPrefixed appends a length-prefixed byte slice to dst.
// The length is encoded as a big-endian 32-bit integer.
func appendLengthPrefixed(dst, data []byte) []byte {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(data)))
	dst = append(dst, length...)
	dst = append(dst, data...)
	return dst
}

// concatKDF1PU implements the Concat KDF for ECDH-1PU as specified in draft-madden-jose-ecdh-1pu.
// It differs from standard concatKDF by including the content ciphertext authentication tag
// in the SuppPubInfo, which binds the key derivation to the specific ciphertext.
//
// OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
// where SuppPubInfo = keydatalen || len(ccTag) || ccTag (if ccTag is not empty)
func concatKDF1PU(z []byte, algorithm string, apu, apv, ccTag []byte, keySize int) ([]byte, error) {
	// Build OtherInfo per draft-madden-jose-ecdh-1pu
	algorithmBytes := []byte(algorithm)

	// Calculate buffer size
	bufSize := 4 + len(algorithmBytes) + 4 + len(apu) + 4 + len(apv) + 4
	if len(ccTag) > 0 {
		bufSize += 4 + len(ccTag)
	}

	otherInfo := make([]byte, 0, bufSize)

	// AlgorithmID
	otherInfo = appendLengthPrefixed(otherInfo, algorithmBytes)

	// PartyUInfo (APU)
	otherInfo = appendLengthPrefixed(otherInfo, apu)

	// PartyVInfo (APV)
	otherInfo = appendLengthPrefixed(otherInfo, apv)

	// SuppPubInfo: keydatalen (key length in bits)
	keySizeBits := make([]byte, 4)
	binary.BigEndian.PutUint32(keySizeBits, uint32(keySize*8))
	otherInfo = append(otherInfo, keySizeBits...)

	// SuppPubInfo: ccTag (if present)
	// Per draft-madden-jose-ecdh-1pu, the tag is length-prefixed and appended to SuppPubInfo
	if len(ccTag) > 0 {
		otherInfo = appendLengthPrefixed(otherInfo, ccTag)
	}

	// Concat KDF per NIST SP 800-56A / RFC 7518:
	// DerivedKey = Hash(counter || Z || OtherInfo) for each round
	hashSize := sha256.Size
	rounds := (keySize + hashSize - 1) / hashSize

	derivedKey := make([]byte, 0, rounds*hashSize)

	for counter := uint32(1); counter <= uint32(rounds); counter++ {
		h := sha256.New()

		// Write counter as big-endian 32-bit
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, counter)
		h.Write(counterBytes)

		// Write Z (shared secret)
		h.Write(z)

		// Write OtherInfo
		h.Write(otherInfo)

		derivedKey = append(derivedKey, h.Sum(nil)...)
	}

	// Return only the required key size
	return derivedKey[:keySize], nil
}
