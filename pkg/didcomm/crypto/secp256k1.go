package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrdecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// ES256K implements the ES256K (secp256k1 + SHA-256) signature algorithm.
//
// ES256K is commonly used in cryptocurrency and decentralized identity systems.
// It uses the secp256k1 curve (same as Bitcoin/Ethereum) with SHA-256 hashing.
//
// This implementation uses github.com/decred/dcrd/dcrec/secp256k1/v4 for
// the underlying cryptographic operations, providing a well-tested and
// audited implementation of the secp256k1 curve.
//
// Note: ES256K is distinct from ES256 which uses the P-256 (secp256r1) curve.
// The two are NOT interchangeable.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc8812 (COSE/JOSE secp256k1)
//   - DIDComm v2.1 Specification

// Secp256k1Signer implements JWS signing using ES256K.
type Secp256k1Signer struct {
	privateKey *secp256k1.PrivateKey
	publicKey  *secp256k1.PublicKey
	keyID      string
}

// NewSecp256k1Signer creates a new ES256K signer from a JWK.
func NewSecp256k1Signer(key jwk.Key) (*Secp256k1Signer, error) {
	privateKey, err := extractSecp256k1PrivateKey(key)
	if err != nil {
		return nil, err
	}

	var keyID string
	_ = key.Get("kid", &keyID)

	return &Secp256k1Signer{
		privateKey: privateKey,
		publicKey:  privateKey.PubKey(),
		keyID:      keyID,
	}, nil
}

// Sign signs the payload and returns the raw signature (r || s, 64 bytes).
func (s *Secp256k1Signer) Sign(payload []byte) ([]byte, error) {
	// Hash the payload with SHA-256
	hash := sha256.Sum256(payload)

	// Sign using ECDSA with secp256k1
	signature := dcrdecdsa.Sign(s.privateKey, hash[:])

	// Convert to r || s format (64 bytes total)
	return signatureToRS(signature), nil
}

// SignJWS creates a complete JWS with ES256K algorithm.
func (s *Secp256k1Signer) SignJWS(payload []byte, typ string) ([]byte, error) {
	// Build protected header manually since jwx doesn't support ES256K
	header := map[string]any{
		"alg": "ES256K",
		"typ": typ,
	}
	if s.keyID != "" {
		header["kid"] = s.keyID
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}

	// Create signing input: BASE64URL(Header) || '.' || BASE64URL(Payload)
	encodedHeader := base64.RawURLEncoding.EncodeToString(headerBytes)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := encodedHeader + "." + encodedPayload

	// Sign the input
	signature, err := s.Sign([]byte(signingInput))
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Encode signature and create compact JWS
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)
	compactJWS := signingInput + "." + encodedSignature

	return []byte(compactJWS), nil
}

// KeyID returns the key ID if available.
func (s *Secp256k1Signer) KeyID() string {
	return s.keyID
}

// PublicKey returns the public key as a JWK.
func (s *Secp256k1Signer) PublicKey() (jwk.Key, error) {
	return exportSecp256k1PublicKey(s.publicKey, s.keyID)
}

// Secp256k1Verifier implements JWS verification using ES256K.
type Secp256k1Verifier struct {
	publicKey *secp256k1.PublicKey
	keyID     string
}

// NewSecp256k1Verifier creates a new ES256K verifier from a JWK.
func NewSecp256k1Verifier(key jwk.Key) (*Secp256k1Verifier, error) {
	publicKey, err := extractSecp256k1PublicKey(key)
	if err != nil {
		return nil, err
	}

	var keyID string
	_ = key.Get("kid", &keyID)

	return &Secp256k1Verifier{
		publicKey: publicKey,
		keyID:     keyID,
	}, nil
}

// Verify verifies a raw signature against the payload.
func (v *Secp256k1Verifier) Verify(payload, signature []byte) error {
	// Hash the payload with SHA-256
	hash := sha256.Sum256(payload)

	// Parse the signature from r || s format
	sig, err := parseRSSignature(signature)
	if err != nil {
		return fmt.Errorf("invalid signature format: %w", err)
	}

	// Verify using ECDSA
	if !sig.Verify(hash[:], v.publicKey) {
		return ErrVerificationFailed
	}

	return nil
}

// VerifyJWS verifies a compact JWS and returns the payload.
func (v *Secp256k1Verifier) VerifyJWS(compactJWS []byte) ([]byte, error) {
	// Parse compact JWS: header.payload.signature
	parts := splitJWS(compactJWS)
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: invalid JWS format", ErrInvalidJWS)
	}

	// Decode and verify header
	headerBytes, err := base64.RawURLEncoding.DecodeString(string(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	alg, _ := header["alg"].(string)
	if alg != "ES256K" {
		return nil, fmt.Errorf("%w: expected ES256K, got %s", ErrUnsupportedAlgorithm, alg)
	}

	// Decode payload
	payload, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	// Decode signature
	signature, err := base64.RawURLEncoding.DecodeString(string(parts[2]))
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Create signing input and verify
	signingInput := string(parts[0]) + "." + string(parts[1])
	if err := v.Verify([]byte(signingInput), signature); err != nil {
		return nil, err
	}

	return payload, nil
}

// splitJWS splits a compact JWS into its three parts.
func splitJWS(data []byte) [][]byte {
	var parts [][]byte
	start := 0
	for i, b := range data {
		if b == '.' {
			parts = append(parts, data[start:i])
			start = i + 1
		}
	}
	parts = append(parts, data[start:])
	return parts
}

// extractSecp256k1PrivateKey extracts a secp256k1 private key from a JWK.
func extractSecp256k1PrivateKey(key jwk.Key) (*secp256k1.PrivateKey, error) {
	// Verify curve
	var crv string
	if err := key.Get("crv", &crv); err != nil {
		return nil, fmt.Errorf("failed to get curve: %w", err)
	}
	if crv != CurveSecp256k1 {
		return nil, fmt.Errorf("%w: expected secp256k1, got %s", ErrInvalidKey, crv)
	}

	// Get the 'd' parameter (private key scalar)
	var d []byte
	if err := key.Get("d", &d); err != nil {
		return nil, fmt.Errorf("failed to get private key parameter: %w", err)
	}

	// Create secp256k1 private key
	privKey := secp256k1.PrivKeyFromBytes(d)
	return privKey, nil
}

// extractSecp256k1PublicKey extracts a secp256k1 public key from a JWK.
func extractSecp256k1PublicKey(key jwk.Key) (*secp256k1.PublicKey, error) {
	// Verify curve
	var crv string
	if err := key.Get("crv", &crv); err != nil {
		return nil, fmt.Errorf("failed to get curve: %w", err)
	}
	if crv != CurveSecp256k1 {
		return nil, fmt.Errorf("%w: expected secp256k1, got %s", ErrInvalidKey, crv)
	}

	// Get the 'x' and 'y' parameters (public key coordinates)
	var x, y []byte
	if err := key.Get("x", &x); err != nil {
		return nil, fmt.Errorf("failed to get x coordinate: %w", err)
	}
	if err := key.Get("y", &y); err != nil {
		return nil, fmt.Errorf("failed to get y coordinate: %w", err)
	}

	// Create secp256k1 public key from coordinates
	xInt := new(big.Int).SetBytes(x)
	yInt := new(big.Int).SetBytes(y)

	// Convert to uncompressed public key format: 0x04 || X || Y
	pubKeyBytes := make([]byte, 65)
	pubKeyBytes[0] = 0x04
	xBytes := xInt.Bytes()
	yBytes := yInt.Bytes()
	copy(pubKeyBytes[33-len(xBytes):33], xBytes)
	copy(pubKeyBytes[65-len(yBytes):65], yBytes)

	pubKey, err := secp256k1.ParsePubKey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return pubKey, nil
}

// exportSecp256k1PublicKey exports a secp256k1 public key as a JWK.
func exportSecp256k1PublicKey(pubKey *secp256k1.PublicKey, keyID string) (jwk.Key, error) {
	x := pubKey.X()
	y := pubKey.Y()

	xBytes := x.Bytes()
	yBytes := y.Bytes()

	// Pad to 32 bytes
	xPadded := padTo32(xBytes[:])
	yPadded := padTo32(yBytes[:])

	// Build JWK manually
	jwkMap := map[string]any{
		"kty": "EC",
		"crv": CurveSecp256k1,
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}
	if keyID != "" {
		jwkMap["kid"] = keyID
	}

	jwkJSON, err := json.Marshal(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK: %w", err)
	}

	key, err := jwk.ParseKey(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	return key, nil
}

// padTo32 pads a byte slice to 32 bytes (left-padded with zeros).
func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

// signatureToRS converts a dcrd ECDSA signature to the r || s format.
func signatureToRS(sig *dcrdecdsa.Signature) []byte {
	r := sig.R()
	s := sig.S()

	rBytes := r.Bytes()
	sBytes := s.Bytes()

	result := make([]byte, 64)
	copy(result[32-len(rBytes[:]):32], rBytes[:])
	copy(result[64-len(sBytes[:]):64], sBytes[:])

	return result
}

// parseRSSignature parses an r || s format signature.
func parseRSSignature(sig []byte) (*dcrdecdsa.Signature, error) {
	if len(sig) != 64 {
		return nil, fmt.Errorf("signature must be 64 bytes, got %d", len(sig))
	}

	r := new(secp256k1.ModNScalar)
	r.SetByteSlice(sig[:32])

	s := new(secp256k1.ModNScalar)
	s.SetByteSlice(sig[32:])

	return dcrdecdsa.NewSignature(r, s), nil
}

// GenerateSecp256k1Key generates a new secp256k1 key pair.
func GenerateSecp256k1Key() (jwk.Key, error) {
	return GenerateSecp256k1KeyWithID("")
}

// GenerateSecp256k1KeyWithID generates a new secp256k1 key pair with a key ID.
func GenerateSecp256k1KeyWithID(keyID string) (jwk.Key, error) {
	privKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	return importSecp256k1PrivateKey(privKey, keyID)
}

// importSecp256k1PrivateKey imports a secp256k1 private key as a JWK.
func importSecp256k1PrivateKey(privKey *secp256k1.PrivateKey, keyID string) (jwk.Key, error) {
	pubKey := privKey.PubKey()

	d := privKey.Key.Bytes()
	x := pubKey.X().Bytes()
	y := pubKey.Y().Bytes()

	// Build JWK manually
	jwkMap := map[string]any{
		"kty": "EC",
		"crv": CurveSecp256k1,
		"x":   base64.RawURLEncoding.EncodeToString(padTo32(x[:])),
		"y":   base64.RawURLEncoding.EncodeToString(padTo32(y[:])),
		"d":   base64.RawURLEncoding.EncodeToString(padTo32(d[:])),
	}
	if keyID != "" {
		jwkMap["kid"] = keyID
	}

	jwkJSON, err := json.Marshal(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK: %w", err)
	}

	key, err := jwk.ParseKey(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	return key, nil
}

// secp256k1Random is a helper for cryptographically secure random generation.
func secp256k1Random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
