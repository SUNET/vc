package trust

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
	"math/big"
)

// ecdsaToJWK converts an ECDSA public key to JWK format.
func ecdsaToJWK(publicKey *ecdsa.PublicKey) (map[string]any, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	var crv string
	switch publicKey.Curve {
	case elliptic.P256():
		crv = "P-256"
	case elliptic.P384():
		crv = "P-384"
	case elliptic.P521():
		crv = "P-521"
	default:
		return nil, fmt.Errorf("unsupported curve: %v", publicKey.Curve.Params().Name)
	}

	// Get the byte size for the curve
	byteLen := (publicKey.Curve.Params().BitSize + 7) / 8

	// Pad coordinates to the correct length
	xBytes := publicKey.X.Bytes()
	yBytes := publicKey.Y.Bytes()

	xPadded := make([]byte, byteLen)
	yPadded := make([]byte, byteLen)
	copy(xPadded[byteLen-len(xBytes):], xBytes)
	copy(yPadded[byteLen-len(yBytes):], yBytes)

	return map[string]any{
		"kty": "EC",
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}, nil
}

// ed25519ToJWK converts an Ed25519 public key to JWK format.
func ed25519ToJWK(publicKey ed25519.PublicKey) map[string]any {
	return map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(publicKey),
	}
}

// jwkToECDSA extracts an ECDSA public key from a JWK.
func jwkToECDSA(jwk map[string]any) (*ecdsa.PublicKey, error) {
	kty, ok := jwk["kty"].(string)
	if !ok || kty != "EC" {
		return nil, fmt.Errorf("invalid key type, expected EC, got %v", jwk["kty"])
	}

	crv, ok := jwk["crv"].(string)
	if !ok {
		return nil, fmt.Errorf("missing curve")
	}

	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	xStr, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("missing x coordinate")
	}

	yStr, ok := jwk["y"].(string)
	if !ok {
		return nil, fmt.Errorf("missing y coordinate")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y coordinate: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Verify the point is on the curve
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("point is not on curve")
	}

	return pubKey, nil
}

// jwkToEd25519 extracts an Ed25519 public key from a JWK.
func jwkToEd25519(jwk map[string]any) (ed25519.PublicKey, error) {
	kty, ok := jwk["kty"].(string)
	if !ok || kty != "OKP" {
		return nil, fmt.Errorf("invalid key type, expected OKP, got %v", jwk["kty"])
	}

	crv, ok := jwk["crv"].(string)
	if !ok || crv != "Ed25519" {
		return nil, fmt.Errorf("invalid curve, expected Ed25519, got %v", jwk["crv"])
	}

	x, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("missing x coordinate")
	}

	pubBytes, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x coordinate: %w", err)
	}

	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: got %d, expected %d", len(pubBytes), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(pubBytes), nil
}

// extractKeyFromMetadata extracts a public key from trust metadata (DID document).
func extractKeyFromMetadata(metadata any, verificationMethod string) (crypto.PublicKey, error) {
	doc, ok := metadata.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid trust metadata format")
	}

	// Find verification method in document
	vms, _ := doc["verificationMethod"].([]any)
	for _, vm := range vms {
		vmMap, ok := vm.(map[string]any)
		if !ok {
			continue
		}

		vmID, _ := vmMap["id"].(string)
		if vmID != verificationMethod {
			continue
		}

		// Handle publicKeyJwk
		if jwk, ok := vmMap["publicKeyJwk"].(map[string]any); ok {
			return extractKeyFromJWK(jwk)
		}

		// Handle publicKeyMultibase (Ed25519)
		if multibase, ok := vmMap["publicKeyMultibase"].(string); ok {
			return decodeMultibaseKey(multibase)
		}
	}

	return nil, fmt.Errorf("verification method not found in metadata: %s", verificationMethod)
}

// extractKeyFromJWK extracts a public key from a JWK map.
func extractKeyFromJWK(jwk map[string]any) (crypto.PublicKey, error) {
	kty, _ := jwk["kty"].(string)

	switch kty {
	case "EC":
		return jwkToECDSA(jwk)
	case "OKP":
		return jwkToEd25519(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}
}

// decodeMultibaseKey decodes a multibase-encoded public key (Ed25519).
func decodeMultibaseKey(multibase string) (crypto.PublicKey, error) {
	if len(multibase) < 2 {
		return nil, fmt.Errorf("multibase string too short")
	}

	// Handle 'z' prefix (base58-btc)
	if multibase[0] == 'z' {
		// For now, return error - full multibase/multicodec support would require additional dependencies
		return nil, fmt.Errorf("base58-btc multibase decoding not implemented in trust package")
	}

	return nil, fmt.Errorf("unsupported multibase encoding: %c", multibase[0])
}
