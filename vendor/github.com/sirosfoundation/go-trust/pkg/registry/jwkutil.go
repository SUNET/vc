// Package registry provides trust registry management.
// This file contains shared JWK utility functions used across registries.
package registry

// JWKsMatch compares two JWK maps for public key material equality.
// It supports OKP (Ed25519, X25519), EC (P-256, P-384, P-521), and RSA key types.
// Only the public key components are compared; private key fields are ignored.
func JWKsMatch(jwk1, jwk2 map[string]interface{}) bool {
	kty1, ok1 := jwk1["kty"].(string)
	kty2, ok2 := jwk2["kty"].(string)
	if !ok1 || !ok2 || kty1 != kty2 {
		return false
	}

	switch kty1 {
	case "OKP":
		return jwk1["crv"] == jwk2["crv"] && jwk1["x"] == jwk2["x"]
	case "EC":
		return jwk1["crv"] == jwk2["crv"] && jwk1["x"] == jwk2["x"] && jwk1["y"] == jwk2["y"]
	case "RSA":
		return jwk1["n"] == jwk2["n"] && jwk1["e"] == jwk2["e"]
	default:
		return false
	}
}
