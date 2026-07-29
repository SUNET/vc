package jose

import (
	"crypto"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/SUNET/vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWKWithMetadata `json:"keys"`
}

// JWKWithMetadata includes additional fields like alg, use, kid
type JWKWithMetadata struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	// EC key fields
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	// RSA key fields
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
}

// ParseSigningKey parses a private key from a PEM file (supports EC and RSA in various formats)
// Handles SEC1, PKCS1, and PKCS8 formats automatically.
func ParseSigningKey(signingKeyPath string) (crypto.PrivateKey, error) {
	keyByte, err := os.ReadFile(filepath.Clean(signingKeyPath))
	if err != nil {
		return nil, err
	}

	// Try EC (handles SEC1 and PKCS8 formats)
	if privateKey, err := jwt.ParseECPrivateKeyFromPEM(keyByte); err == nil {
		return privateKey, nil
	}

	// Try RSA (handles PKCS1 and PKCS8 formats)
	if privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyByte); err == nil {
		return privateKey, nil
	}

	return nil, errors.New("unsupported key type: expected EC or RSA private key in PEM format")
}

// CreateJWKSFromSigner creates a JWKS from a pki.Signer
// keyUsage defaults to "sig" if empty string is provided
func CreateJWKSFromSigner(signer pki.Signer, keyUsage string) (*JWKS, error) {
	if signer == nil {
		return nil, errors.New("signer must not be nil")
	}

	// Default keyUsage to "sig" if not provided
	if keyUsage == "" {
		keyUsage = "sig"
	}

	// Import public key using jwx library
	key, err := jwk.Import(signer.PublicKey())
	if err != nil {
		return nil, err
	}

	// Set additional fields
	if err := key.Set(jwk.AlgorithmKey, signer.Algorithm()); err != nil {
		return nil, err
	}
	if err := key.Set(jwk.KeyUsageKey, keyUsage); err != nil {
		return nil, err
	}
	if err := key.Set(jwk.KeyIDKey, signer.KeyID()); err != nil {
		return nil, err
	}

	// Marshal to JSON and unmarshal to our JWKS struct
	jwkJSON, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}

	var jwkWithMetadata JWKWithMetadata
	if err := json.Unmarshal(jwkJSON, &jwkWithMetadata); err != nil {
		return nil, err
	}

	jwks := &JWKS{
		Keys: []JWKWithMetadata{jwkWithMetadata},
	}

	return jwks, nil
}

// ParseJWK converts a JWK map (e.g., from a JWT header) to a JWKWithMetadata struct
// This is commonly used for DPoP and similar protocols where JWK is embedded in JWT headers
func ParseJWK(jwkMap map[string]any) (*JWKWithMetadata, error) {
	jwkBytes, err := json.Marshal(jwkMap)
	if err != nil {
		return nil, err
	}

	var jwk JWKWithMetadata
	if err := json.Unmarshal(jwkBytes, &jwk); err != nil {
		return nil, err
	}

	return &jwk, nil
}
