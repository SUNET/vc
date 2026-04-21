package sdjwtvc

import (
	"crypto/sha256"
	sha30 "crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"time"

	"github.com/SUNET/vc/pkg/jose"

	"github.com/golang-jwt/jwt/v5"
)

// KeyBindingJWT represents a Key Binding JWT for SD-JWT+KB
// Per section 4.3: proves possession of the key referenced in the SD-JWT
type KeyBindingJWT struct {
	Nonce    string `json:"nonce"`             // REQUIRED: ensures freshness
	Audience string `json:"aud"`               // REQUIRED: intended receiver
	IssuedAt int64  `json:"iat"`               // REQUIRED: time of KB-JWT creation
	SDHash   string `json:"sd_hash,omitempty"` // REQUIRED: hash of SD-JWT
}

// CreateKeyBindingJWT creates a Key Binding JWT for an SD-JWT
// Per section 4.3: binds the SD-JWT to the Holder's key
// Parameters:
// - sdJWT: the SD-JWT string (without KB-JWT)
// - nonce: freshness value from Verifier
// - audience: identifier of the Verifier
// - holderPrivateKey: Holder's private key for signing
// - hashAlg: hash algorithm to use (must match _sd_alg from SD-JWT)
func CreateKeyBindingJWT(
	sdJWT string,
	nonce string,
	audience string,
	holderPrivateKey any,
	hashAlg string,
) (string, error) {
	// Calculate sd_hash over the SD-JWT
	// Per section 4.3.1: hash over Issuer-signed JWT and Disclosures
	hashMethod, err := getHashFromAlgorithm(hashAlg)
	if err != nil {
		return "", fmt.Errorf("unsupported hash algorithm: %w", err)
	}

	sdHash, err := calculateSDHash(sdJWT, hashMethod)
	if err != nil {
		return "", fmt.Errorf("failed to calculate sd_hash: %w", err)
	}

	// Create KB-JWT claims
	now := time.Now().Unix()
	claims := jwt.MapClaims{
		"nonce":   nonce,
		"aud":     audience,
		"iat":     now,
		"sd_hash": sdHash,
	}

	// Determine signing method from private key
	signingMethod, algName := jose.GetSigningMethodFromKey(holderPrivateKey)

	// Create JWT header
	// Per section 4.3: typ MUST be "kb+jwt"
	header := map[string]any{
		"typ": "kb+jwt",
		"alg": algName,
	}

	// Sign the KB-JWT
	signedToken, err := Sign(header, claims, signingMethod, holderPrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign KB-JWT: %w", err)
	}

	return signedToken, nil
}

// calculateSDHash calculates the sd_hash value for the KB-JWT
// Per section 4.3.1: "The hash value in the sd_hash claim binds the KB-JWT to the
// specific SD-JWT. The sd_hash value MUST be taken over the US-ASCII bytes of the
// encoded SD-JWT"
func calculateSDHash(sdJWT string, hashMethod hash.Hash) (string, error) {
	// The SD-JWT format is: <Issuer-signed JWT>~<Disclosure 1>~<Disclosure 2>~...~<Disclosure N>~
	// We hash this entire string
	hashMethod.Reset()
	_, err := hashMethod.Write([]byte(sdJWT))
	if err != nil {
		return "", err
	}

	// Base64url-encode the hash
	digest := base64.RawURLEncoding.EncodeToString(hashMethod.Sum(nil))
	return digest, nil
}

// getHashFromAlgorithm returns a hash.Hash instance from algorithm name
func getHashFromAlgorithm(algName string) (hash.Hash, error) {
	switch algName {
	case "sha-256":
		return sha256.New(), nil
	case "sha-384":
		return sha512.New384(), nil
	case "sha-512":
		return sha512.New(), nil
	case "sha3-256":
		return hash.
			Hash(sha30.New256()), nil
	case "sha3-512":
		return hash.
			Hash(sha30.New512()), nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algName)
	}
}

// CombineWithKeyBinding combines an SD-JWT with a Key Binding JWT to create SD-JWT+KB
// Format: <SD-JWT without trailing ~><KB-JWT>
func CombineWithKeyBinding(sdJWT string, kbJWT string) string {
	// SD-JWT already ends with ~, so we can append directly
	// But we need to remove the trailing ~ first
	if len(sdJWT) > 0 && sdJWT[len(sdJWT)-1] == '~' {
		sdJWT = sdJWT[:len(sdJWT)-1]
	}
	return sdJWT + "~" + kbJWT
}
