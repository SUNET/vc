package jose

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
)

// MakeJWT creates a signed JWT using pki.Signer.
// The pki.Signer interface supports both software keys and HSM.
func MakeJWT(ctx context.Context, header, body jwt.MapClaims, signer pki.Signer) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("signer cannot be nil")
	}

	// Build header with algorithm and key ID from signer
	headerCopy := make(jwt.MapClaims)
	maps.Copy(headerCopy, header)
	headerCopy["alg"] = signer.Algorithm()
	headerCopy["kid"] = signer.KeyID()

	// Encode header
	headerJSON, err := json.Marshal(headerCopy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Encode payload
	payloadJSON, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create signing input
	signingInput := headerB64 + "." + payloadB64

	// Sign using the signer interface
	signature, err := signer.Sign(ctx, []byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("failed to sign: %w", err)
	}

	// Encode signature
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Return complete JWT
	return signingInput + "." + signatureB64, nil
}

// GetSigningMethodFromKey determines the JWT signing method and algorithm name from the private key
func GetSigningMethodFromKey(privateKey any) (jwt.SigningMethod, string) {
	// Check if the key is RSA
	if rsaKey, ok := privateKey.(*rsa.PrivateKey); ok {
		// Determine RSA algorithm based on key size
		keySize := rsaKey.N.BitLen()
		switch {
		case keySize >= 4096:
			return jwt.SigningMethodRS512, "RS512"
		case keySize >= 3072:
			return jwt.SigningMethodRS384, "RS384"
		default:
			return jwt.SigningMethodRS256, "RS256"
		}
	}

	// Check if the key is ECDSA
	if ecKey, ok := privateKey.(*ecdsa.PrivateKey); ok {
		// Determine algorithm based on the curve of the ECDSA key
		switch ecKey.Curve.Params().Name {
		case "P-256":
			return jwt.SigningMethodES256, "ES256"
		case "P-384":
			return jwt.SigningMethodES384, "ES384"
		case "P-521":
			return jwt.SigningMethodES512, "ES512"
		default:
			// Default to ES256 for unknown curves
			return jwt.SigningMethodES256, "ES256"
		}
	}

	// Default to ES256 if key type is unknown
	return jwt.SigningMethodES256, "ES256"
}
