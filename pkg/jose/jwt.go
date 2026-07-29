package jose

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"

	"github.com/SUNET/vc/pkg/pki"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
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

	// Ensure ECDSA signatures are in JWS format (IEEE P1363: fixed-size R||S).
	// Some Signer implementations (e.g., PKCS#11 HSMs, crypto.Signer wrappers)
	// may return ASN.1 DER-encoded signatures, which are not valid for JWS.
	// This normalization handles both formats transparently.
	signature, err = ensureJWSSignature(signature, signer.Algorithm())
	if err != nil {
		return "", fmt.Errorf("failed to normalize signature for JWS: %w", err)
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

// ExtractClaim extracts a specific claim from a JWT without validation
func ExtractClaim(token string, claimName string) (any, error) {
	if token == "" {
		return nil, fmt.Errorf("token is empty")
	}

	claims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(token, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	value, ok := claims[claimName]
	if !ok {
		return nil, fmt.Errorf("claim %q not found", claimName)
	}

	return value, nil
}

// ParseJWTWithJWKHeader parses and validates a JWT where the public key is embedded in the JWT header as a JWK
// Returns the parsed claims, the token header, the JWK header, the key thumbprint, and any error
func ParseJWTWithJWKHeader(token string) (jwt.MapClaims, map[string]any, map[string]any, string, error) {
	if token == "" {
		return nil, nil, nil, "", fmt.Errorf("token is empty")
	}

	claims := jwt.MapClaims{}
	var jwkHeader map[string]any
	var tokenHeader map[string]any
	var thumbprint string

	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		// Capture the full header
		tokenHeader = t.Header

		// Extract JWK from header
		jwkClaim, ok := t.Header["jwk"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("missing or invalid jwk in token header")
		}
		jwkHeader = jwkClaim

		// Parse JWK and get signing key
		jwkBytes, err := json.Marshal(jwkClaim)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal JWK: %w", err)
		}

		key, err := jwk.ParseKey(jwkBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse JWK: %w", err)
		}

		// Calculate thumbprint (RFC 7638: base64url-encoded)
		tp, err := key.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate key thumbprint: %w", err)
		}
		thumbprint = base64.RawURLEncoding.EncodeToString(tp)

		// Export key for signature verification
		algRaw, exists := t.Header["alg"]
		if !exists {
			return nil, fmt.Errorf("missing alg in token header")
		}
		algStr, ok := algRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid alg type in token header: expected string, got %T", algRaw)
		}
		switch jwt.GetSigningMethod(algStr).(type) {
		case *jwt.SigningMethodECDSA:
			var ecKey ecdsa.PublicKey
			if err := jwk.Export(key, &ecKey); err != nil {
				return nil, fmt.Errorf("failed to export ECDSA key: %w", err)
			}
			return &ecKey, nil
		case *jwt.SigningMethodRSA:
			var rsaKey rsa.PublicKey
			if err := jwk.Export(key, &rsaKey); err != nil {
				return nil, fmt.Errorf("failed to export RSA key: %w", err)
			}
			return &rsaKey, nil
		default:
			return nil, fmt.Errorf("unsupported signing method: %v", algStr)
		}
	})
	if err != nil {
		return nil, nil, nil, "", err
	}

	return claims, tokenHeader, jwkHeader, thumbprint, nil
}
