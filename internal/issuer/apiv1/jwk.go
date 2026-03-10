package apiv1

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func (c *Client) createJWK(ctx context.Context) error {
	_, cancel := context.WithDeadline(ctx, time.Now().Add(2*time.Second))
	defer cancel()

	// Create JWK from private key (supports both ECDSA and RSA)
	key, err := jwk.Import(c.privateKey)
	if err != nil {
		return fmt.Errorf("failed to create JWK from private key: %w", err)
	}

	// Use the same kid that the signer puts into JWT headers.
	// This ensures the JWKS endpoint serves keys with matching kid values.
	kid := c.signer.KeyID()

	if err := key.Set("kid", kid); err != nil {
		return fmt.Errorf("failed to set kid: %w", err)
	}

	keyID, ok := key.KeyID()
	if !ok {
		return fmt.Errorf("failed to get key ID")
	}
	c.kid = keyID

	// Marshal JWK to JSON
	c.jwkBytes, err = json.MarshalIndent(key, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JWK: %w", err)
	}

	// Unmarshal into proto structure
	if err := json.Unmarshal(c.jwkBytes, c.jwkProto); err != nil {
		return fmt.Errorf("failed to unmarshal JWK into proto: %w", err)
	}

	// Create JWT claim based on key type
	switch c.privateKey.(type) {
	case *ecdsa.PrivateKey:
		// ECDSA keys have crv, x, y fields
		c.jwkClaim["jwk"] = jwt.MapClaims{
			"kid": c.jwkProto.Kid,
			"kty": c.jwkProto.Kty,
			"crv": c.jwkProto.Crv,
			"x":   c.jwkProto.X,
			"y":   c.jwkProto.Y,
		}
	case *rsa.PrivateKey:
		// RSA keys have n, e fields (stored differently in proto)
		// For RSA public keys, we only need kty, kid, and the public key components
		jwkClaim := jwt.MapClaims{
			"kid": c.jwkProto.Kid,
			"kty": c.jwkProto.Kty,
		}

		// Parse the full JWK to get RSA-specific fields
		var fullJWK map[string]any
		if err := json.Unmarshal(c.jwkBytes, &fullJWK); err == nil {
			// Add RSA-specific fields if present
			if n, ok := fullJWK["n"].(string); ok {
				jwkClaim["n"] = n
			}
			if e, ok := fullJWK["e"].(string); ok {
				jwkClaim["e"] = e
			}
		}

		c.jwkClaim["jwk"] = jwkClaim
	default:
		return fmt.Errorf("unsupported key type: %T", c.privateKey)
	}

	return nil
}
