package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// createJWK builds the public JWK from the signer's key material and populates
// the proto structure used by the gRPC JWKS endpoint.
//
// Key design decisions:
//   - Uses go-jose (same library as pki.SignerConfig.GetJWK) for consistent JWK serialization
//   - Only serializes the PUBLIC key — no private key material flows over gRPC
//   - Kid is derived from the signer (same source as JWT header kid) to guarantee
//     that verifiers can match JWKS keys to JWT headers
func (c *Client) createJWK(ctx context.Context) error {
	_, cancel := context.WithDeadline(ctx, time.Now().Add(2*time.Second))
	defer cancel()

	// Build JWK from the signer's public key.
	// go-jose handles EC, RSA, and Ed25519 key types uniformly.
	jwk := jose.JSONWebKey{
		Key:       c.signer.PublicKey(),
		KeyID:     c.signer.KeyID(),
		Algorithm: c.signer.Algorithm(),
		Use:       "sig",
	}

	// Marshal to JSON (public key only — no private key material)
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		return fmt.Errorf("failed to marshal JWK: %w", err)
	}

	// Populate proto for the gRPC JWKS endpoint
	if err := json.Unmarshal(jwkBytes, c.jwkProto); err != nil {
		return fmt.Errorf("failed to unmarshal JWK into proto: %w", err)
	}

	return nil
}
