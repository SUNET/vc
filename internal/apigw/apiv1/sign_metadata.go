package apiv1

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
)

// signMetadataViaIssuer delegates metadata signing to the issuer service via gRPC.
// The issuer signs with its own key (the key advertised in /jwks), ensuring that
// wallets can verify signed_metadata by looking up the kid in the JWKS endpoint.
func (c *Client) signMetadataViaIssuer(ctx context.Context, metadata any, typ string, issuer string) (string, error) {
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %w", err)
	}

	reply, err := c.issuerClient.SignMetadata(ctx, &apiv1_issuer.SignMetadataRequest{
		MetadataJson: metadataJSON,
		Typ:          typ,
		Iss:          issuer,
		Sub:          issuer,
	})
	if err != nil {
		return "", fmt.Errorf("failed to sign metadata via issuer: %w", err)
	}

	return reply.GetSignedMetadata(), nil
}
