package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/SUNET/vc/internal/gen/issuer/apiv1_issuer"
)

const (
	// Cache keys for signed metadata
	signedMetadataKeyVCI    = "vci"
	signedMetadataKeyOAuth2 = "oauth2"

	// signedMetadataRefreshInterval is how often the background ticker refreshes.
	// Slightly shorter than the 1-hour cache TTL to ensure continuity.
	signedMetadataRefreshInterval = 55 * time.Minute
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

// getOrSignMetadata returns cached signed metadata on hit, or signs via the
// issuer gRPC on cache miss and stores the result. Freshness is provided by
// the background ticker (StartSignedMetadataRefresher), not by this function.
func (c *Client) getOrSignMetadata(ctx context.Context, cacheKey string, metadata any, typ string, issuer string) (string, error) {
	// Try cache first
	if cached, ok := c.cacheService.SignedMetadata.Get(ctx, cacheKey); ok {
		return cached, nil
	}

	// Cache miss — sign via issuer
	signed, err := c.signMetadataViaIssuer(ctx, metadata, typ, issuer)
	if err != nil {
		return "", err
	}

	// Atomic write: in HA, only the first node to set wins.
	// If another node already cached it, that's fine — we use our freshly
	// signed copy for this response and the cached one will be used next time.
	c.cacheService.SignedMetadata.SetNX(ctx, cacheKey, signed)

	return signed, nil
}

// StartSignedMetadataRefresher starts a background ticker that refreshes
// signed metadata in the cache every 55 minutes, keeping it warm.
// Call this once during apigw initialization.
func (c *Client) StartSignedMetadataRefresher(ctx context.Context) {
	ticker := time.NewTicker(signedMetadataRefreshInterval)

	go func() {
		// Do an initial refresh at startup
		c.refreshSignedMetadata(ctx)

		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				c.refreshSignedMetadata(ctx)
			}
		}
	}()

	c.log.Info("signed metadata refresher started", "interval", signedMetadataRefreshInterval)
}

// refreshSignedMetadata fetches fresh signed metadata from the issuer and
// updates the cache. In HA mode, multiple nodes may race — each signs and
// writes atomically; the first writer wins via SetNX, others simply overwrite
// on the next cycle when the TTL has expired.
func (c *Client) refreshSignedMetadata(ctx context.Context) {
	// Guard against a stuck issuer gRPC call blocking the refresher indefinitely.
	refreshCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Refresh VCI metadata
	vci, err := c.signMetadataViaIssuer(refreshCtx, c.issuerMetadata, "openidvci-issuer-metadata+jwt", c.issuerMetadata.CredentialIssuer)
	if err != nil {
		c.log.Error(err, "failed to refresh VCI signed metadata")
	} else {
		c.cacheService.SignedMetadata.Set(refreshCtx, signedMetadataKeyVCI, vci)
		c.log.Debug("refreshed VCI signed metadata")
	}

	// Refresh OAuth2 metadata
	oauth2Signed, err := c.signMetadataViaIssuer(refreshCtx, c.oauth2Metadata, "JWT", c.oauth2Metadata.Issuer)
	if err != nil {
		c.log.Error(err, "failed to refresh OAuth2 signed metadata")
	} else {
		c.cacheService.SignedMetadata.Set(refreshCtx, signedMetadataKeyOAuth2, oauth2Signed)
		c.log.Debug("refreshed OAuth2 signed metadata")
	}
}
