package apiv1

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
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

// issuerReachable tracks whether the issuer gRPC was reachable on the last refresh.
// Used to log state transitions (down→up, up→down) at Info level.
var issuerReachable atomic.Bool

// signMetadataViaIssuer delegates metadata signing to the issuer service via gRPC.
// The issuer signs with its own key (the key advertised in /jwks), ensuring that
// wallets can verify signed_metadata by looking up the kid in the JWKS endpoint.
func (c *Client) signMetadataViaIssuer(ctx context.Context, metadata any, typ string, issuer string) (string, error) {
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Guard against a stuck issuer gRPC call; each call gets its own 30s budget.
	grpcCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	reply, err := c.issuerClient.SignMetadata(grpcCtx, &apiv1_issuer.SignMetadataRequest{
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
	if _, err := c.cacheService.SignedMetadata.SetNX(ctx, cacheKey, signed); err != nil {
		c.log.Error(err, "failed to cache signed metadata", "key", cacheKey)
	}

	return signed, nil
}

// StartSignedMetadataRefresher starts a background goroutine that keeps
// signed metadata warm in the cache. On startup it retries every 5 seconds
// until the issuer is reachable, then switches to 55-minute steady-state refreshes.
func (c *Client) StartSignedMetadataRefresher(ctx context.Context) {
	go func() {
		// Retry loop: wait for the issuer to become reachable.
		for {
			c.refreshSignedMetadata(ctx)
			if issuerReachable.Load() {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}

		// Steady-state: refresh every 55 minutes.
		ticker := time.NewTicker(signedMetadataRefreshInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.refreshSignedMetadata(ctx)
			}
		}
	}()

	c.log.Info("signed metadata refresher started")
}

// refreshSignedMetadata fetches fresh signed metadata from the issuer and
// updates the cache. Each gRPC call has its own 30s timeout (in signMetadataViaIssuer).
// In HA mode, multiple nodes may race — each signs and writes; the first writer
// wins via SetNX, others simply overwrite on the next cycle when the TTL has expired.
func (c *Client) refreshSignedMetadata(ctx context.Context) {
	var failed bool

	// Refresh VCI metadata
	vci, err := c.signMetadataViaIssuer(ctx, c.issuerMetadata, "openidvci-issuer-metadata+jwt", c.issuerMetadata.CredentialIssuer)
	if err != nil {
		c.log.Error(err, "failed to refresh VCI signed metadata")
		failed = true
	} else {
		c.cacheService.SignedMetadata.Set(ctx, signedMetadataKeyVCI, vci)
	}

	// Refresh OAuth2 metadata
	oauth2Signed, err := c.signMetadataViaIssuer(ctx, c.oauth2Metadata, "JWT", c.oauth2Metadata.Issuer)
	if err != nil {
		c.log.Error(err, "failed to refresh OAuth2 signed metadata")
		failed = true
	} else {
		c.cacheService.SignedMetadata.Set(ctx, signedMetadataKeyOAuth2, oauth2Signed)
	}

	// Log state transitions at Info level so operators notice when the issuer
	// becomes reachable or goes away.
	wasReachable := issuerReachable.Load()
	if !failed && !wasReachable {
		c.log.Info("issuer signing service is now reachable, signed metadata cached")
		issuerReachable.Store(true)
	} else if failed && wasReachable {
		c.log.Info("issuer signing service became unreachable")
		issuerReachable.Store(false)
	}
}
