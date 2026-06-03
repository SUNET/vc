package apiv1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
func (c *Client) signMetadataViaIssuer(ctx context.Context, metadata any, metadataType string, issuer string) (string, error) {
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Guard against a stuck issuer gRPC call; each call gets its own 30s budget.
	grpcCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	reply, err := c.issuerClient.SignMetadata(grpcCtx, &apiv1_issuer.SignMetadataRequest{
		MetadataJson: metadataJSON,
		MetadataType: metadataType,
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
// signed metadata warm in the cache. On startup it retries with a 5-second
// pause between attempts until the issuer is reachable, then switches to
// 55-minute steady-state refreshes. Note: each attempt calls refreshSignedMetadata
// which makes two gRPC calls (VCI + OAuth2), each with a 30-second timeout, so a
// single retry iteration can take over 60 seconds when the issuer is unresponsive.
func (c *Client) StartSignedMetadataRefresher(ctx context.Context) {
	go func() {
		// Retry loop: wait for the issuer to become reachable.
		for {
			c.refreshSignedMetadata(ctx)
			if c.issuerReachable.Load() {
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
// In HA mode, multiple nodes may race — each signs and writes with Set (last writer
// wins). This is acceptable because all nodes sign identical metadata with the same
// key, so any value is equally valid.
func (c *Client) refreshSignedMetadata(ctx context.Context) {
	var unreachable bool
	var cached int

	// Refresh VCI metadata
	vci, err := c.signMetadataViaIssuer(ctx, c.issuerMetadata, "vci-issuer", c.issuerMetadata.CredentialIssuer)
	if err != nil {
		if isGRPCUnavailable(err) {
			unreachable = true
			c.log.Debug("failed to refresh VCI signed metadata", "error", err)
		} else {
			c.log.Error(err, "failed to refresh VCI signed metadata")
		}
	} else {
		c.cacheService.SignedMetadata.Set(ctx, signedMetadataKeyVCI, vci)
		cached++
	}

	// Refresh OAuth2 metadata
	oauth2Signed, err := c.signMetadataViaIssuer(ctx, c.oauth2Metadata, "oauth2-authorization-server", c.oauth2Metadata.Issuer)
	if err != nil {
		if isGRPCUnavailable(err) {
			unreachable = true
			c.log.Debug("failed to refresh OAuth2 signed metadata", "error", err)
		} else {
			c.log.Error(err, "failed to refresh OAuth2 signed metadata")
		}
	} else {
		c.cacheService.SignedMetadata.Set(ctx, signedMetadataKeyOAuth2, oauth2Signed)
		cached++
	}

	// Log state transitions at Info level so operators notice when the issuer
	// becomes reachable or goes away. Only gRPC UNAVAILABLE (transport-level
	// failures) flips the reachability flag; application-level errors (e.g.
	// invalid metadata, signing failures) are logged above but do not affect
	// the reachability state.
	wasReachable := c.issuerReachable.Load()
	if !unreachable && !wasReachable {
		c.issuerReachable.Store(true)
		if cached > 0 {
			c.log.Info("issuer signing service is now reachable, signed metadata cached", "cached", cached)
		} else {
			c.log.Info("issuer signing service is now reachable, but no metadata was cached (check application errors above)")
		}
	} else if unreachable && wasReachable {
		c.log.Info("issuer signing service became unreachable")
		c.issuerReachable.Store(false)
	}
}

// isGRPCUnavailable reports whether err is a gRPC UNAVAILABLE error,
// indicating a transport-level connectivity failure.
// It unwraps the error chain so it works even when the gRPC status has
// been wrapped with fmt.Errorf.
func isGRPCUnavailable(err error) bool {
	for e := err; e != nil; e = errors.Unwrap(e) {
		if s, ok := status.FromError(e); ok {
			return s.Code() == codes.Unavailable
		}
	}
	return false
}
