package apiv1

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/openid4vp"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// CreateRequestObject creates and signs an OpenID4VP request object
func (c *Client) CreateRequestObject(ctx context.Context, sessionID string, dcqlQuery *openid4vp.DCQL, nonce string) (string, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:create_request_object")
	defer span.End()

	// Determine response mode based on Digital Credentials API configuration
	responseMode := "direct_post"
	if c.cfg.Verifier.DigitalCredentials.Enable {
		if c.cfg.Verifier.DigitalCredentials.ResponseMode != "" {
			responseMode = c.cfg.Verifier.DigitalCredentials.ResponseMode
		} else {
			responseMode = "dc_api.jwt" // Default for DC API
		}
	}

	// Create request object
	// Use the OIDC direct_post endpoint which does not require a browser session,
	// so that external wallets can POST the VP token back.
	responseURI, err := url.JoinPath(c.cfg.Verifier.PublicURL, "/verification/oidc-direct_post")
	if err != nil {
		c.log.Error(err, "Failed to construct response URI")
		return "", err
	}
	// Determine client_id based on configured scheme (x509_san_dns or did)
	clientID, err := c.cfg.Verifier.VerifierClientID()
	if err != nil {
		return "", fmt.Errorf("failed to determine verifier client_id: %w", err)
	}

	requestObject := &openid4vp.RequestObject{
		ISS:          c.cfg.Verifier.Outbound.OIDCProvider.Issuer,
		AUD:          "https://self-issued.me/v2",
		IAT:          time.Now().Unix(),
		ResponseType: "vp_token",
		ClientID:     clientID,
		Nonce:        nonce,
		ResponseMode: responseMode,
		ResponseURI:  responseURI,
		State:        sessionID,
		DCQLQuery:    dcqlQuery,
	}

	// Add vp_formats_supported to client_metadata if Digital Credentials API is enabled
	if c.cfg.Verifier.DigitalCredentials.Enable && c.cfg.Verifier.PreferredVPFormats != nil {
		requestObject.ClientMetadata = &openid4vp.ClientMetadata{
			VPFormatsSupported: c.cfg.Verifier.PreferredVPFormats,
		}
	}

	// Sign the request object with X.509 certificate chain for x509_san_dns verification
	signedJWT, err := requestObject.Sign(ctx, c.pkiSigner, c.pkiSignerChain)
	if err != nil {
		c.log.Error(err, "Failed to sign request object")
		return "", err
	}

	// Cache the request object
	c.cacheService.RequestObject.SetWithTTL(ctx, sessionID, requestObject, 5*time.Minute)

	if c.vpMetrics != nil {
		c.vpMetrics.RequestsCreated.Add(ctx, 1)
	}

	return signedJWT, nil
}

// GetRequestObject retrieves a request object by session ID
func (c *Client) GetRequestObject(ctx context.Context, sessionID string) (*openid4vp.RequestObject, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:get_request_object")
	defer span.End()

	val, ok := c.cacheService.RequestObject.Get(ctx, sessionID)
	if !ok {
		return nil, ErrNotFound
	}

	return val, nil
}

// HandleDirectPost processes the OpenID4VP direct_post response from a wallet
func (c *Client) HandleDirectPost(ctx context.Context, sessionID string, vpToken string, presentationSubmission any) error {
	start := time.Now()
	ctx, span := c.tracer.Start(ctx, "apiv1:handle_direct_post")
	defer span.End()

	// Get the session
	authCtx, err := c.cacheService.AuthContext.GetByID(ctx, sessionID)
	if err != nil {
		c.log.Error(err, "Failed to get session")
		return ErrServerError
	}
	if authCtx == nil {
		c.log.Info("Session not found", "session_id", sessionID)
		return ErrInvalidRequest
	}

	// Update session with VP token and presentation submission
	authCtx.VPToken = vpToken
	authCtx.PresentationSubmission = presentationSubmission

	// Extract claims from VP token
	claims, err := c.extractAndMapClaims(ctx, vpToken, "")
	if err != nil {
		c.log.Error(err, "Failed to extract claims from VP token")
		authCtx.Status = "error"
		if err := c.cacheService.AuthContext.Update(ctx, authCtx); err != nil {
			c.log.Error(err, "Failed to update session with error status")
		}
		if c.vpMetrics != nil {
			c.vpMetrics.VerificationsFailed.Add(ctx, 1, metric.WithAttributes(
				attribute.String("error_class", "claims_extraction"),
			))
		}
		return err
	}

	// Store verified claims
	authCtx.VerifiedClaims = claims

	// Generate authorization code
	authCode, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		c.log.Error(err, "Failed to generate authorization code")
		return err
	}
	authCtx.Code = authCode
	authCtx.CodeExpiresAt = time.Now().Add(time.Duration(c.cfg.Verifier.Outbound.OIDCProvider.CodeDuration) * time.Second).Unix()
	authCtx.Status = "code_issued"

	// Update session
	if err := c.cacheService.AuthContext.Update(ctx, authCtx); err != nil {
		c.log.Error(err, "Failed to update session")
		return ErrServerError
	}

	if c.vpMetrics != nil {
		c.vpMetrics.PresentationsReceived.Add(ctx, 1)
		c.vpMetrics.VerificationLatency.Record(ctx, time.Since(start).Seconds())
	}

	return nil
}

// GetPollStatus returns the current status of a session for polling
func (c *Client) GetPollStatus(ctx context.Context, sessionID string) (*SessionPollResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:get_poll_status")
	defer span.End()

	authCtx, err := c.cacheService.AuthContext.GetByID(ctx, sessionID)
	if err != nil {
		c.log.Error(err, "Failed to get session")
		return nil, ErrServerError
	}
	if authCtx == nil {
		return nil, ErrNotFound
	}

	response := &SessionPollResponse{
		SessionID: authCtx.SessionID,
		Status:    string(authCtx.Status),
	}

	// Include authorization code if available
	if authCtx.Status == "code_issued" && authCtx.Code != "" {
		response.AuthorizationCode = authCtx.Code
		response.RedirectURI = authCtx.RedirectURI
		response.State = authCtx.State
	}

	return response, nil
}

// SessionPollResponse represents the response from polling a session
type SessionPollResponse struct {
	SessionID         string `json:"session_id"`
	Status            string `json:"status"`
	AuthorizationCode string `json:"authorization_code,omitempty"`
	RedirectURI       string `json:"redirect_uri,omitempty"`
	State             string `json:"state,omitempty"`
}
