package apiv1

import (
	"context"
	"net/url"
	"time"
	"vc/pkg/crypto"
	"vc/pkg/openid4vp"
)

// CreateRequestObject creates and signs an OpenID4VP request object
func (c *Client) CreateRequestObject(ctx context.Context, sessionID string, dcqlQuery *openid4vp.DCQL, nonce string) (string, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:create_request_object")
	defer span.End()

	// Determine response mode based on Digital Credentials API configuration
	responseMode := "direct_post"
	if c.cfg.Verifier.DigitalCredentials.Enabled {
		if c.cfg.Verifier.DigitalCredentials.ResponseMode != "" {
			responseMode = c.cfg.Verifier.DigitalCredentials.ResponseMode
		} else {
			responseMode = "dc_api.jwt" // Default for DC API
		}
	}

	// Create request object
	responseURI, err := url.JoinPath(c.cfg.Verifier.PublicURL, "/verification/direct_post")
	if err != nil {
		c.log.Error(err, "Failed to construct response URI")
		return "", err
	}
	requestObject := &openid4vp.RequestObject{
		ISS:          c.cfg.Verifier.OIDC.Issuer,
		AUD:          "https://self-issued.me/v2",
		IAT:          time.Now().Unix(),
		ResponseType: "vp_token",
		ClientID:     c.cfg.Verifier.OIDC.Issuer,
		Nonce:        nonce,
		ResponseMode: responseMode,
		ResponseURI:  responseURI,
		State:        sessionID,
		DCQLQuery:    dcqlQuery,
	}

	// Add vp_formats_supported to client_metadata if Digital Credentials API is enabled
	if c.cfg.Verifier.DigitalCredentials.Enabled && c.cfg.Verifier.PreferredVPFormats != nil {
		requestObject.ClientMetadata = &openid4vp.ClientMetadata{
			VPFormatsSupported: c.cfg.Verifier.PreferredVPFormats,
		}
	}

	// Sign the request object
	signedJWT, err := requestObject.Sign(ctx, c.pkiSigner, nil)
	if err != nil {
		c.log.Error(err, "Failed to sign request object")
		return "", err
	}

	// Cache the request object
	c.requestObjectCache.Set(sessionID, requestObject, 5*time.Minute)

	return signedJWT, nil
}

// buildVPFormats constructs the vp_formats object based on configured preferred formats
func (c *Client) buildVPFormats() *openid4vp.VPFormatsSupported {
	result := &openid4vp.VPFormatsSupported{}

	preferredFormats := c.cfg.Verifier.DigitalCredentials.PreferredFormats
	if len(preferredFormats) == 0 {
		// Default to SD-JWT if no preferences specified
		preferredFormats = []string{"vc+sd-jwt"}
	}

	for _, format := range preferredFormats {
		switch format {
		case "vc+sd-jwt", "dc+sd-jwt":
			// SD-JWT format with supported algorithms
			if result.SDJWT == nil {
				result.SDJWT = &openid4vp.SDJWTVCFormat{
					SDJWTAlgValues: []string{"ES256", "ES384", "ES512", "RS256"},
					KBJWTAlgValues: []string{"ES256", "ES384", "ES512", "RS256"},
				}
			}
		case "mso_mdoc":
			// mdoc format with COSE algorithm identifiers
			if result.MsoMdoc == nil {
				result.MsoMdoc = &openid4vp.MsoMdocFormat{
					IssuerAuthAlgValues: []int{-7, -35, -36}, // ES256, ES384, ES512
					DeviceAuthAlgValues: []int{-7, -35, -36},
				}
			}
		}
	}

	return result
}

// GetRequestObject retrieves a request object by session ID
func (c *Client) GetRequestObject(ctx context.Context, sessionID string) (*openid4vp.RequestObject, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:get_request_object")
	defer span.End()

	item := c.requestObjectCache.Get(sessionID)
	if item == nil {
		return nil, ErrNotFound
	}

	return item.Value(), nil
}

// HandleDirectPost processes the OpenID4VP direct_post response from a wallet
func (c *Client) HandleDirectPost(ctx context.Context, sessionID string, vpToken string, presentationSubmission any) error {
	ctx, span := c.tracer.Start(ctx, "apiv1:handle_direct_post")
	defer span.End()

	// Get the session
	session, err := c.db.Sessions.GetByID(ctx, sessionID)
	if err != nil {
		c.log.Error(err, "Failed to get session")
		return ErrServerError
	}
	if session == nil {
		c.log.Info("Session not found", "session_id", sessionID)
		return ErrInvalidRequest
	}

	// Update session with VP token and presentation submission
	session.OpenID4VP.VPToken = vpToken
	session.OpenID4VP.PresentationSubmission = presentationSubmission

	// Extract claims from VP token
	claims, err := c.extractClaimsFromVPToken(ctx, vpToken)
	if err != nil {
		c.log.Error(err, "Failed to extract claims from VP token")
		session.Status = "error"
		if err := c.db.Sessions.Update(ctx, session); err != nil {
			c.log.Error(err, "Failed to update session with error status")
		}
		return err
	}

	// Store verified claims
	session.VerifiedClaims = claims

	// Generate authorization code
	authCode, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		c.log.Error(err, "Failed to generate authorization code")
		return err
	}
	session.Tokens.AuthorizationCode = authCode
	session.Tokens.CodeExpiresAt = time.Now().Add(time.Duration(c.cfg.Verifier.OIDC.CodeDuration) * time.Second)
	session.Status = "code_issued"

	// Update session
	if err := c.db.Sessions.Update(ctx, session); err != nil {
		c.log.Error(err, "Failed to update session")
		return ErrServerError
	}

	return nil
}

// extractClaimsFromVPToken extracts and maps claims from the VP token
func (c *Client) extractClaimsFromVPToken(ctx context.Context, vpToken string) (map[string]any, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:extract_claims")
	defer span.End()

	// If no claims extractor, return empty claims
	if c.claimsExtractor == nil {
		c.log.Debug("No claims extractor configured")
		return make(map[string]any), nil
	}

	// Extract claims
	claims, err := c.claimsExtractor.ExtractClaimsFromVPToken(ctx, vpToken)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// GetPollStatus returns the current status of a session for polling
func (c *Client) GetPollStatus(ctx context.Context, sessionID string) (*SessionPollResponse, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:get_poll_status")
	defer span.End()

	session, err := c.db.Sessions.GetByID(ctx, sessionID)
	if err != nil {
		c.log.Error(err, "Failed to get session")
		return nil, ErrServerError
	}
	if session == nil {
		return nil, ErrNotFound
	}

	response := &SessionPollResponse{
		SessionID: session.ID,
		Status:    string(session.Status),
	}

	// Include authorization code if available
	if session.Status == "code_issued" && session.Tokens.AuthorizationCode != "" {
		response.AuthorizationCode = session.Tokens.AuthorizationCode
		response.RedirectURI = session.OIDCRequest.RedirectURI
		response.State = session.OIDCRequest.State
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
