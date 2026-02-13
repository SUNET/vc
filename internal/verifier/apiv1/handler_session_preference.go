package apiv1

import (
	"context"
	"net/url"
	"time"
	"vc/pkg/cache"
	"vc/pkg/crypto"
)

// UpdateSessionPreferenceRequest represents a request to update session display preference
type UpdateSessionPreferenceRequest struct {
	SessionID             string `json:"session_id" binding:"required"`
	ShowCredentialDetails bool   `json:"show_credential_details"`
}

// UpdateSessionPreferenceResponse contains the response
type UpdateSessionPreferenceResponse struct {
	Success bool `json:"success"`
}

// UpdateSessionPreference updates the session's credential display preference
func (c *Client) UpdateSessionPreference(ctx context.Context, req *UpdateSessionPreferenceRequest) (*UpdateSessionPreferenceResponse, error) {
	// Get session
	authCtx, err := c.cacheService.AuthContext.GetByID(ctx, req.SessionID)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if authCtx == nil {
		return nil, ErrSessionNotFound
	}

	// Update preference
	authCtx.ShowCredentialDetails = req.ShowCredentialDetails

	if err := c.cacheService.AuthContext.Update(ctx, authCtx); err != nil {
		c.log.Error(err, "Failed to update session preference")
		return nil, ErrServerError
	}

	return &UpdateSessionPreferenceResponse{Success: true}, nil
}

// ConfirmCredentialDisplayRequest represents a confirmation from the credential display page
type ConfirmCredentialDisplayRequest struct {
	Confirmed bool `json:"confirmed"`
}

// ConfirmCredentialDisplayResponse contains the redirect URI
type ConfirmCredentialDisplayResponse struct {
	RedirectURI string `json:"redirect_uri"`
}

// ConfirmCredentialDisplay handles user confirmation after viewing credential details
func (c *Client) ConfirmCredentialDisplay(ctx context.Context, sessionID string, req *ConfirmCredentialDisplayRequest) (*ConfirmCredentialDisplayResponse, error) {
	// Get session
	authCtx, err := c.cacheService.AuthContext.GetByID(ctx, sessionID)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if authCtx == nil {
		return nil, ErrSessionNotFound
	}

	// Verify session is in the right state
	if authCtx.Status != cache.SessionStatusAwaitingPresentation {
		c.log.Info("Session not awaiting confirmation", "session_id", sessionID, "status", authCtx.Status)
		return nil, ErrInvalidRequest
	}

	if !req.Confirmed {
		// User cancelled - return error to RP
		c.log.Info("User cancelled credential display", "session_id", sessionID)
		authCtx.Status = cache.SessionStatusError
		if err := c.cacheService.AuthContext.Update(ctx, authCtx); err != nil {
			c.log.Error(err, "Failed to update session after cancellation")
			return nil, ErrServerError
		}

		redirectURI := ""
		if authCtx.RedirectURI != "" && authCtx.State != "" {
			u, err := url.Parse(authCtx.RedirectURI)
			if err != nil {
				c.log.Error(err, "Failed to parse redirect URI")
				return nil, ErrServerError
			}
			q := u.Query()
			q.Set("error", "access_denied")
			q.Set("error_description", "User cancelled")
			q.Set("state", authCtx.State)
			u.RawQuery = q.Encode()
			redirectURI = u.String()
		}

		return &ConfirmCredentialDisplayResponse{
			RedirectURI: redirectURI,
		}, nil
	}

	// User confirmed - issue authorization code
	code, err := crypto.GenerateSecureToken(0, 32)
	if err != nil {
		c.log.Error(err, "Failed to generate authorization code")
		return nil, ErrServerError
	}
	codeExpiry := time.Now().Add(time.Duration(c.cfg.Verifier.OIDC.CodeDuration) * time.Second)

	authCtx.Status = cache.SessionStatusCodeIssued
	authCtx.Code = code
	authCtx.CodeExpiresAt = codeExpiry.Unix()

	if err := c.cacheService.AuthContext.Update(ctx, authCtx); err != nil {
		c.log.Error(err, "Failed to update session after confirmation")
		return nil, ErrServerError
	}

	c.log.Info("User confirmed credential display, code issued", "session_id", sessionID)

	// Return redirect URI with code
	redirectURI := ""
	if authCtx.RedirectURI != "" {
		u, err := url.Parse(authCtx.RedirectURI)
		if err != nil {
			c.log.Error(err, "Failed to parse redirect URI")
			return nil, ErrServerError
		}
		q := u.Query()
		q.Set("code", code)
		q.Set("state", authCtx.State)
		u.RawQuery = q.Encode()
		redirectURI = u.String()
	}

	return &ConfirmCredentialDisplayResponse{
		RedirectURI: redirectURI,
	}, nil
}

// GetCredentialDisplayDataRequest represents a request to get display data
type GetCredentialDisplayDataRequest struct {
	SessionID string
}

// GetCredentialDisplayDataResponse contains data for the credential display page
type GetCredentialDisplayDataResponse struct {
	SessionID         string         `json:"session_id"`
	VPToken           string         `json:"vp_token"`
	Claims            map[string]any `json:"claims"`
	ClientID          string         `json:"client_id"`
	RedirectURI       string         `json:"redirect_uri"`
	State             string         `json:"state"`
	ShowRawCredential bool           `json:"show_raw_credential"`
	ShowClaims        bool           `json:"show_claims"`
	PrimaryColor      string         `json:"primary_color"`
	SecondaryColor    string         `json:"secondary_color"`
	CustomCSS         string         `json:"custom_css"`
}

// GetCredentialDisplayData retrieves data needed for the credential display page
func (c *Client) GetCredentialDisplayData(ctx context.Context, req *GetCredentialDisplayDataRequest) (*GetCredentialDisplayDataResponse, error) {
	// Get session
	authCtx, err := c.cacheService.AuthContext.GetByID(ctx, req.SessionID)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if authCtx == nil {
		return nil, ErrSessionNotFound
	}

	// Verify session has VP data
	if authCtx.VPToken == "" {
		c.log.Info("Session has no VP token", "session_id", req.SessionID)
		return nil, ErrInvalidRequest
	}

	// Build response
	response := &GetCredentialDisplayDataResponse{
		SessionID:         authCtx.SessionID,
		VPToken:           authCtx.VPToken,
		Claims:            authCtx.VerifiedClaims,
		ClientID:          authCtx.ClientID,
		RedirectURI:       authCtx.RedirectURI,
		State:             authCtx.State,
		ShowRawCredential: c.cfg.Verifier.CredentialDisplay.ShowRawCredential,
		ShowClaims:        c.cfg.Verifier.CredentialDisplay.ShowClaims,
		PrimaryColor:      c.cfg.Verifier.AuthorizationPageCSS.PrimaryColor,
		SecondaryColor:    c.cfg.Verifier.AuthorizationPageCSS.SecondaryColor,
		CustomCSS:         c.cfg.Verifier.AuthorizationPageCSS.CustomCSS,
	}

	// Set defaults
	if response.PrimaryColor == "" {
		response.PrimaryColor = "#3182ce"
	}
	if response.SecondaryColor == "" {
		response.SecondaryColor = "#2c5282"
	}

	return response, nil
}
