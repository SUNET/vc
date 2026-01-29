package apiv1

import (
	"context"
	"fmt"
	"time"
	"vc/internal/verifier/db"
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
	session, err := c.db.Sessions.GetByID(ctx, req.SessionID)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Update preference
	session.OIDCRequest.ShowCredentialDetails = req.ShowCredentialDetails

	if err := c.db.Sessions.Update(ctx, session); err != nil {
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
	session, err := c.db.Sessions.GetByID(ctx, sessionID)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Verify session is in the right state
	if session.Status != db.SessionStatusAwaitingPresentation {
		c.log.Info("Session not awaiting confirmation", "session_id", sessionID, "status", session.Status)
		return nil, ErrInvalidRequest
	}

	if !req.Confirmed {
		// User cancelled - return error to RP
		c.log.Info("User cancelled credential display", "session_id", sessionID)
		session.Status = db.SessionStatusError
		c.db.Sessions.Update(ctx, session)

		redirectURI := ""
		if session.OIDCRequest.RedirectURI != "" && session.OIDCRequest.State != "" {
			redirectURI = fmt.Sprintf("%s?error=access_denied&error_description=User+cancelled&state=%s",
				session.OIDCRequest.RedirectURI,
				session.OIDCRequest.State,
			)
		}

		return &ConfirmCredentialDisplayResponse{
			RedirectURI: redirectURI,
		}, nil
	}

	// User confirmed - issue authorization code
	code := c.generateAuthorizationCode()
	codeExpiry := time.Now().Add(time.Duration(c.cfg.Verifier.OIDC.CodeDuration) * time.Second)

	session.Status = db.SessionStatusCodeIssued
	session.Tokens.AuthorizationCode = code
	session.Tokens.CodeExpiresAt = codeExpiry

	if err := c.db.Sessions.Update(ctx, session); err != nil {
		c.log.Error(err, "Failed to update session after confirmation")
		return nil, ErrServerError
	}

	c.log.Info("User confirmed credential display, code issued", "session_id", sessionID)

	// Return redirect URI with code
	redirectURI := ""
	if session.OIDCRequest.RedirectURI != "" {
		redirectURI = fmt.Sprintf("%s?code=%s&state=%s",
			session.OIDCRequest.RedirectURI,
			code,
			session.OIDCRequest.State,
		)
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
	session, err := c.db.Sessions.GetByID(ctx, req.SessionID)
	if err != nil {
		return nil, ErrSessionNotFound
	}
	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Verify session has VP data
	if session.OpenID4VP.VPToken == "" {
		c.log.Info("Session has no VP token", "session_id", req.SessionID)
		return nil, ErrInvalidRequest
	}

	// Build response
	response := &GetCredentialDisplayDataResponse{
		SessionID:         session.ID,
		VPToken:           session.OpenID4VP.VPToken,
		Claims:            session.VerifiedClaims,
		ClientID:          session.OIDCRequest.ClientID,
		RedirectURI:       session.OIDCRequest.RedirectURI,
		State:             session.OIDCRequest.State,
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
