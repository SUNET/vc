package apiv1

import (
	"context"
	"fmt"
	"net/url"

	"github.com/SUNET/vc/pkg/crypto"
)

// AdminLoginURLReply holds the authorization URL and state for an OIDC login redirect.
type AdminLoginURLReply struct {
	AuthURL string
	State   string
}

// AdminLoginURL generates an OIDC authorization URL and a random state value.
// When OIDC is not configured, it returns an empty AuthURL to signal that
// login should proceed without authentication
func (c *Client) AdminLoginURL(ctx context.Context) (*AdminLoginURLReply, error) {
	if c.adminOIDC == nil {
		return &AdminLoginURLReply{}, nil
	}

	oauthCfg, err := c.adminOIDC.Config(ctx)
	if err != nil {
		return nil, fmt.Errorf("OIDC provider not ready: %w", err)
	}

	state, err := crypto.GenerateSecureToken(32, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	authURL := oauthCfg.AuthCodeURL(state)

	reply := &AdminLoginURLReply{
		AuthURL: authURL,
		State:   state,
	}

	return reply, nil
}

// AdminCallbackRequest holds the OIDC callback query parameters.
type AdminCallbackRequest struct {
	Code             string `form:"code"`
	State            string `form:"state"`
	Error            string `form:"error"`
	ErrorDescription string `form:"error_description"`
}

// AdminCallbackReply holds the authenticated subject.
type AdminCallbackReply struct {
	Subject    string
	RawIDToken string
}

// AdminCallback exchanges the authorization code for tokens, validates the
// ID token, resolves authorized resources, and returns the result.
func (c *Client) AdminCallback(ctx context.Context, req *AdminCallbackRequest) (*AdminCallbackReply, error) {
	if c.adminOIDC == nil {
		return nil, fmt.Errorf("OIDC authentication is not configured")
	}

	if req.Error != "" {
		return nil, fmt.Errorf("OIDC error: %s: %s", req.Error, req.ErrorDescription)
	}

	if req.Code == "" {
		return nil, fmt.Errorf("missing authorization code")
	}

	oauthCfg, err := c.adminOIDC.Config(ctx)
	if err != nil {
		return nil, fmt.Errorf("OIDC provider not ready: %w", err)
	}

	token, err := oauthCfg.Exchange(ctx, req.Code)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	verifier, err := c.adminOIDC.Verifier(ctx)
	if err != nil {
		return nil, fmt.Errorf("OIDC provider not ready: %w", err)
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("id_token verification failed: %w", err)
	}

	var claims struct {
		EPPN  string `json:"eppn"`
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %w", err)
	}

	// Use eppn or email as the SPOCP subject identity
	subject := claims.EPPN
	if subject == "" {
		subject = claims.Email
	}
	if subject == "" {
		subject = idToken.Subject
	}

	c.log.Info("admin OIDC callback", "subject", subject)

	reply := &AdminCallbackReply{
		Subject:    subject,
		RawIDToken: rawIDToken,
	}

	return reply, nil
}

// AdminLogoutURL returns the OIDC end_session_endpoint URL for RP-initiated
// logout, or empty string if the provider does not advertise one
func (c *Client) AdminLogoutURL(ctx context.Context, idTokenHint string) string {
	if c.adminOIDC == nil {
		return ""
	}
	endSessionURL := c.adminOIDC.EndSessionURL(ctx)
	if endSessionURL == "" {
		return ""
	}
	oauthCfg, err := c.adminOIDC.Config(ctx)
	if err != nil {
		return ""
	}
	v := url.Values{}
	if idTokenHint != "" {
		v.Set("id_token_hint", idTokenHint)
	}
	v.Set("client_id", oauthCfg.ClientID)
	v.Set("post_logout_redirect_uri", c.adminOIDC.PostLogoutRedirect(ctx))
	return endSessionURL + "?" + v.Encode()
}

// ListAuthenticSources returns all unique authentic source names from the datastore
func (c *Client) ListAuthenticSources(ctx context.Context) ([]string, error) {
	return c.datastoreStore.ListAuthenticSources(ctx)
}
