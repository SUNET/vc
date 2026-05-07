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
func (c *Client) AdminLoginURL(_ context.Context) (*AdminLoginURLReply, error) {
	if c.adminOIDCConfig == nil {
		return nil, fmt.Errorf("OIDC authentication is not configured")
	}

	state, err := crypto.GenerateSecureToken(32, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	authURL := c.adminOIDCConfig.AuthCodeURL(state)

	reply := &AdminLoginURLReply{
		AuthURL: authURL,
		State:   state,
	}

	return reply, nil
}

// AdminCallbackRequest holds the authorization code from the OIDC callback.
type AdminCallbackRequest struct {
	Code string
}

// AdminCallbackReply holds the authenticated subject from the OIDC callback.
type AdminCallbackReply struct {
	Subject    string
	RawIDToken string
	OrgIDs     []string
	GivenName  string
}

// AdminCallback exchanges the authorization code for tokens, validates the
// ID token, and returns the subject.
func (c *Client) AdminCallback(ctx context.Context, req *AdminCallbackRequest) (*AdminCallbackReply, error) {
	if c.adminOIDCConfig == nil {
		return nil, fmt.Errorf("OIDC authentication is not configured")
	}

	token, err := c.adminOIDCConfig.Exchange(ctx, req.Code)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in token response")
	}

	idToken, err := c.adminOIDCVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("id_token verification failed: %w", err)
	}

	var claims struct {
		OrgID     []string `json:"org_id"`
		GivenName string   `json:"given_name"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %w", err)
	}

	// Debug: log all claims from the ID token
	var allClaims map[string]any
	if err := idToken.Claims(&allClaims); err == nil {
		c.log.Info("admin OIDC callback", "subject", idToken.Subject, "claims", allClaims, "parsed_org_id", claims.OrgID)
	}

	reply := &AdminCallbackReply{
		Subject:    idToken.Subject,
		RawIDToken: rawIDToken,
		OrgIDs:     claims.OrgID,
		GivenName:  claims.GivenName,
	}

	return reply, nil
}

// AdminLogoutURL returns the OIDC end_session_endpoint URL for RP-initiated
// logout, or empty string if the provider does not advertise one
func (c *Client) AdminLogoutURL(idTokenHint string) string {
	if c.adminOIDCEndSessionURL == "" {
		return ""
	}
	v := url.Values{}
	if idTokenHint != "" {
		v.Set("id_token_hint", idTokenHint)
	}
	v.Set("client_id", c.adminOIDCConfig.ClientID)
	v.Set("post_logout_redirect_uri", c.adminOIDCPostLogoutRedirect)
	return c.adminOIDCEndSessionURL + "?" + v.Encode()
}
