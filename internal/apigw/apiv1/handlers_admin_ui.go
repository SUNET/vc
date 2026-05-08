package apiv1

import (
	"context"
	"fmt"
	"net/url"

	"github.com/SUNET/vc/pkg/crypto"
	"github.com/SUNET/vc/pkg/httphelpers"
)

// AdminLoginURLReply holds the authorization URL and state for an OIDC login redirect.
type AdminLoginURLReply struct {
	AuthURL string
	State   string
}

// AdminLoginURL generates an OIDC authorization URL and a random state value.
// When OIDC is not configured, it returns an empty AuthURL to signal that
// login should proceed without authentication
func (c *Client) AdminLoginURL(_ context.Context) (*AdminLoginURLReply, error) {
	if c.adminOIDCConfig == nil {
		return &AdminLoginURLReply{}, nil
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

// AdminCallbackRequest holds the OIDC callback query parameters.
type AdminCallbackRequest struct {
	Code             string `form:"code"`
	State            string `form:"state"`
	Error            string `form:"error"`
	ErrorDescription string `form:"error_description"`
}

// AdminCallbackReply holds the authenticated subject and resolved resources.
type AdminCallbackReply struct {
	Subject          string
	RawIDToken       string
	AllowedResources []AllowedResource
}

// AllowedResource represents a resource+scope pair the subject can access
type AllowedResource struct {
	AuthenticSource string
	Scope           string
}

// AdminCallback exchanges the authorization code for tokens, validates the
// ID token, resolves authorized resources, and returns the result.
func (c *Client) AdminCallback(ctx context.Context, req *AdminCallbackRequest) (*AdminCallbackReply, error) {
	if c.adminOIDCConfig == nil {
		return nil, fmt.Errorf("OIDC authentication is not configured")
	}

	if req.Error != "" {
		return nil, fmt.Errorf("OIDC error: %s: %s", req.Error, req.ErrorDescription)
	}

	if req.Code == "" {
		return nil, fmt.Errorf("missing authorization code")
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

	// Resolve which authentic sources this subject can access
	allowedResources, err := c.resolveAdminResources(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("resource resolution failed: %w", err)
	}

	reply := &AdminCallbackReply{
		Subject:          subject,
		RawIDToken:       rawIDToken,
		AllowedResources: allowedResources,
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

// ListAuthenticSources returns all unique authentic source names from the datastore
func (c *Client) ListAuthenticSources(ctx context.Context) ([]string, error) {
	return c.datastoreStore.ListAuthenticSources(ctx)
}

// resolveAdminResources determines which authentic source + scope combinations
// the subject can access by querying each pair against the SPOCP engine
func (c *Client) resolveAdminResources(ctx context.Context, subject string) ([]AllowedResource, error) {
	if c.spocpEngine == nil {
		return nil, fmt.Errorf("SPOCP engine is not configured")
	}

	// Combine authentic sources from DB and from parsed SPOCP rules
	dbSources, err := c.datastoreStore.ListAuthenticSources(ctx)
	if err != nil {
		return nil, err
	}
	sourceSet := map[string]struct{}{}
	for _, s := range dbSources {
		sourceSet[s] = struct{}{}
	}
	for _, s := range c.spocpUIResources {
		sourceSet[s] = struct{}{}
	}

	var scopes []string
	if c.cfg.Common != nil {
		for scope := range c.cfg.Common.CredentialMetadata {
			scopes = append(scopes, scope)
		}
	}

	var allowed []AllowedResource
	for src := range sourceSet {
		for _, scope := range scopes {
			q := httphelpers.BuildUISPOCPQuery(subject, src, scope)
			if c.spocpEngine.QueryElement(q) {
				allowed = append(allowed, AllowedResource{AuthenticSource: src, Scope: scope})
			}
		}
	}
	return allowed, nil
}
