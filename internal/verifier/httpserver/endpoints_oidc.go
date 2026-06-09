package httpserver

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/SUNET/vc/internal/verifier/apiv1"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

// endpointOIDCDiscovery handles OpenID Provider Configuration requests
func (s *Service) endpointOIDCDiscovery(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointOIDCDiscovery")
	defer span.End()

	metadata, err := s.apiv1.GetDiscoveryMetadata(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to get discovery metadata")
		return nil, err
	}

	c.Header("Content-Type", "application/json")
	return metadata, nil
}

// endpointJWKS handles JWKS requests
func (s *Service) endpointJWKS(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointJWKS")
	defer span.End()

	jwks, err := s.apiv1.GetJWKS(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to get JWKS")
		return nil, err
	}

	c.Header("Content-Type", "application/json")
	return jwks, nil
}

// endpointAuthorize handles OIDC authorization requests
func (s *Service) endpointAuthorize(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointAuthorize")
	defer span.End()

	s.log.Debug("endpointAuthorize called")

	// Parse request
	request := &apiv1.AuthorizeRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to bind authorization request")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, nil
	}

	// Process authorization request
	response, err := s.apiv1.Authorize(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Authorization failed")

		// Return error to redirect_uri if possible
		if request.RedirectURI != "" && request.State != "" {
			// Use the actual OAuth error code if available
			errorCode := "server_error"
			var oauthErr *apiv1.OAuthError
			if errors.As(err, &oauthErr) {
				errorCode = oauthErr.ErrorCode
			}
			errorURL := request.RedirectURI + "?error=" + errorCode + "&state=" + request.State
			c.Redirect(http.StatusFound, errorURL)
			return nil, nil
		}

		c.AbortWithStatus(http.StatusInternalServerError)
		return nil, nil
	}

	// Render authorization page with QR code and DC API support
	templateData := gin.H{
		"SessionID":        response.SessionID,
		"QRCodeData":       response.QRCodeData,
		"DeepLinkURL":      response.DeepLinkURL,
		"PollURL":          response.PollURL,
		"WalletLinks":      response.WalletLinks,
		"PreferredFormats": response.PreferredFormats,
		"UseJAR":           response.UseJAR,
		"ResponseMode":     response.ResponseMode,
		"Title":            response.Title,
		"Subtitle":         response.Subtitle,
		"PrimaryColor":     response.PrimaryColor,
		"SecondaryColor":   response.SecondaryColor,
		"Theme":            response.Theme,
		"CustomCSS":        response.CustomCSS,
		"CSSFile":          response.CSSFile,
		"LogoURL":          response.LogoURL,
		"Config": gin.H{
			"DigitalCredentials": gin.H{
				"Enable":          s.cfg.Verifier.DigitalCredentials.Enable,
				"AllowQRFallback": model.BoolVal(s.cfg.Verifier.DigitalCredentials.AllowQRFallback, true),
				"DeepLinkScheme":  s.cfg.Verifier.DigitalCredentials.DeepLinkScheme,
			},
			"CredentialDisplay": gin.H{
				"Enable":              s.cfg.Verifier.CredentialDisplay.Enable,
				"RequireConfirmation": s.cfg.Verifier.CredentialDisplay.RequireConfirmation,
			},
		},
	}

	c.HTML(http.StatusOK, "authorize_enhanced.html", templateData)

	return nil, nil
}

// endpointToken handles OIDC token requests
func (s *Service) endpointToken(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointToken")
	defer span.End()

	s.log.Debug("endpointToken called")

	// Parse request
	request := &apiv1.TokenRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Failed to bind token request")
		return s.tokenError("invalid_request", "Invalid request parameters"), nil
	}

	// Process token request
	response, err := s.apiv1.Token(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "Token request failed")

		// Map errors to OAuth2 error codes
		errorCode := "server_error"
		switch err {
		case apiv1.ErrInvalidClient:
			errorCode = "invalid_client"
			c.Status(http.StatusUnauthorized)
		case apiv1.ErrInvalidGrant:
			errorCode = "invalid_grant"
		case apiv1.ErrUnsupportedGrantType:
			errorCode = "unsupported_grant_type"
		case apiv1.ErrInvalidRequest:
			errorCode = "invalid_request"
		}

		return s.tokenError(errorCode, err.Error()), nil
	}

	c.Header("Content-Type", "application/json")
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")

	return response, nil
}

// tokenError returns an OAuth2 error response
func (s *Service) tokenError(code string, description string) map[string]string {
	return map[string]string{
		"error":             code,
		"error_description": description,
	}
}

// endpointUserInfo handles OIDC UserInfo requests
func (s *Service) endpointUserInfo(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointUserInfo")
	defer span.End()

	s.log.Debug("endpointUserInfo called")

	// Parse request (binds Authorization header)
	request := &apiv1.UserInfoRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Info("UserInfo binding failed", "error", err)
		c.Header("WWW-Authenticate", "Bearer")
		return nil, oauth2.NewOAuthError("invalid_request", "missing or invalid Authorization header", http.StatusUnauthorized)
	}

	// Extract bearer token from Authorization header (RFC 7235: scheme is case-insensitive)
	parts := strings.SplitN(request.Authorization, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		span.SetStatus(codes.Error, "Invalid Authorization header")
		c.Header("WWW-Authenticate", "Bearer")
		return nil, oauth2.NewOAuthError("invalid_request", "invalid Authorization header format", http.StatusUnauthorized)
	}
	request.AccessToken = parts[1]

	response, err := s.apiv1.GetUserInfo(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "UserInfo request failed")

		if errors.Is(err, apiv1.ErrInvalidGrant) {
			c.Header("WWW-Authenticate", "Bearer error=\"invalid_token\"")
			return nil, oauth2.NewOAuthError("invalid_token", "access token is invalid or expired", http.StatusUnauthorized)
		}

		return nil, err
	}

	c.Header("Content-Type", "application/json")
	return response, nil
}
