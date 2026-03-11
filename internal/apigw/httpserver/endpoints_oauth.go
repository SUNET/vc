package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"vc/internal/apigw/apiv1"
	"vc/pkg/model"
	"vc/pkg/oauth2"
	"vc/pkg/openid4vci"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

func (s *Service) endpointOAuthPar(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointAuthPar")
	defer span.End()

	request := &openid4vci.PARRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "binding error")
		return nil, err
	}

	reply, err := s.apiv1.OAuthPar(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "par error")
		if errors.Is(err, oauth2.ErrInvalidClient) {
			c.AbortWithStatus(http.StatusMethodNotAllowed)
			return nil, nil
		}
		return nil, err
	}
	s.log.Debug("par", "reply", reply)

	return reply, nil
}

func (s *Service) endpointOAuthAuthorize(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointAuthorize")
	defer span.End()
	session := sessions.Default(c)

	s.log.Debug("Authorize endpoint", "c.Request.URL", c.Request.URL.String(), "headers", c.Request.Header)

	request := &openid4vci.AuthorizeRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	reply, err := s.apiv1.OAuthAuthorize(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	s.log.Debug("endpointAuthorize", "scope", reply.Scope, "auth_method", s.cfg.GetCredentialConstructorAuthMethod(reply.Scope))

	session.Set("scope", reply.Scope)
	session.Set("auth_method", s.cfg.GetCredentialConstructorAuthMethod(reply.Scope))
	session.Set("request_uri", request.RequestURI)
	session.Set("session_id", reply.SessionID)
	session.Set("client_id", reply.ClientID)
	if err := session.Save(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "session save error")
		return nil, err
	}

	s.log.Debug("Authorize endpoint", "requestURI", request.RequestURI, "reply", reply)

	c.SetAccepted("application/json")
	c.Redirect(http.StatusFound, reply.RedirectURL)

	return nil, nil
}

// after authorize and before token endpoint is authorization/consent be placed

func (s *Service) endpointOAuthToken(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointToken")
	defer span.End()

	s.log.Debug("endpointOAuthToken")

	session := sessions.Default(c)

	request := &openid4vci.TokenRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	reply, err := s.apiv1.OAuthToken(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	s.log.Debug("Token endpoint", "redirectURI", request.RedirectURI, "reply", reply)

	session.Clear()

	c.SetAccepted("application/json")
	c.Redirect(http.StatusPermanentRedirect, request.RedirectURI)

	return reply, nil
}

func (s *Service) endpointOAuthMetadata(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointMetadata")
	defer span.End()

	reply, err := s.apiv1.OAuthMetadata(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.SetAccepted("application/json")
	return reply, nil
}

func (s *Service) endpointJWKS(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointJWKS")
	defer span.End()

	reply, err := s.apiv1.JWKS(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.SetAccepted("application/json")
	return reply, nil
}

func (s *Service) endpointSDJWTVCIssuerMetadata(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointSDJWTVCIssuerMetadata")
	defer span.End()

	reply, err := s.apiv1.SDJWTVCIssuerMetadata(ctx)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	c.SetAccepted("application/json")
	return reply, nil
}

func (s *Service) endpointOAuthAuthorizationConsent(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointOAuthAuthorizationConsent", "c.Request.URL", c.Request.URL.String(), "headers", c.Request.Header)
	_, span := s.tracer.Start(ctx, "httpserver:endpointAuthorizationConsent")
	defer span.End()

	session := sessions.Default(c)
	authMethod, ok := session.Get("auth_method").(string)
	s.log.Debug("endpointOAuthAuthorizationConsent", "authMethod", authMethod)
	if !ok {
		err := errors.New("auth_method not found in session")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "auth_method not found in session")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, err
	}

	// Collect template data for the consent page instead of setting cookies.
	// This avoids non-HttpOnly cookies (S3330) since JavaScript reads auth state
	// from data attributes embedded in the rendered HTML.
	var redirectURL string

	sessionID, ok := session.Get("session_id").(string)
	if !ok {
		err := errors.New("session_id not found in session")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "session_id not found in session")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, err
	}

	if authMethod == model.AuthMethodPID {
		request := &apiv1.OauthAuthorizationConsentRequest{
			SessionID: sessionID,
		}
		reply, err := s.apiv1.OAuthAuthorizationConsent(ctx, request)
		if err != nil {
			return nil, err
		}

		redirectURL = reply.RedirectURL
		session.Set("verifier_context_id", reply.VerifierContextID)
		if err := session.Save(); err != nil {
			return nil, err
		}

		// in order to avoid the verifier context ID being sent to the client
		reply.VerifierContextID = ""
	}

	if authMethod == model.AuthMethodSAML {
		if s.samlSPService == nil {
			err := errors.New("SAML auth method requested but SAML is not enabled")
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}

		// Skip re-initiating auth if the callback already stored documents.
		if !s.apiv1.HasVCIDocuments(ctx, sessionID) {
			scope, _ := session.Get("scope").(string)
			if s.cfg.GetCredentialConstructor(scope) == nil {
				err := fmt.Errorf("scope %q not configured for credential issuance", scope)
				span.SetStatus(codes.Error, err.Error())
				return nil, err
			}

			// Determine the IdP entity ID: use static IdP or default from config
			idpEntityID := s.samlSPService.GetStaticIDPEntityID()

			authReq, err := s.samlSPService.InitiateAuthForVCI(ctx, idpEntityID, scope, sessionID)
			if err != nil {
				span.SetStatus(codes.Error, err.Error())
				return nil, err
			}

			redirectURL = authReq.RedirectURL
		} else {
			s.log.Debug("SAML auth already completed, documents cached", "session_id", sessionID)
		}
	}

	if authMethod == model.AuthMethodOIDC {
		if s.oidcrpService == nil {
			err := errors.New("OIDC auth method requested but OIDC RP is not enabled")
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}

		// Skip re-initiating auth if the callback already stored documents.
		if !s.apiv1.HasVCIDocuments(ctx, sessionID) {
			scope, _ := session.Get("scope").(string)
			if s.cfg.GetCredentialConstructor(scope) == nil {
				err := fmt.Errorf("scope %q not configured for credential issuance", scope)
				span.SetStatus(codes.Error, err.Error())
				return nil, err
			}

			authReq, err := s.oidcrpService.InitiateAuthForVCI(ctx, scope, sessionID)
			if err != nil {
				span.SetStatus(codes.Error, err.Error())
				return nil, err
			}

			redirectURL = authReq.AuthorizationURL
		} else {
			s.log.Debug("OIDC auth already completed, documents cached", "session_id", sessionID)
		}
	}

	c.HTML(http.StatusOK, "consent.html", gin.H{
		"AuthMethod":  authMethod,
		"RedirectURL": redirectURL,
	})
	return nil, nil
}
func (s *Service) endpointOAuthAuthorizationConsentCallback(ctx context.Context, c *gin.Context) (any, error) {
	session := sessions.Default(c)

	request := &apiv1.OauthAuthorizationConsentCallbackRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		s.log.Error(err, "binding error")
		return nil, err
	}

	session.Set("response_code", request.ResponseCode)
	if err := session.Save(); err != nil {
		s.log.Error(err, "session save error")
		return nil, err
	}

	_, err := s.apiv1.OAuthAuthorizationConsentCallback(ctx, request)
	if err != nil {
		return nil, err
	}

	c.Redirect(http.StatusFound, "/authorization/consent/#/credentials")

	return nil, nil
}

func (s *Service) endpointOAuthAuthorizationConsentSvgTemplate(ctx context.Context, c *gin.Context) (any, error) {
	s.log.Debug("endpointOAuthAuthorizationConsentSvgTemplate", "c.Request.URL", c.Request.URL.String(), "headers", c.Request.Header)
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointOAuthAuthorizationConsentSvgTemplate")
	defer span.End()

	session := sessions.Default(c)

	scope, ok := session.Get("scope").(string)
	if !ok {
		err := errors.New("scope not found in session")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "scope not found in session")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, err
	}

	getVCTMFromScopeRequest := &apiv1.GetVCTMFromScopeRequest{
		Scope: scope,
	}

	vctm, err := s.apiv1.GetVCTMFromScope(ctx, getVCTMFromScopeRequest)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "getting VCTM failed")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, err
	}

	svgTemplateRequest := &apiv1.SVGTemplateRequest{
		VCTM: vctm,
	}

	reply, err := s.apiv1.SVGTemplateReply(ctx, svgTemplateRequest)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "getting SVG template failed")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, err
	}

	c.SetAccepted("application/json")

	return reply, nil
}
