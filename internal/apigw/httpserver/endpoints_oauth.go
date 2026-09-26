package httpserver

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/SUNET/vc/internal/apigw/apiv1"
	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/mdoc"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"
	"github.com/SUNET/vc/pkg/vcclient"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/codes"
)

// acceptsHTML reports whether the caller's Accept header explicitly asks
// for text/html. Browsers always send it; standards-conformant headless
// wallets (HAIP, OpenID4VCI test tooling) don't. Everything else is
// treated as a headless client so the OpenID4VP presentation-during-
// issuance handoff can be driven purely via HTTP 302.
func acceptsHTML(c *gin.Context) bool {
	return strings.Contains(c.GetHeader("Accept"), "text/html")
}

func (s *Service) endpointOAuthPar(ctx context.Context, c *gin.Context) (any, error) {
	ctx, span := s.tracer.Start(ctx, "httpserver:endpointAuthPar")
	defer span.End()

	request := &openid4vci.PARRequest{}
	if err := s.httpHelpers.Binding.Request(ctx, c, request); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "binding error")
		return nil, err
	}

	// gin's form binder cannot decode the JSON-array-string authorization_details (OpenID4VCI §5.1.1); PARRequest post-parses and validates it.
	if err := request.ParseAuthorizationDetails(); err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "authorization_details validation error")
		return nil, oauth2.NewOAuthErrorWithCause(oauth2.ErrCodeInvalidRequest, "invalid authorization_details", 400, err)
	}

	// Extract OAuth-Client-Attestation headers (draft-ietf-oauth-attestation-based-client-auth-04 §3.1)
	request.ClientAttestation = c.GetHeader("OAuth-Client-Attestation")
	request.ClientAttestationPoP = c.GetHeader("OAuth-Client-Attestation-PoP")

	reply, err := s.apiv1.OAuthPar(ctx, request)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "par error")
		if errors.Is(err, oauth2.ErrInvalidClient) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client",
				"error_description": oauth2.ErrInvalidClient.Error(),
			})
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

	authProvider, credSource, err := s.authProviders.Selector().Select(reply.Scope, &s.cfg.APIGW.DataSources)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "no usable auth provider for scope", "scope", reply.Scope)
		return nil, err
	}
	s.log.Debug("endpointAuthorize", "scope", reply.Scope, "auth_provider", authProvider, "data_source", credSource.DataSource)

	// Persist the auth provider into the authorization context so the
	// credential endpoint (which has no gin session) can read it back.
	authCtx, err := s.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{SessionID: reply.SessionID})
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("failed to get auth context for session %s: %w", reply.SessionID, err)
	}
	authCtx.AuthProvider = authProvider
	authCtx.DataSource = string(credSource.DataSource)
	authCtx.RemoteName = credSource.RemoteName
	if err := s.cacheService.AuthContext.Update(ctx, authCtx); err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("failed to update auth provider on session %s: %w", reply.SessionID, err)
	}

	session.Set("scope", reply.Scope)
	session.Set("auth_provider", authProvider)
	session.Set("data_source", string(credSource.DataSource))
	session.Set("remote_name", credSource.RemoteName)
	session.Set("request_uri", request.RequestURI)
	session.Set("session_id", reply.SessionID)
	session.Set("client_id", reply.ClientID)
	session.Set("wallet_client_id", reply.WalletClientID)
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

	// Extract OAuth-Client-Attestation headers (draft-ietf-oauth-attestation-based-client-auth-04 §3.1)
	request.ClientAttestation = c.GetHeader("OAuth-Client-Attestation")
	request.ClientAttestationPoP = c.GetHeader("OAuth-Client-Attestation-PoP")

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
	authProvider, ok := session.Get("auth_provider").(string)
	s.log.Debug("endpointOAuthAuthorizationConsent", "authProvider", authProvider)
	if !ok {
		err := errors.New("auth_provider not found in session")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "auth_provider not found in session")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, err
	}

	// Collect template data for the consent page instead of setting cookies.
	// This avoids non-HttpOnly cookies (S3330) since JavaScript reads auth state
	// from data attributes embedded in the rendered HTML.
	var redirectURL string

	if authProvider == model.AuthProviderPreAuth {
		c.HTML(http.StatusOK, "consent.html", gin.H{
			"AuthMethod":  authProvider,
			"RedirectURL": "",
		})
		return nil, nil
	}

	sessionID, ok := session.Get("session_id").(string)
	if !ok {
		err := errors.New("session_id not found in session")
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "session_id not found in session")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, err
	}

	if authProvider == model.AuthProviderOpenID4VP {
		request := &apiv1.OauthAuthorizationConsentRequest{
			SessionID: sessionID,
		}
		reply, err := s.apiv1.OAuthAuthorizationConsent(ctx, request)
		if err != nil {
			return nil, err
		}

		session.Set("verifier_context_id", reply.VerifierContextID)
		if err := session.Save(); err != nil {
			return nil, err
		}

		// Headless wallets (interop testbeds, HAIP-conformant clients)
		// cannot drive the JS-based consent.html countdown redirect. Skip
		// the browser UI and 302 straight to the wallet's openid4vp://
		// authorization request URL.
		if !acceptsHTML(c) {
			s.log.Debug("endpointOAuthAuthorizationConsent: headless client, 302 to wallet URL",
				"redirect_url", reply.RedirectURL)
			c.Redirect(http.StatusFound, reply.RedirectURL)
			return nil, nil
		}

		// Pass the wallet redirect URL via the template data attribute
		// (cookies are no longer used for this purpose).
		redirectURL = reply.RedirectURL
	}

	if authProvider == model.AuthProviderSAML {
		if s.authProviders.SAML() == nil {
			err := errors.New("SAML auth provider requested but SAML is not enabled")
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}

		// Skip re-initiating auth if the callback already stored documents.
		if !s.apiv1.HasVCIDocuments(ctx, sessionID) {
			scope, ok := session.Get("scope").(string)
			if !ok {
				err := errors.New("scope not found in session")
				span.SetStatus(codes.Error, err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return nil, err
			}
			if s.cfg.GetCredentialMetadata(scope) == nil {
				err := fmt.Errorf("scope %q not configured for credential issuance", scope)
				span.SetStatus(codes.Error, err.Error())
				return nil, err
			}

			// Determine the IdP entity ID: use static IdP or default from config
			idpEntityID := s.authProviders.SAML().GetStaticIDPEntityID()

			authReq, err := s.authProviders.SAML().InitiateAuthForVCI(ctx, idpEntityID, scope, sessionID)
			if err != nil {
				span.SetStatus(codes.Error, err.Error())
				return nil, err
			}

			redirectURL = authReq.RedirectURL
		} else {
			s.log.Debug("SAML auth already completed, documents cached", "session_id", sessionID)
		}
	}

	if authProvider == model.AuthProviderOIDC {
		if s.authProviders.OIDC() == nil {
			err := errors.New("OIDC auth provider requested but OIDC RP is not enabled")
			span.SetStatus(codes.Error, err.Error())
			return nil, err
		}

		// Skip re-initiating auth if the callback already stored documents.
		if !s.apiv1.HasVCIDocuments(ctx, sessionID) {
			scope, ok := session.Get("scope").(string)
			if !ok {
				err := errors.New("scope not found in session")
				span.SetStatus(codes.Error, err.Error())
				c.AbortWithStatus(http.StatusBadRequest)
				return nil, err
			}
			if s.cfg.GetCredentialMetadata(scope) == nil {
				err := fmt.Errorf("scope %q not configured for credential issuance", scope)
				span.SetStatus(codes.Error, err.Error())
				return nil, err
			}

			s.log.Debug("consent: initiating OIDC auth for VCI", "scope", scope, "session_id", sessionID)

			// Look up per-scope OIDC request params and dynamic params from auth context
			var oidcParams *model.OIDCRequestParams
			var dynamicParams map[string]string
			if scopeCfg := s.cfg.APIGW.DataSources.LookupScopePolicyConfig(scope); scopeCfg != nil {
				oidcParams = scopeCfg.OIDCRequestParams
			}
			authCtx, authCtxErr := s.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{SessionID: sessionID})
			if authCtxErr == nil && len(authCtx.DynamicParams) > 0 {
				dynamicParams = authCtx.DynamicParams
			}

			authReq, err := s.authProviders.OIDC().InitiateAuthForVCI(ctx, scope, sessionID, oidcParams, dynamicParams)
			if err != nil {
				span.SetStatus(codes.Error, err.Error())
				return nil, err
			}

			redirectURL = authReq.AuthorizationURL
		} else {
			s.log.Debug("OIDC auth already completed, documents cached", "session_id", sessionID)
		}
	}

	// After authentication, check if the credential's data source is external_api
	// and fetch the data from the remote if needed.
	if !s.apiv1.HasVCIDocuments(ctx, sessionID) {
		dataSource := model.DataSourceType(session.Get("data_source").(string))
		if dataSource == model.DataSourceExternalAPI {
			if s.dataSources.EduAPI() == nil {
				scope, _ := session.Get("scope").(string)
				err := fmt.Errorf("external API data source requested for %q but no remote is enabled", scope)
				span.SetStatus(codes.Error, err.Error())
				return nil, err
			}

			// Read person_id from auth context cache (set by SAML ACS / OIDC callback)
			authCtx, lookupErr := s.cacheService.AuthContext.Get(ctx, &cache.AuthorizationContext{SessionID: sessionID})
			if lookupErr != nil {
				span.SetStatus(codes.Error, "auth context lookup failed")
				return nil, fmt.Errorf("failed to get auth context for session %s: %w", sessionID, lookupErr)
			}
			if authCtx.Identifier == "" {
				err := errors.New("identifier not found in auth context for external API flow")
				span.SetStatus(codes.Error, err.Error())
				return nil, err
			}

			scope, _ := session.Get("scope").(string)
			if err := s.dataSources.EduAPI().FetchAndStoreForVCI(ctx, authCtx.Identifier, scope, sessionID); err != nil {
				span.SetStatus(codes.Error, err.Error())
				return nil, err
			}

			s.log.Debug("External API data fetched and stored", "session_id", sessionID, "scope", scope, "remote", authCtx.RemoteName)
		}
	}

	// html/template's default URL-attribute escaper only trusts a small
	// scheme allowlist (http/https/mailto); anything else -- including the
	// wallet's own custom-scheme redirect_uri (e.g.
	// "eu.europa.ec.euidi://authorization"), which is exactly what ends up
	// here for the openid4vp auth method -- gets silently replaced with the
	// "#ZgotmplZ" safety sentinel instead of erroring, breaking the
	// data-redirect-url attribute consent.js reads. Confirmed live
	// (lpidproto PLAN.md workstream 7): the wallet's own JS then fails with
	// "TypeError: Failed to construct 'URL': Invalid URL". redirectURL here
	// is server-derived from the requesting client's own registered
	// redirect_uri (WalletURI) or an internal auth-provider redirect, never
	// raw user input, so marking it template.URL to bypass the scheme
	// filter is safe.
	c.HTML(http.StatusOK, "consent.html", gin.H{
		"AuthMethod":  authProvider,
		"RedirectURL": template.URL(redirectURL),
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

	// Bind the wallet's response_code to the verifier code stored when the
	// matching VP request was created. Without this a callback carrying an
	// unrelated but well-formed verifier code would still mark this request
	// URI consented, because OAuthAuthorizationConsentCallback is a no-op.
	expected, _ := session.Get("verifier_context_id").(string)
	if expected == "" {
		err := errors.New("verifier_context_id not found in session")
		s.log.Error(err, "missing verifier_context_id")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, err
	}
	if request.ResponseCode == "" || request.ResponseCode != expected {
		err := errors.New("response_code does not match session verifier_context_id")
		s.log.Error(err, "response_code mismatch")
		c.AbortWithStatus(http.StatusForbidden)
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

	if !acceptsHTML(c) {
		return nil, s.headlessConsentComplete(ctx, c, session, request.ResponseCode)
	}

	c.Redirect(http.StatusFound, "/authorization/consent/#/credentials")

	return nil, nil
}

// headlessConsentComplete finishes the OpenID4VP-driven authorization for
// non-browser clients by running the same UserLookup the SPA would run on
// the "Confirm" click and then 302ing to the wallet's redirect_uri with
// the OAuth code. Mirrors endpointUserLookup so the two paths stay in sync.
func (s *Service) headlessConsentComplete(ctx context.Context, c *gin.Context, session sessions.Session, responseCode string) error {
	scope, ok := session.Get("scope").(string)
	if !ok {
		return errors.New("scope not found in session")
	}
	requestURI, ok := session.Get("request_uri").(string)
	if !ok {
		return errors.New("request_uri not found in session")
	}
	authProvider, ok := session.Get("auth_provider").(string)
	if !ok {
		return errors.New("auth_provider not found in session")
	}
	if authProvider != model.AuthProviderOpenID4VP {
		return fmt.Errorf("headless consent completion supports only openid4vp, got %q", authProvider)
	}

	vctm, err := s.apiv1.GetVCTMFromScope(ctx, &apiv1.GetVCTMFromScopeRequest{Scope: scope})
	if err != nil && !errors.Is(err, apiv1.ErrScopeIsMDoc) {
		return fmt.Errorf("get VCTM: %w", err)
	}
	var mddl *mdoc.MDDLSchema
	if errors.Is(err, apiv1.ErrScopeIsMDoc) {
		mddl, err = s.apiv1.GetMDDLFromScope(ctx, &apiv1.GetMDDLFromScopeRequest{Scope: scope})
		if err != nil {
			return fmt.Errorf("get MDDL: %w", err)
		}
	}

	reply, err := s.apiv1.UserLookup(ctx, &vcclient.UserLookupRequest{
		RequestURI:   requestURI,
		AuthProvider: authProvider,
		ResponseCode: responseCode,
		VCTM:         vctm,
		MDDL:         mddl,
	})
	if err != nil {
		return fmt.Errorf("user lookup: %w", err)
	}
	if reply == nil || reply.RedirectURL == "" {
		return errors.New("user lookup returned empty redirect URL")
	}

	session.Clear()
	if err := session.Save(); err != nil {
		s.log.Error(err, "session clear error")
	}

	s.log.Debug("headless consent complete: 302 to wallet", "redirect_url", reply.RedirectURL)
	c.Redirect(http.StatusFound, reply.RedirectURL)
	return nil
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

	var svgTemplateRequest *apiv1.SVGTemplateRequest
	vctm, err := s.apiv1.GetVCTMFromScope(ctx, getVCTMFromScopeRequest)
	switch {
	case err == nil:
		svgTemplateRequest = &apiv1.SVGTemplateRequest{VCTM: vctm}
	case errors.Is(err, apiv1.ErrScopeIsMDoc):
		// mso_mdoc scopes have no VCTM - fall back to the MDDL schema, same
		// pattern as UICreateCredentialOffer. MDDL display entries can
		// declare their own svg_templates (see MDDLSchema.Rendering);
		// SVGTemplateReply returns its own error if none are present.
		mddl, mddlErr := s.apiv1.GetMDDLFromScope(ctx, &apiv1.GetMDDLFromScopeRequest{Scope: scope})
		if mddlErr != nil {
			span.SetStatus(codes.Error, mddlErr.Error())
			s.log.Error(mddlErr, "getting MDDL schema failed")
			c.AbortWithStatus(http.StatusBadRequest)
			return nil, mddlErr
		}
		svgTemplateRequest = &apiv1.SVGTemplateRequest{MDDL: mddl}
	default:
		span.SetStatus(codes.Error, err.Error())
		s.log.Error(err, "getting VCTM failed")
		c.AbortWithStatus(http.StatusBadRequest)
		return nil, err
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
