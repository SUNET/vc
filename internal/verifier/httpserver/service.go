package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"
	"vc/internal/verifier/apiv1"
	"vc/internal/verifier/middleware"
	"vc/internal/verifier/notify"
	"vc/pkg/crypto"
	"vc/pkg/httphelpers"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/gin-contrib/sessions"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/gin-gonic/gin"
)

// Service is the service object for httpserver
type Service struct {
	cfg              *model.Cfg
	log              *logger.Log
	server           *http.Server
	apiv1            Apiv1
	gin              *gin.Engine
	tracer           *trace.Tracer
	httpHelpers      *httphelpers.Client
	notify           *notify.Service
	sessionsOptions  sessions.Options
	sessionsEncKey   string
	sessionsAuthKey  string
	sessionsName     string
	tokenLimiter     *middleware.RateLimiter
	authorizeLimiter *middleware.RateLimiter
	registerLimiter  *middleware.RateLimiter
}

// New creates a new httpserver service
func New(ctx context.Context, cfg *model.Cfg, apiv1 *apiv1.Client, notify *notify.Service, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	// Initialize rate limiters with default configuration
	rateLimitConfig := middleware.DefaultRateLimitConfig()

	s := &Service{
		cfg:    cfg,
		log:    log.New("httpserver"),
		apiv1:  apiv1,
		gin:    gin.New(),
		notify: notify,
		tracer: tracer,
		server: &http.Server{
			ReadHeaderTimeout: 3 * time.Second,
		},
		sessionsName:     "verifier_user_session",
		tokenLimiter:     middleware.NewRateLimiter(rateLimitConfig.TokenRequestsPerMinute, rateLimitConfig.TokenBurst),
		authorizeLimiter: middleware.NewRateLimiter(rateLimitConfig.AuthorizeRequestsPerMinute, rateLimitConfig.AuthorizeBurst),
		registerLimiter:  middleware.NewRateLimiter(rateLimitConfig.RegisterRequestsPerMinute, rateLimitConfig.RegisterBurst),
		sessionsOptions: sessions.Options{
			Path:     "/",
			Domain:   "",
			MaxAge:   900,
			Secure:   false,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		},
	}

	if s.cfg.Verifier.APIServer.TLS.Enabled {
		s.sessionsOptions.Secure = true
		//s.sessionsOptions.SameSite = http.SameSiteStrictMode
	}

	// Generate session keys
	var err error
	s.sessionsAuthKey, err = crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session auth key: %w", err)
	}

	s.sessionsEncKey, err = crypto.GenerateSecureToken(0, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate session encryption key: %w", err)
	}

	s.httpHelpers, err = httphelpers.New(ctx, s.tracer, s.cfg, s.log)
	if err != nil {
		return nil, err
	}

	rgRoot, err := s.httpHelpers.Server.Default(ctx, s.server, s.gin, s.cfg.Verifier.APIServer.Addr)
	if err != nil {
		return nil, err
	}

	// templating functions
	s.gin.SetFuncMap(template.FuncMap{
		"toJSON": func(v any) string {
			b, _ := json.MarshalIndent(v, "", "  ")
			return string(b)
		},
		"json": func(v any) (any, error) {
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			// Return as template.JS to prevent escaping in JavaScript context
			return template.JS(string(jsonBytes)), nil
		},
	})

	s.gin.Static("/static", "./static")
	s.gin.LoadHTMLGlob("./static/*.html")

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "/", http.StatusOK, s.endpointIndex)

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "health", http.StatusOK, s.endpointHealth)

	// oauth2 (original verifier metadata)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, ".well-known/oauth-authorization-server", http.StatusOK, s.endpointOAuthMetadata)

	// OIDC Discovery
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, ".well-known/openid-configuration", http.StatusOK, s.endpointOIDCDiscovery)

	// JWKS
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "jwks", http.StatusOK, s.endpointJWKS)

	// UserInfo endpoint
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "userinfo", http.StatusOK, s.endpointUserInfo)

	rgOAuthSession := rgRoot.Group("")
	rgOAuthSession.Use(s.httpHelpers.Middleware.UserSession(s.sessionsName, s.sessionsAuthKey, s.sessionsEncKey, s.sessionsOptions))
	s.httpHelpers.Server.RegEndpoint(ctx, rgOAuthSession, http.MethodPost, "op/par", http.StatusCreated, s.endpointOAuthPar)

	// Rate-limited OIDC endpoints
	// Authorize endpoint with rate limiting
	rgRoot.GET("authorize", s.authorizeLimiter.Middleware(), func(c *gin.Context) {
		response, err := s.endpointAuthorize(ctx, c)
		if err != nil {
			s.log.Error(err, "Authorize endpoint error")
		}
		if response != nil {
			c.JSON(http.StatusOK, response)
		}
	})

	// Token endpoint with rate limiting
	rgRoot.POST("token", s.tokenLimiter.Middleware(), func(c *gin.Context) {
		response, err := s.endpointToken(ctx, c)
		if err != nil {
			s.log.Error(err, "Token endpoint error")
		}
		if response != nil {
			c.JSON(http.StatusOK, response)
		}
	})

	// Dynamic Client Registration (RFC 7591/7592) with rate limiting
	rgRoot.POST("register", s.registerLimiter.Middleware(), func(c *gin.Context) {
		response, err := s.endpointRegisterClient(ctx, c)
		if err != nil {
			s.handleOAuthError(c, err)
			return
		}
		c.JSON(http.StatusCreated, response)
	})
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "register/:client_id", http.StatusOK, s.endpointGetClientConfiguration)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPut, "register/:client_id", http.StatusOK, s.endpointUpdateClient)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodDelete, "register/:client_id", http.StatusNoContent, s.endpointDeleteClient)

	// Original verifier verification endpoints (with user session)
	sgVerification := rgOAuthSession.Group("/verification")
	s.httpHelpers.Server.RegEndpoint(ctx, sgVerification, http.MethodGet, "request-object", http.StatusOK, s.endpointVerificationRequestObject)
	s.httpHelpers.Server.RegEndpoint(ctx, sgVerification, http.MethodPost, "direct_post", http.StatusOK, s.endpointVerificationDirectPost)
	s.httpHelpers.Server.RegEndpoint(ctx, sgVerification, http.MethodGet, "callback", http.StatusOK, s.endpointVerificationCallback)

	// OIDC-flow OpenID4VP endpoints
	rgOIDCVerification := rgRoot.Group("/verification")
	s.httpHelpers.Server.RegEndpoint(ctx, rgOIDCVerification, http.MethodGet, "request-object/:session_id", http.StatusOK, s.endpointOIDCRequestObject)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOIDCVerification, http.MethodPost, "oidc-direct_post", http.StatusOK, s.endpointOIDCDirectPost)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOIDCVerification, http.MethodGet, "oidc-callback", http.StatusOK, s.endpointOIDCCallback)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOIDCVerification, http.MethodPost, "session-preference", http.StatusOK, s.endpointSessionPreference)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOIDCVerification, http.MethodGet, "display/:session_id", http.StatusOK, s.endpointCredentialDisplay)
	s.httpHelpers.Server.RegEndpoint(ctx, rgOIDCVerification, http.MethodPost, "confirm/:session_id", http.StatusOK, s.endpointConfirmCredentialDisplay)

	// UI Endpoints
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "qr/:session_id", http.StatusOK, s.endpointQRCode)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "poll/:session_id", http.StatusOK, s.endpointPollSession)

	rgUI := rgOAuthSession.Group("/ui")
	s.httpHelpers.Server.RegEndpoint(ctx, rgUI, http.MethodPost, "/interaction", http.StatusOK, s.endpointUIInteraction)
	s.httpHelpers.Server.RegEndpoint(ctx, rgUI, http.MethodGet, "/notify", http.StatusOK, s.endpointUINotify)
	s.httpHelpers.Server.RegEndpoint(ctx, rgUI, http.MethodGet, "/metadata", http.StatusOK, s.endpointUIMetadata)

	rgDocs := rgRoot.Group("/swagger")
	rgDocs.GET("/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Run http server
	go func() {
		err := s.httpHelpers.Server.ListenAndServe(ctx, s.server, s.cfg.Verifier.APIServer)
		if err != nil {
			s.log.Trace("listen_error", "error", err)
		}
	}()

	s.log.Info("Started")

	return s, nil
}

// Close closing httpserver
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Stopping")
	return nil
}

// handleOAuthError handles OAuth error responses
func (s *Service) handleOAuthError(c *gin.Context, err error) {
	if oauthErr, ok := err.(*apiv1.OAuthError); ok {
		c.JSON(oauthErr.HTTPStatus, gin.H{
			"error":             oauthErr.ErrorCode,
			"error_description": oauthErr.ErrorDescription,
		})
		return
	}

	// Generic error
	c.JSON(http.StatusInternalServerError, gin.H{
		"error":             "server_error",
		"error_description": err.Error(),
	})
}
