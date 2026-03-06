package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/SUNET/vc/internal/verifier/apiv1"
	"github.com/SUNET/vc/internal/verifier/cache"
	"github.com/SUNET/vc/internal/verifier/middleware"
	"github.com/SUNET/vc/internal/verifier/notify"
	"github.com/SUNET/vc/internal/verifier/staticembed"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/openidfederation"
	"github.com/SUNET/vc/pkg/pki"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-contrib/cors"
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
	registerAuth     gin.HandlerFunc

	// openidFederationService is nil when OpenID Federation is not enabled.
	// Built once here rather than per-request, since constructing a signer
	// forces key material to be (re)loaded every time (expensive, especially
	// with PKCS#11/HSM).
	openidFederationService *openidfederation.Service
}

// New creates a new httpserver service
func New(ctx context.Context, cfg *model.Cfg, apiv1 *apiv1.Client, notify *notify.Service, tracer *trace.Tracer, cacheService *cache.Service, log *logger.Log) (*Service, error) {
	// Initialize rate limiters with default configuration
	rateLimitConfig := middleware.DefaultRateLimitConfig()

	s := &Service{
		cfg:              cfg,
		log:              log.New("httpserver"),
		apiv1:            apiv1,
		gin:              gin.New(),
		notify:           notify,
		tracer:           tracer,
		server:           &http.Server{}, //#nosec G112 -- ReadHeaderTimeout set by httphelpers.Server.Default
		sessionsName:     "verifier_user_session",
		tokenLimiter:     middleware.NewRateLimiter(rateLimitConfig.TokenRequestsPerMinute, rateLimitConfig.TokenBurst),
		authorizeLimiter: middleware.NewRateLimiter(rateLimitConfig.AuthorizeRequestsPerMinute, rateLimitConfig.AuthorizeBurst),
		registerLimiter:  middleware.NewRateLimiter(rateLimitConfig.RegisterRequestsPerMinute, rateLimitConfig.RegisterBurst),
		registerAuth:     func(c *gin.Context) { c.Next() },
		sessionsOptions: sessions.Options{
			Path:     "/",
			Domain:   "",
			MaxAge:   900,
			Secure:   false,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		},
	}

	if s.cfg.Verifier.APIServer.TLS.Enable {
		s.sessionsOptions.Secure = true
	}

	// Session keys resolved by the cache service (HA-shared or ephemeral).
	s.sessionsAuthKey = cacheService.SessionAuthKey
	s.sessionsEncKey = cacheService.SessionEncKey

	var err error
	s.httpHelpers, err = httphelpers.New(ctx, s.tracer, s.cfg, s.log)
	if err != nil {
		return nil, err
	}

	// Configure CORS at the engine level (before route registration) so that
	// OPTIONS preflight requests are handled correctly. Placing CORS on a
	// router group causes preflight requests to hit Gin's NoRoute handler
	// (404) because no explicit OPTIONS route is registered.
	if s.cfg.Verifier.APIServer.CORS != nil && len(s.cfg.Verifier.APIServer.CORS.AllowedOrigins) > 0 {
		corsConfig := cors.Config{
			AllowOrigins:     s.cfg.Verifier.APIServer.CORS.AllowedOrigins,
			AllowMethods:     []string{"GET", "POST", "OPTIONS"},
			AllowHeaders:     []string{"Content-Type", "Authorization", "DPoP"},
			AllowCredentials: true,
			MaxAge:           12 * time.Hour,
		}
		s.gin.Use(cors.New(corsConfig))
	}

	s.registerAuth, err = middleware.NewRegistrationAuthMiddleware(s.cfg, s.log.New("registration_auth"))
	if err != nil {
		return nil, err
	}

	rgRoot, err := s.httpHelpers.Server.Default(ctx, s.server, s.gin, s.cfg.Verifier.APIServer)
	if err != nil {
		return nil, err
	}

	s.gin.StaticFS("/static", http.FS(staticembed.FS))

	tmpl := template.New("").Funcs(template.FuncMap{
		"toJSON": func(v any) string {
			cleaned := cleanUnresolvedMarkersForDisplay(v)
			b, _ := json.MarshalIndent(cleaned, "", "  ")
			return string(b)
		},
		"json": func(v any) (any, error) {
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			return template.JS(string(jsonBytes)), nil //#nosec G203 -- json.Marshal output is safe
		},
		"claimsTree": func(credential map[string]any) template.HTML {
			return template.HTML(renderClaimsTree(credential)) //#nosec G203 -- internally generated HTML
		},
	})
	s.gin.SetHTMLTemplate(template.Must(tmpl.ParseFS(staticembed.FS, "*.html")))

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "/", http.StatusOK, s.endpointIndex)

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "health", http.StatusOK, s.endpointHealth)

	// oauth2 (original verifier metadata)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, ".well-known/oauth-authorization-server", http.StatusOK, s.endpointOAuthMetadata)

	// OIDC Discovery
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, ".well-known/openid-configuration", http.StatusOK, s.endpointOIDCDiscovery)

	// OpenID Federation entity configuration
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, ".well-known/openid-federation", http.StatusOK, s.endpointOpenIDFederationEntityConfig)

	// JWKS
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "jwks", http.StatusOK, s.endpointJWKS)

	// DID Document (did:web)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, ".well-known/did.json", http.StatusOK, s.endpointDIDDocument)

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
	rgRoot.POST("register", s.registerLimiter.Middleware(), s.registerAuth, func(c *gin.Context) {
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
	// TODO(masv): no polling, use WebSocket or Server-Sent Events instead
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

	if fedCfg := cfg.Verifier.OpenIDFederation; fedCfg != nil && fedCfg.Enabled {
		fedSigner := pki.NewSignerConfig(cfg.Verifier.KeyConfig)
		s.openidFederationService = openidfederation.New(fedCfg, fedSigner, cfg.Verifier.PublicURL)
	}

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

// jwtMetadataClaims are JWT/SD-JWT infrastructure claims excluded from display.
var jwtMetadataClaims = map[string]bool{
	"iss": true, "sub": true, "iat": true, "exp": true, "nbf": true,
	"jti": true, "cnf": true, "vct": true, "vct#integrity": true,
	"status": true, "_sd": true, "_sd_alg": true,
}

// renderClaimsTree renders a credential claims map as HTML table rows with
// tree-style indentation for nested objects.
func renderClaimsTree(claims map[string]any) string {
	var sb strings.Builder
	keys := sortedKeys(claims)
	for _, key := range keys {
		if jwtMetadataClaims[key] {
			continue
		}
		renderNode(&sb, key, claims[key], 0)
	}
	return sb.String()
}

func renderNode(sb *strings.Builder, name string, value any, depth int) {
	indent := depth * 24 // pixels for indentation

	switch v := value.(type) {
	case map[string]any:
		// Group header row
		fmt.Fprintf(sb,
			`<tr><td style="padding-left:%dpx;font-weight:600;">%s</td><td></td></tr>`,
			indent, template.HTMLEscapeString(name),
		)
		// Recurse into children
		keys := sortedKeys(v)
		for _, childKey := range keys {
			if jwtMetadataClaims[childKey] {
				continue
			}
			renderNode(sb, childKey, v[childKey], depth+1)
		}
	case []any:
		// Render array elements, handling unresolved SD-JWT markers {"...": hash}
		parts := make([]string, 0, len(v))
		for _, elem := range v {
			if m, ok := elem.(map[string]any); ok {
				if _, isMarker := m["..."]; isMarker && len(m) == 1 {
					// Unresolved array element disclosure — wallet didn't include element disclosure.
					// Skip the marker silently; we'll show whatever was actually disclosed.
					continue
				}
			}
			parts = append(parts, fmt.Sprintf("%v", elem))
		}
		if len(parts) > 0 {
			fmt.Fprintf(sb,
				`<tr><td style="padding-left:%dpx;">%s</td><td><code>%s</code></td></tr>`,
				indent, template.HTMLEscapeString(name), template.HTMLEscapeString(strings.Join(parts, ", ")),
			)
		} else {
			// Array was disclosed but contained only unresolved element markers.
			// Show the claim name to confirm it was disclosed.
			fmt.Fprintf(sb,
				`<tr><td style="padding-left:%dpx;">%s</td><td><code>[]</code> <em>(element details not disclosed by wallet)</em></td></tr>`,
				indent, template.HTMLEscapeString(name),
			)
		}
	default:
		valStr := fmt.Sprintf("%v", value)
		// Render picture as image
		if name == "picture" {
			fmt.Fprintf(sb,
				`<tr><td style="padding-left:%dpx;">%s</td><td><img src="data:image/png;base64,%s" alt="Picture" style="max-width:120px;max-height:160px;border-radius:4px;"></td></tr>`,
				indent, template.HTMLEscapeString(name), template.HTMLEscapeString(valStr),
			)
		} else {
			fmt.Fprintf(sb,
				`<tr><td style="padding-left:%dpx;">%s</td><td><code>%s</code></td></tr>`,
				indent, template.HTMLEscapeString(name), template.HTMLEscapeString(valStr),
			)
		}
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// cleanUnresolvedMarkersForDisplay deep-copies the value, removing SD-JWT array element
// markers ({"...": hash}) so the JSON output is clean for display purposes.
func cleanUnresolvedMarkersForDisplay(v any) any {
	switch val := v.(type) {
	case map[string]any:
		result := make(map[string]any, len(val))
		for k, child := range val {
			result[k] = cleanUnresolvedMarkersForDisplay(child)
		}
		return result
	case []any:
		result := make([]any, 0, len(val))
		for _, elem := range val {
			if m, ok := elem.(map[string]any); ok && len(m) == 1 {
				if _, isMarker := m["..."]; isMarker {
					continue
				}
			}
			result = append(result, cleanUnresolvedMarkersForDisplay(elem))
		}
		return result
	default:
		return v
	}
}
