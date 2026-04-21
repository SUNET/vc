package httpserver

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/internal/registry/apiv1"
	"github.com/SUNET/vc/internal/registry/cache"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
)

// Service is the service object for httpserver
type Service struct {
	cfg                    *model.Cfg
	log                    *logger.Log
	server                 *http.Server
	apiv1                  Apiv1
	tracer                 *trace.Tracer
	gin                    *gin.Engine
	httpHelpers            *httphelpers.Client
	statusListsRateLimiter *httphelpers.RateLimiter
	sessionStore           *sessions.CookieStore
}

// New creates a new httpserver service
func New(ctx context.Context, cfg *model.Cfg, api *apiv1.Client, tracer *trace.Tracer, cacheService *cache.Service, log *logger.Log) (*Service, error) {
	// Initialize rate limiter for statuslists endpoints
	rateLimitRequestsPerMinute := cfg.Registry.TokenStatusLists.RateLimitRequestsPerMinute
	if rateLimitRequestsPerMinute <= 0 {
		rateLimitRequestsPerMinute = 60 // Default: 60 requests per minute
	}

	s := &Service{
		cfg:    cfg,
		log:    log.New("httpserver"),
		apiv1:  api,
		gin:    gin.New(),
		tracer: tracer,
		server: &http.Server{}, // Timeouts and other defaults are set by httphelpers.Server.Default
	}

	var err error
	s.httpHelpers, err = httphelpers.New(ctx, s.tracer, s.cfg, s.log)
	if err != nil {
		return nil, err
	}

	s.statusListsRateLimiter = s.httpHelpers.Middleware.NewRateLimiter(rateLimitRequestsPerMinute)

	rgRoot, err := s.httpHelpers.Server.Default(ctx, s.server, s.gin, s.cfg.Registry.APIServer)
	if err != nil {
		return nil, err
	}

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "health", http.StatusOK, s.endpointHealth)

	// Token Status List endpoints per draft-ietf-oauth-status-list
	// These endpoints are rate-limited to prevent abuse
	rgStatuslists := rgRoot.Group("statuslists")
	rgStatuslists.Use(s.statusListsRateLimiter.Middleware())
	// Section 9.3: Status List Aggregation at /statuslists returns list of all Status List Token URIs
	s.httpHelpers.Server.RegEndpoint(ctx, rgStatuslists, http.MethodGet, "", http.StatusOK, s.endpointTokenStatusListAggregation)
	// Section 8.1: Individual Status List Token at /statuslists/:id
	s.httpHelpers.Server.RegEndpoint(ctx, rgStatuslists, http.MethodGet, ":id", http.StatusOK, s.endpointStatusLists)

	// Admin GUI endpoints for managing Token Status Lists
	if model.BoolVal(s.cfg.Registry.AdminGUI.Enable, true) {
		s.sessionStore = sessions.NewCookieStore([]byte(cacheService.SessionAuthKey), []byte(cacheService.SessionEncKey))
		s.sessionStore.Options = &sessions.Options{
			Path:     "/admin",
			MaxAge:   3600,
			HttpOnly: true,
			Secure:   s.cfg.Registry.APIServer.TLS.Enable,
			SameSite: http.SameSiteStrictMode,
		}

		// Redirect root to admin login
		s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "", http.StatusFound, s.endpointRootRedirect)

		rgAdmin := rgRoot.Group("/admin")
		// Public routes (no auth required)
		s.httpHelpers.Server.RegEndpoint(ctx, rgAdmin, http.MethodGet, "/login", http.StatusOK, s.endpointAdminLoginPage)
		s.httpHelpers.Server.RegEndpoint(ctx, rgAdmin, http.MethodPost, "/login", http.StatusOK, s.endpointAdminLogin)
		// Protected routes (auth required)
		rgAdminProtected := rgAdmin.Group("")
		rgAdminProtected.Use(s.adminAuthMiddleware())
		s.httpHelpers.Server.RegEndpoint(ctx, rgAdminProtected, http.MethodGet, "", http.StatusOK, s.endpointAdminDashboard)
		s.httpHelpers.Server.RegEndpoint(ctx, rgAdminProtected, http.MethodGet, "/dashboard", http.StatusOK, s.endpointAdminDashboard)
		s.httpHelpers.Server.RegEndpoint(ctx, rgAdminProtected, http.MethodGet, "/search", http.StatusOK, s.endpointAdminSearchPage)
		s.httpHelpers.Server.RegEndpoint(ctx, rgAdminProtected, http.MethodPost, "/search", http.StatusOK, s.endpointAdminSearch)
		s.httpHelpers.Server.RegEndpoint(ctx, rgAdminProtected, http.MethodPost, "/status", http.StatusOK, s.endpointAdminUpdateStatus)
		s.httpHelpers.Server.RegEndpoint(ctx, rgAdminProtected, http.MethodPost, "/logout", http.StatusOK, s.endpointAdminLogout)

		s.log.Info("Admin GUI enabled", "path", "/admin")
	}

	// Run http server
	go func() {
		err := s.httpHelpers.Server.ListenAndServe(ctx, s.server, s.cfg.Registry.APIServer)
		if err != nil {
			s.log.Trace("listen_error", "error", err)
		}
	}()

	s.log.Info("Started")

	return s, nil
}

// Close closing httpserver
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Stopped")
	return nil
}
