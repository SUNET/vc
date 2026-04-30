package httpserver

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/internal/ui/apiv1"
	"github.com/SUNET/vc/internal/ui/cache"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/gin-gonic/gin"
)

// Service is the service object for httpserver
type Service struct {
	cfg           *model.Cfg
	log           *logger.Log
	tracer        *trace.Tracer
	server        *http.Server
	apiv1         Apiv1
	gin           *gin.Engine
	sessionConfig *sessionConfig
	httpHelpers   *httphelpers.Client
	cacheService  *cache.Service
}

// sessionConfig... values is also used for the session cookie
type sessionConfig struct {
	//if name is changed, the web (javascript) must also be updated with the new name
	name                       string
	inactivityTimeoutInSeconds int
	path                       string
	httpOnly                   bool
	secure                     bool
	sameSite                   http.SameSite
	usernameKey                string
	loggedInTimeKey            string
}

// New creates a new httpserver service
func New(ctx context.Context, cfg *model.Cfg, apiv1 *apiv1.Client, tracer *trace.Tracer, cacheService *cache.Service, log *logger.Log) (*Service, error) {
	s := &Service{
		cfg:          cfg,
		log:          log.New("httpserver"),
		tracer:       tracer,
		apiv1:        apiv1,
		gin:          gin.New(),
		server:       &http.Server{}, //#nosec G112 -- ReadHeaderTimeout set by httphelpers.Server.Default
		cacheService: cacheService,
		sessionConfig: &sessionConfig{
			name:                       "vc_ui_auth_session",
			inactivityTimeoutInSeconds: cfg.UI.SessionInactivityTimeoutInSeconds,
			path:                       "/",
			httpOnly:                   true,
			secure:                     cfg.UI.APIServer.TLS.Enable,
			sameSite:                   http.SameSiteStrictMode,
			usernameKey:                "username_key",
			loggedInTimeKey:            "logged_in_time_key",
		},
	}

	var err error
	s.httpHelpers, err = httphelpers.New(ctx, s.tracer, s.cfg, s.log)
	if err != nil {
		return nil, err
	}

	// extra middlewares (must be declared before Server.Default)
	s.gin.Use(s.middlewareUserSession(ctx, s.cfg))

	rgRoot, err := s.httpHelpers.Server.Default(ctx, s.server, s.gin, s.cfg.UI.APIServer)
	if err != nil {
		return nil, err
	}

	s.gin.Static("/static", "./static")
	s.gin.LoadHTMLFiles("./static/index.html")
	s.gin.GET("/", func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodPost, "login", http.StatusOK, s.endpointLogin)
	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "health", http.StatusOK, s.endpointHealth)

	rgAPIGW := rgRoot.Group("apigw")
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIGW, http.MethodGet, "health", http.StatusOK, s.endpointHealthAPIGW)

	rgVerifier := rgRoot.Group("verifier")
	s.httpHelpers.Server.RegEndpoint(ctx, rgVerifier, http.MethodGet, "health", http.StatusOK, s.endpointHealthVerifier)

	rgMockAS := rgRoot.Group("mockas")
	s.httpHelpers.Server.RegEndpoint(ctx, rgMockAS, http.MethodGet, "health", http.StatusOK, s.endpointHealthMockAS)

	rgSecure := rgRoot.Group("secure", s.middlewareAuthRequired(ctx))
	s.httpHelpers.Server.RegEndpoint(ctx, rgSecure, http.MethodDelete, "logout", http.StatusOK, s.endpointLogout)
	s.httpHelpers.Server.RegEndpoint(ctx, rgSecure, http.MethodGet, "user", http.StatusOK, s.endpointUser)

	rgMockASSecure := rgSecure.Group("mockas")
	s.httpHelpers.Server.RegEndpoint(ctx, rgMockASSecure, http.MethodPost, "mock/next", http.StatusOK, s.endpointMockNext)

	rgAPIGWSecure := rgSecure.Group("apigw")
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIGWSecure, http.MethodPost, "document/list", http.StatusOK, s.endpointDocumentList)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIGWSecure, http.MethodPost, "upload", http.StatusOK, s.endpointUpload)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIGWSecure, http.MethodPost, "document", http.StatusOK, s.endpointGetDocument)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIGWSecure, http.MethodPost, "notification", http.StatusOK, s.endpointNotification)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIGWSecure, http.MethodPost, "document/search", http.StatusOK, s.endpointSearchDocuments)
	s.httpHelpers.Server.RegEndpoint(ctx, rgAPIGWSecure, http.MethodDelete, "document", http.StatusOK, s.endpointDeleteDocument)

	// Run http server
	go func() {
		err := s.httpHelpers.Server.ListenAndServe(ctx, s.server, s.cfg.UI.APIServer)
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
