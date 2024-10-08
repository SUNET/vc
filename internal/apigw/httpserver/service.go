package httpserver

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"
	"vc/internal/apigw/apiv1"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	// Swagger
	_ "vc/docs/apigw"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// Service is the service object for httpserver
type Service struct {
	config         *model.Cfg
	logger         *logger.Log
	server         *http.Server
	apiv1          Apiv1
	gin            *gin.Engine
	tlsConfig      *tls.Config
	tp             *trace.Tracer
	eventPublisher apiv1.EventPublisher
}

// New creates a new httpserver service
func New(ctx context.Context, config *model.Cfg, api *apiv1.Client, tp *trace.Tracer, logger *logger.Log, eventPublisher apiv1.EventPublisher) (*Service, error) {
	s := &Service{
		config: config,
		logger: logger,
		apiv1:  api,
		tp:     tp,
		server: &http.Server{
			ReadHeaderTimeout: 2 * time.Second,
		},
		eventPublisher: eventPublisher,
	}

	switch s.config.Common.Production {
	case true:
		gin.SetMode(gin.ReleaseMode)
	case false:
		gin.SetMode(gin.DebugMode)
	}

	apiValidator, err := helpers.NewValidator()
	if err != nil {
		return nil, err
	}
	binding.Validator = &defaultValidator{
		Validate: apiValidator,
	}

	s.gin = gin.New()
	s.server.Handler = s.gin
	s.server.Addr = config.APIGW.APIServer.Addr
	s.server.ReadTimeout = 5 * time.Second
	s.server.WriteTimeout = 30 * time.Second
	s.server.IdleTimeout = 90 * time.Second

	// Middlewares
	s.gin.Use(s.middlewareRequestID(ctx))
	s.gin.Use(s.middlewareDuration(ctx))
	s.gin.Use(s.middlewareLogger(ctx))
	s.gin.Use(s.middlewareCrash(ctx))
	problem404, err := helpers.Problem404()
	if err != nil {
		return nil, err
	}
	s.gin.NoRoute(func(c *gin.Context) { c.JSON(http.StatusNotFound, problem404) })

	rgRoot := s.gin.Group("/")
	s.regEndpoint(ctx, rgRoot, http.MethodGet, "health", s.endpointHealth)

	rgDocs := rgRoot.Group("/swagger")
	rgDocs.GET("/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	rgAPIv1 := rgRoot.Group("api/v1")

	if s.config.APIGW.APIServer.BasicAuth.Enabled {
		rgAPIv1.Use(s.middlewareBasicAuth(ctx))
	}

	s.regEndpoint(ctx, rgAPIv1, http.MethodPost, "/upload", s.endpointUpload)
	s.regEndpoint(ctx, rgAPIv1, http.MethodPost, "/notification", s.endpointNotification)
	s.regEndpoint(ctx, rgAPIv1, http.MethodPut, "/document/identity", s.endpointAddDocumentIdentity)
	s.regEndpoint(ctx, rgAPIv1, http.MethodDelete, "/document/identity", s.endpointDeleteDocumentIdentity)
	s.regEndpoint(ctx, rgAPIv1, http.MethodDelete, "/document", s.endpointDeleteDocument)
	s.regEndpoint(ctx, rgAPIv1, http.MethodPost, "/document/collect_id", s.endpointGetDocumentCollectID)
	s.regEndpoint(ctx, rgAPIv1, http.MethodPost, "/identity/mapping", s.endpointIdentityMapping)
	s.regEndpoint(ctx, rgAPIv1, http.MethodPost, "/document/list", s.endpointDocumentList)
	s.regEndpoint(ctx, rgAPIv1, http.MethodPost, "/document", s.endpointGetDocument)
	s.regEndpoint(ctx, rgAPIv1, http.MethodPost, "/consent", s.endpointAddConsent)
	s.regEndpoint(ctx, rgAPIv1, http.MethodPost, "/consent/get", s.endpointGetConsent)
	s.regEndpoint(ctx, rgAPIv1, http.MethodPost, "/document/revoke", s.endpointRevokeDocument)

	s.regEndpoint(ctx, rgAPIv1, http.MethodPost, "/credential", s.endpointCredential)

	// Run http server
	go func() {
		if s.config.APIGW.APIServer.TLS.Enabled {
			s.applyTLSConfig(ctx)

			err := s.server.ListenAndServeTLS(s.config.APIGW.APIServer.TLS.CertFilePath, s.config.APIGW.APIServer.TLS.KeyFilePath)
			if err != nil {
				s.logger.Error(err, "listen_and_server_tls")
			}
		} else {
			err = s.server.ListenAndServe()
			if err != nil {
				s.logger.Error(err, "listen_and_server")
			}
		}
	}()

	s.logger.Info("started")

	return s, nil
}

func (s *Service) regEndpoint(ctx context.Context, rg *gin.RouterGroup, method, path string, handler func(context.Context, *gin.Context) (interface{}, error)) {
	rg.Handle(method, path, func(c *gin.Context) {
		res, err := handler(ctx, c)
		if err != nil {
			renderContent(c, 400, gin.H{"error": helpers.NewErrorFromError(err)})
			return
		}

		renderContent(c, 200, res)
	})
}

func renderContent(c *gin.Context, code int, data interface{}) {
	switch c.NegotiateFormat(gin.MIMEJSON, "*/*") {
	case gin.MIMEJSON:
		c.JSON(code, data)
	case "*/*": // curl
		c.JSON(code, data)
	default:
		c.JSON(406, gin.H{"error": helpers.NewErrorDetails("not_acceptable", "Accept header is invalid. It should be \"application/json\".")})
	}
}

// Close closing httpserver
func (s *Service) Close(ctx context.Context) error {
	s.logger.Info("Quit")
	return nil
}
