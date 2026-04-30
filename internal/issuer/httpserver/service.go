package httpserver

import (
	"context"
	"net/http"

	"github.com/SUNET/vc/internal/issuer/apiv1"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	// swagger docs
	_ "github.com/SUNET/vc/docs/issuer"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// Service is the service object for httpserver
type Service struct {
	cfg         *model.Cfg
	log         *logger.Log
	server      *http.Server
	apiv1       Apiv1
	gin         *gin.Engine
	tracer      *trace.Tracer
	httpHelpers *httphelpers.Client
}

// New creates a new httpserver service
func New(ctx context.Context, cfg *model.Cfg, apiv1 *apiv1.Client, tracer *trace.Tracer, log *logger.Log) (*Service, error) {
	s := &Service{
		cfg:    cfg,
		log:    log.New("httpserver"),
		apiv1:  apiv1,
		gin:    gin.New(),
		server: &http.Server{}, //#nosec G112 -- ReadHeaderTimeout set by httphelpers.Server.Default
		tracer: tracer,
	}

	var err error
	s.httpHelpers, err = httphelpers.New(ctx, s.tracer, s.cfg, s.log)
	if err != nil {
		return nil, err
	}

	rgRoot, err := s.httpHelpers.Server.Default(ctx, s.server, s.gin, s.cfg.Issuer.APIServer)
	if err != nil {
		return nil, err
	}

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "health", http.StatusOK, s.endpointHealth)

	rgDocs := rgRoot.Group("/swagger")
	rgDocs.GET("/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Run http server
	go func() {
		err := s.httpHelpers.Server.ListenAndServe(ctx, s.server, s.cfg.Issuer.APIServer)
		if err != nil {
			s.log.Trace("listen_error", "error", err)
		}
	}()

	s.log.Info("started")

	return s, nil
}

// Close closing httpserver
func (s *Service) Close(ctx context.Context) error {
	s.log.Info("Stopped")
	return nil
}
