package httpserver

import (
	"context"
	"net/http"
	"vc/internal/mockas/apiv1"
	"vc/pkg/httphelpers"
	"vc/pkg/logger"
	"vc/pkg/model"
	"vc/pkg/trace"

	"github.com/gin-gonic/gin"
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
		cfg:   cfg,
		log:   log.New("httpserver"),
		apiv1: apiv1,
		gin:   gin.New(),
		server: &http.Server{}, // Timeouts and other defaults are set by httphelpers.Server.Default
		tracer: tracer,
	}

	var err error
	s.httpHelpers, err = httphelpers.New(ctx, s.tracer, s.cfg, s.log)
	if err != nil {
		return nil, err
	}

	rgRoot, err := s.httpHelpers.Server.Default(ctx, s.server, s.gin, s.cfg.MockAS.APIServer)
	if err != nil {
		return nil, err
	}

	s.httpHelpers.Server.RegEndpoint(ctx, rgRoot, http.MethodGet, "health", http.StatusOK, s.endpointHealth)

	rgAPIv1 := rgRoot.Group("api/v1")
	rgMock := rgAPIv1.Group("/mock")
	s.httpHelpers.Server.RegEndpoint(ctx, rgMock, http.MethodPost, "/next", http.StatusOK, s.endpointMockNext)
	s.httpHelpers.Server.RegEndpoint(ctx, rgMock, http.MethodPost, "/bulk", http.StatusOK, s.endpointMockBulk)

	// Run http server
	go func() {
		err := s.httpHelpers.Server.ListenAndServe(ctx, s.server, s.cfg.MockAS.APIServer)
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
