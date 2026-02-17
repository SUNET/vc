package httphelpers

import (
	"context"
	"fmt"
	"net/http"
	"time"
	"vc/pkg/helpers"
	"vc/pkg/logger"
	"vc/pkg/model"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

type serverHandler struct {
	log    *logger.Log
	client *Client
}

// ListenAndServe starts the HTTP server with TLS or without based on the APIServer.TLS configuration
func (s *serverHandler) ListenAndServe(ctx context.Context, server *http.Server, apiConfig model.APIServer) error {
	if apiConfig.TLS.Enable {
		server.TLSConfig = s.client.TLS.Standard(ctx)

		err := server.ListenAndServeTLS(apiConfig.TLS.CertFilePath, apiConfig.TLS.KeyFilePath)
		if err != nil {
			s.log.Error(err, "listen_and_server_tls")
			return err
		}
	} else {
		if err := server.ListenAndServe(); err != nil {
			s.log.Error(err, "listen_and_server")
			return err
		}
	}

	return nil
}

// RegEndpoint registers an endpoint with the gin router
func (s *serverHandler) RegEndpoint(ctx context.Context, rg *gin.RouterGroup, method, path string, defaultStatus int, handler func(context.Context, *gin.Context) (any, error)) {
	rg.Handle(method, path, func(c *gin.Context) {
		k := fmt.Sprintf("api_endpoint %s:%s%s", method, rg.BasePath(), path)
		ctx, span := s.client.tracer.Start(ctx, k)
		defer span.End()

		res, err := handler(ctx, c)
		if err != nil {
			s.log.Debug("RegEndpoint", "err", err)
			statusCode := StatusCode(ctx, err)
			s.client.Rendering.Content(ctx, c, statusCode, gin.H{"error": helpers.NewErrorFromError(err)})
			return
		}

		// Skip rendering if response is nil (e.g., redirect was already handled)
		if res == nil {
			return
		}

		s.client.Rendering.Content(ctx, c, defaultStatus, res)
	})
}

// RegStreamEndpoint registers an endpoint with the gin router
func (s *serverHandler) RegStreamEndpoint(ctx context.Context, rg *gin.RouterGroup, method, path string, defaultStatus int, ch chan string, handler func(context.Context, *gin.Context, chan string) (any, error)) {
	rg.Handle(method, path, func(c *gin.Context) {
		k := fmt.Sprintf("api_endpoint %s:%s%s", method, rg.BasePath(), path)
		ctx, span := s.client.tracer.Start(ctx, k)
		defer span.End()

		res, err := handler(ctx, c, ch)
		if err != nil {
			s.log.Debug("RegStreamEndpoint", "err", err)
			statusCode := StatusCode(ctx, err)
			s.client.Rendering.Content(ctx, c, statusCode, gin.H{"error": helpers.NewErrorFromError(err)})
			return
		}

		s.client.Rendering.Content(ctx, c, defaultStatus, res)
	})
}

// SetGinProductionMode sets the gin mode to production or debug
func (s *serverHandler) SetGinProductionMode() {
	switch s.client.cfg.Common.Production {
	case true:
		gin.SetMode(gin.ReleaseMode)
	case false:
		gin.SetMode(gin.DebugMode)
	}
}

// Default sets the default server configuration
func (s *serverHandler) Default(ctx context.Context, serverHTTP *http.Server, serverGin *gin.Engine, APIAddr string) (*gin.RouterGroup, error) {
	s.SetGinProductionMode()

	var err error
	binding.Validator, err = s.client.Binding.Validator()
	if err != nil {
		return nil, err
	}

	serverHTTP.Handler = serverGin
	serverHTTP.Addr = APIAddr
	serverHTTP.ReadTimeout = 5 * time.Second
	serverHTTP.WriteTimeout = 30 * time.Second
	serverHTTP.IdleTimeout = 90 * time.Second
	serverHTTP.ReadHeaderTimeout = 2 * time.Second

	// Middlewares
	serverGin.Use(s.client.Middleware.RequestID(ctx))
	serverGin.Use(s.client.Middleware.Duration(ctx))
	serverGin.Use(s.client.Middleware.Logger(ctx))
	serverGin.Use(s.client.Middleware.Crash(ctx))
	problem404 := helpers.Problem404()
	serverGin.NoRoute(func(c *gin.Context) { c.JSON(http.StatusNotFound, problem404) })

	rgRoot := serverGin.Group("/")

	return rgRoot, nil
}
