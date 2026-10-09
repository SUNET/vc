package httphelpers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/oauth2"
	"github.com/SUNET/vc/pkg/openid4vci"

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
			// Every failed request gets this, here rather than inside
			// publicError: the two structured branches below return
			// without reaching it, and an OAuth or OpenID4VCI refusal
			// deliberately withholds its cause from the RESPONSE - which
			// is exactly why the cause has to reach the log.
			s.log.Debug("RegEndpoint", "err", err)

			// OAuth 2.0 structured error response per RFC 6749 §5.2
			if oauthErr, ok := errors.AsType[*oauth2.OAuthError](err); ok {
				c.Header("Cache-Control", "no-store")
				c.Header("Pragma", "no-cache")
				if oauthErr.HTTPStatus == http.StatusUnauthorized && c.Writer.Header().Get("WWW-Authenticate") == "" {
					c.Header("WWW-Authenticate", "Bearer")
				}
				c.JSON(oauthErr.HTTPStatus, oauthErr)
				return
			}

			// OpenID4VCI structured error response per OID4VCI §7.3
			if vciErr, ok := errors.AsType[*openid4vci.Error](err); ok {
				c.JSON(openid4vci.StatusCode(vciErr), vciErr)
				return
			}

			statusCode := StatusCode(ctx, err)
			s.client.Rendering.Content(ctx, c, statusCode, gin.H{"error": s.publicError(c, "RegEndpoint", err, statusCode)})
			return
		}

		if res == nil {
			// Preserve any status the handler already set (e.g. via c.Redirect).
			if c.Writer.Status() == http.StatusOK {
				c.Status(defaultStatus)
			}
			return
		}

		s.client.Rendering.Content(ctx, c, defaultStatus, res)
	})
}

// publicError shapes an error for the client and makes sure it is logged.
//
// An error nothing recognised used to go out as its raw Go text - the whole
// wrapped chain, naming internal paths, configuration fields and failure
// modes - while the only log line for it was at Debug, which the production
// logger drops. So the detail reached the caller and nothing reached the
// operator, and the req_id the caller was handed correlated with a request
// line carrying no error at all. That is the wrong way round (SUNET/vc#357).
//
// Now it is the other way: the chain is logged at Error with the request id,
// and the caller gets the request id and nothing else.
//
// Errors that were recognised are returned unchanged. A validation report, a
// JSON parse position, a sentinel like "no document found" - those are
// shapes somebody chose to publish, they are useful to an API client, and
// they are not secrets.
func (s *serverHandler) publicError(c *gin.Context, where string, err error, statusCode int) *helpers.Error {
	shaped := helpers.NewErrorFromError(err)
	if !shaped.IsUnclassified() {
		// Already logged at Debug by the caller, along with every other
		// failed request - see RegEndpoint.
		return shaped
	}

	requestID := c.GetString("req_id")

	s.log.Error(err, where+": unclassified error",
		"req_id", requestID,
		"status", statusCode,
		"method", c.Request.Method,
		"path", c.Request.URL.Path)

	details := map[string]any{}
	if requestID != "" {
		// In the body as well as the req_id header: this is the string an
		// operator gets read back to them off a screenshot.
		details["req_id"] = requestID
	}

	return helpers.NewErrorDetails("internal_server_error", details)
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
			s.client.Rendering.Content(ctx, c, statusCode, gin.H{"error": s.publicError(c, "RegStreamEndpoint", err, statusCode)})
			return
		}

		s.client.Rendering.Content(ctx, c, defaultStatus, res)
	})
}

// SetGinProductionMode sets the gin mode to production or debug
func (s *serverHandler) SetGinProductionMode() {
	if model.BoolVal(s.client.cfg.Common.Production, true) {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}
}

// Default sets the default server configuration
func (s *serverHandler) Default(ctx context.Context, serverHTTP *http.Server, serverGin *gin.Engine, apiServer model.APIServer) (*gin.RouterGroup, error) {
	s.SetGinProductionMode()

	var err error
	binding.Validator, err = s.client.Binding.Validator()
	if err != nil {
		return nil, err
	}

	serverHTTP.Handler = serverGin
	serverHTTP.Addr = apiServer.Addr
	serverHTTP.ReadTimeout = 5 * time.Second
	serverHTTP.WriteTimeout = 30 * time.Second
	serverHTTP.IdleTimeout = 90 * time.Second
	// ReadHeaderTimeout limits the time to read request headers.
	// Keep this low (a few seconds) to mitigate Slowloris DoS attacks (CWE-400).
	// Do NOT increase this to "fix" slow requests — find the actual root cause instead.
	serverHTTP.ReadHeaderTimeout = 2 * time.Second
	// MaxHeaderBytes limits the size of request headers to 1 MB (default).
	// This mitigates memory exhaustion attacks from oversized headers.
	serverHTTP.MaxHeaderBytes = 1 << 20 // 1 MB

	// Middlewares
	serverGin.Use(s.client.Middleware.ServedBy(ctx, apiServer.ServedByHeader))
	serverGin.Use(s.client.Middleware.RequestID(ctx))
	serverGin.Use(s.client.Middleware.Duration(ctx))
	serverGin.Use(s.client.Middleware.Logger(ctx))
	serverGin.Use(s.client.Middleware.Crash(ctx))
	serverGin.Use(s.client.Middleware.SecurityHeaders(apiServer.TLS.Enable || apiServer.TrustProxyTLS))
	serverGin.Use(s.client.Middleware.MaxBodySize(10 << 20)) // 10 MB default body limit
	serverGin.Use(s.client.Middleware.CustomBranding(s.client.cfg.Common.Branding))
	problem404 := helpers.Problem404()
	serverGin.NoRoute(func(c *gin.Context) { c.JSON(http.StatusNotFound, problem404) })

	rgRoot := serverGin.Group("/")

	return rgRoot, nil
}
