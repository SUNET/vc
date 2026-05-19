package api

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/g119612/pkg/logging"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
)

// parseX5C extracts and parses x5c certificates from a map[string]interface{}.
// Deprecated: Use parseX5CFromArray or parseX5CFromJWK for AuthZEN Trust Registry Profile compliance.
func parseX5C(props map[string]interface{}) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	if props == nil {
		return certs, nil
	}
	x5cVal, ok := props["x5c"]
	if !ok {
		return certs, nil
	}
	x5cList, ok := x5cVal.([]interface{})
	if !ok {
		return certs, fmt.Errorf("x5c property is not a list")
	}
	for _, item := range x5cList {
		str, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("x5c entry is not a string")
		}
		der, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode x5c entry: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse x5c certificate: %v", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// parseX5CFromArray parses X.509 certificates from an array of base64-encoded DER certificates.
// This is used when resource.type is "x5c" in the AuthZEN Trust Registry Profile.
// Each element in the array should be a base64-encoded X.509 DER certificate.
func parseX5CFromArray(key []interface{}) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	if len(key) == 0 {
		return nil, fmt.Errorf("resource.key is empty")
	}

	for i, item := range key {
		str, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("resource.key[%d] is not a string", i)
		}
		der, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode resource.key[%d]: %v", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate from resource.key[%d]: %v", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// parseX5CFromJWK parses X.509 certificates from a JWK (JSON Web Key) structure.
// This is used when resource.type is "jwk" in the AuthZEN Trust Registry Profile.
// The JWK may contain an "x5c" claim which is an array of base64-encoded DER certificates.
// The resource.key array should contain a single JWK object as a map[string]interface{}.
func parseX5CFromJWK(key []interface{}) ([]*x509.Certificate, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("resource.key is empty")
	}

	// The first element should be a JWK object
	jwk, ok := key[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("resource.key[0] is not a JWK object (map)")
	}

	// Extract x5c claim from JWK
	x5cVal, ok := jwk["x5c"]
	if !ok {
		return nil, fmt.Errorf("JWK does not contain x5c claim")
	}

	x5cList, ok := x5cVal.([]interface{})
	if !ok {
		return nil, fmt.Errorf("JWK x5c claim is not an array")
	}

	var certs []*x509.Certificate
	for i, item := range x5cList {
		str, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("JWK x5c[%d] is not a string", i)
		}
		der, err := base64.StdEncoding.DecodeString(str)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode JWK x5c[%d]: %v", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate from JWK x5c[%d]: %v", i, err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// buildResponse constructs an EvaluationResponse for the AuthZEN API.
// Per the AuthZEN Trust Registry Profile, the response format is not profiled,
// so we use a simplified structure with reason as a general-purpose field.
func buildResponse(decision bool, reason string) authzen.EvaluationResponse {
	if decision {
		return authzen.EvaluationResponse{Decision: true}
	}
	return authzen.EvaluationResponse{
		Decision: false,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{"error": reason},
		},
	}
}

// NewServerContext creates a new ServerContext with a configured logger.
// The ServerContext will always have a valid logger - if none is provided,
// it will use the DefaultLogger.
func NewServerContext(logger logging.Logger) *ServerContext {
	// Always ensure a valid logger
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &ServerContext{
		Logger: logger,
	}
}

// RegisterAPIRoutes sets up all API routes on the given Gin engine.
//
// This function registers the following API endpoints:
//
// AuthZEN Discovery:
//
// GET /.well-known/authzen-configuration - Returns PDP metadata for service discovery (AuthZEN spec Section 9)
//
// AuthZEN Evaluation:
//
// POST /evaluation - Implements the AuthZEN Trust Registry Profile for validating name-to-key bindings
//
//	This endpoint processes AuthZEN EvaluationRequest objects per draft-johansson-authzen-trust,
//	validating that a public key (in resource.key) is correctly bound to a name (in subject.id)
//	according to the trusted certificates in the pipeline context.
//
// Registry Information:
//
// GET /registries - Returns information about all configured trust registries
//
// Deprecated Endpoints (will be removed in v2.0.0):
//
// GET /tsls - DEPRECATED: Use GET /registries instead
//
// GET /status - DEPRECATED: Use GET /readyz instead
//
// GET /info - DEPRECATED: Use GET /registries instead
//
// If a RateLimiter is configured in the ServerContext, it will be applied to all routes.
func RegisterAPIRoutes(r *gin.Engine, serverCtx *ServerContext) {
	// Apply rate limiting middleware if configured
	if serverCtx.RateLimiter != nil {
		r.Use(serverCtx.RateLimiter.Middleware())
		serverCtx.Logger.Info("Rate limiting enabled",
			logging.F("rps", serverCtx.RateLimiter.rps),
			logging.F("burst", serverCtx.RateLimiter.burst))
	}

	// Register health check endpoints (required for Kubernetes probes)
	RegisterHealthEndpoints(r, serverCtx)

	// AuthZEN well-known discovery endpoint (Section 9 of base spec)
	r.GET("/.well-known/authzen-configuration", WellKnownHandler(serverCtx.BaseURL))

	// AuthZEN evaluation endpoint
	r.POST("/evaluation", AuthZENDecisionHandler(serverCtx))

	// Registry information endpoint
	r.GET("/registries", RegistriesHandler(serverCtx))

	// Deprecated endpoints (kept for backward compatibility)
	r.GET("/tsls", DeprecatedTSLsHandler(serverCtx))
	r.GET("/status", StatusHandler(serverCtx))
	r.GET("/info", InfoHandler(serverCtx))

	// Test-mode shutdown endpoint
	// This endpoint is only registered when GO_TRUST_TEST_MODE environment variable is set
	// It allows integration tests to gracefully shutdown the server
	if os.Getenv("GO_TRUST_TEST_MODE") == "1" {
		r.POST("/test/shutdown", TestShutdownHandler(serverCtx))
		serverCtx.Logger.Warn("Test mode enabled: /test/shutdown endpoint is available")
	}
}
