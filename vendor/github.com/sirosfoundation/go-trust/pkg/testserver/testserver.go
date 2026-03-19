// Package testserver provides an embedded test server for go-trust.
//
// This package allows dependent applications to create lightweight test servers
// for integration testing without running a full go-trust instance with pipelines.
// It provides configurable mock registries and supports both httptest.Server
// integration and standalone usage.
//
// # Basic Usage
//
// Create a simple test server that accepts all requests:
//
//	srv := testserver.New(testserver.WithAcceptAll())
//	defer srv.Close()
//
//	client := authzenclient.New(srv.URL())
//	resp, err := client.Evaluate(ctx, req)
//
// # Custom Mock Registries
//
// Create a server with specific trust responses:
//
//	srv := testserver.New(
//	    testserver.WithMockRegistry("test-registry", true, []string{"x5c", "jwk"}),
//	)
//	defer srv.Close()
//
// # Decision Callback
//
// Use a callback for dynamic responses:
//
//	srv := testserver.New(
//	    testserver.WithDecisionFunc(func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
//	        if req.Subject.ID == "trusted-subject" {
//	            return &authzen.EvaluationResponse{Decision: true}, nil
//	        }
//	        return &authzen.EvaluationResponse{Decision: false}, nil
//	    }),
//	)
//
// # HTTP Handler
//
// Get the HTTP handler for use with custom test setups:
//
//	handler := testserver.NewHandler(testserver.WithAcceptAll())
//	srv := httptest.NewServer(handler)
package testserver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirosfoundation/g119612/pkg/logging"
	"github.com/sirosfoundation/go-trust/pkg/api"
	"github.com/sirosfoundation/go-trust/pkg/authzen"
	"github.com/sirosfoundation/go-trust/pkg/registry"
)

// Server is an embedded test server for go-trust AuthZEN endpoints.
type Server struct {
	httpServer *httptest.Server
	serverCtx  *api.ServerContext
}

// DecisionFunc is a function that returns a trust decision for a given request.
type DecisionFunc func(req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error)

// Option configures a test server.
type Option func(*serverConfig)

type serverConfig struct {
	registries   []registry.TrustRegistry
	decisionFunc DecisionFunc
	baseURL      string
}

// WithMockRegistry adds a mock registry with the specified behavior.
func WithMockRegistry(name string, decision bool, resourceTypes []string) Option {
	return func(cfg *serverConfig) {
		cfg.registries = append(cfg.registries, &mockRegistry{
			name:     name,
			decision: decision,
			types:    resourceTypes,
		})
	}
}

// WithAcceptAll configures the server to accept all trust requests.
func WithAcceptAll() Option {
	return WithMockRegistry("accept-all", true, []string{"*"})
}

// WithRejectAll configures the server to reject all trust requests.
func WithRejectAll() Option {
	return WithMockRegistry("reject-all", false, []string{"*"})
}

// WithRegistry adds a custom TrustRegistry implementation.
func WithRegistry(reg registry.TrustRegistry) Option {
	return func(cfg *serverConfig) {
		cfg.registries = append(cfg.registries, reg)
	}
}

// WithDecisionFunc sets a callback function for dynamic trust decisions.
// This takes precedence over mock registries when set.
func WithDecisionFunc(fn DecisionFunc) Option {
	return func(cfg *serverConfig) {
		cfg.decisionFunc = fn
	}
}

// WithBaseURL sets the base URL reported in AuthZEN discovery.
// If not set, the httptest server URL is used.
func WithBaseURL(url string) Option {
	return func(cfg *serverConfig) {
		cfg.baseURL = url
	}
}

// New creates a new embedded test server.
func New(opts ...Option) *Server {
	cfg := &serverConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	// Create server context with silent logger for tests
	serverCtx := api.NewServerContext(logging.SilentLogger())

	// Create registry manager
	registryMgr := registry.NewRegistryManager(registry.FirstMatch, 30*time.Second)

	if cfg.decisionFunc != nil {
		// Use callback-based registry
		registryMgr.Register(&callbackRegistry{fn: cfg.decisionFunc})
	} else if len(cfg.registries) > 0 {
		// Use configured registries
		for _, reg := range cfg.registries {
			registryMgr.Register(reg)
		}
	} else {
		// Default: accept all
		registryMgr.Register(&mockRegistry{
			name:     "default-accept",
			decision: true,
			types:    []string{"*"},
		})
	}

	serverCtx.RegistryManager = registryMgr

	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Create Gin router
	r := gin.New()

	// Create httptest server FIRST so we know the URL
	httpServer := httptest.NewServer(r)

	// Now set base URL (either custom or from httptest server)
	if cfg.baseURL != "" {
		serverCtx.BaseURL = cfg.baseURL
	} else {
		serverCtx.BaseURL = httpServer.URL
	}

	// Register routes AFTER setting BaseURL (WellKnownHandler captures baseURL)
	// Note: RegisterAPIRoutes already includes health endpoints
	api.RegisterAPIRoutes(r, serverCtx)

	return &Server{
		httpServer: httpServer,
		serverCtx:  serverCtx,
	}
}

// NewHandler creates an http.Handler for use with custom test setups.
// Use this when you need more control over the test server lifecycle.
// Note: WithBaseURL should be set explicitly when using NewHandler.
func NewHandler(opts ...Option) http.Handler {
	cfg := &serverConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	// Create server context with silent logger for tests
	serverCtx := api.NewServerContext(logging.SilentLogger())

	// Create registry manager
	registryMgr := registry.NewRegistryManager(registry.FirstMatch, 30*time.Second)

	if cfg.decisionFunc != nil {
		registryMgr.Register(&callbackRegistry{fn: cfg.decisionFunc})
	} else if len(cfg.registries) > 0 {
		for _, reg := range cfg.registries {
			registryMgr.Register(reg)
		}
	} else {
		registryMgr.Register(&mockRegistry{
			name:     "default-accept",
			decision: true,
			types:    []string{"*"},
		})
	}

	serverCtx.RegistryManager = registryMgr

	if cfg.baseURL != "" {
		serverCtx.BaseURL = cfg.baseURL
	}

	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Create Gin router
	// Note: RegisterAPIRoutes already includes health endpoints
	r := gin.New()
	api.RegisterAPIRoutes(r, serverCtx)

	return r
}

// URL returns the base URL of the test server.
func (s *Server) URL() string {
	return s.httpServer.URL
}

// Close shuts down the test server.
func (s *Server) Close() {
	s.httpServer.Close()
}

// Client returns the HTTP client configured for the test server.
func (s *Server) Client() *http.Client {
	return s.httpServer.Client()
}

// mockRegistry implements TrustRegistry for testing.
type mockRegistry struct {
	name     string
	decision bool
	types    []string
}

func (m *mockRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	return &authzen.EvaluationResponse{
		Decision: m.decision,
		Context: &authzen.EvaluationResponseContext{
			Reason: map[string]interface{}{
				"registry": m.name,
				"message":  "mock response",
			},
		},
	}, nil
}

func (m *mockRegistry) SupportedResourceTypes() []string {
	return m.types
}

func (m *mockRegistry) SupportsResolutionOnly() bool {
	return true
}

func (m *mockRegistry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{
		Name:        m.name,
		Type:        "mock",
		Description: "Mock registry for testing",
		Version:     "1.0.0",
	}
}

func (m *mockRegistry) Healthy() bool {
	return true
}

func (m *mockRegistry) Refresh(ctx context.Context) error {
	return nil
}

// callbackRegistry implements TrustRegistry using a callback function.
type callbackRegistry struct {
	fn DecisionFunc
}

func (c *callbackRegistry) Evaluate(ctx context.Context, req *authzen.EvaluationRequest) (*authzen.EvaluationResponse, error) {
	return c.fn(req)
}

func (c *callbackRegistry) SupportedResourceTypes() []string {
	return []string{"*"}
}

func (c *callbackRegistry) SupportsResolutionOnly() bool {
	return true
}

func (c *callbackRegistry) Info() registry.RegistryInfo {
	return registry.RegistryInfo{
		Name:        "callback",
		Type:        "callback",
		Description: "Callback-based registry for testing",
		Version:     "1.0.0",
	}
}

func (c *callbackRegistry) Healthy() bool {
	return true
}

func (c *callbackRegistry) Refresh(ctx context.Context) error {
	return nil
}
