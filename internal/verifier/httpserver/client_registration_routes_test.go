package httpserver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUNET/vc/internal/verifier/middleware"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registrationRouteEngine wires up just the dynamic client registration
// routes, the way New does, for the OIDC provider config given.
//
// The handlers are never called here: what is under test is which routes
// exist, which is decided at registration time and is the whole of what
// closing registration changes.
func registrationRouteEngine(t *testing.T, oidcProvider *model.OIDCOP) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{
		Common: &model.Common{},
		Verifier: &model.Verifier{
			PublicURL: "https://verifier.example.com",
			Outbound: model.VerifierOutbound{
				OIDCProvider: oidcProvider,
			},
		},
	}

	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	rateLimits := middleware.DefaultRateLimitConfig()

	s := &Service{
		cfg:             cfg,
		log:             log.New("httpserver"),
		tracer:          tracer,
		httpHelpers:     helpers,
		registerLimiter: middleware.NewRateLimiter(rateLimits.RegisterRequestsPerMinute, rateLimits.RegisterBurst),
		registerAuth:    func(c *gin.Context) { c.Next() },
	}

	engine := gin.New()
	s.registerDynamicClientRegistrationEndpoints(ctx, engine.Group("/"))

	return engine
}

// registeredRoutes renders the engine's route table as "METHOD /path" strings.
func registeredRoutes(engine *gin.Engine) []string {
	routes := make([]string, 0, len(engine.Routes()))
	for _, r := range engine.Routes() {
		routes = append(routes, fmt.Sprintf("%s %s", r.Method, r.Path))
	}

	return routes
}

// The registration routes an OP that offers dynamic client registration
// serves: RFC 7591 registration and the RFC 7592 configuration endpoints.
var registrationRoutes = []string{
	"POST /register",
	"GET /register/:client_id",
	"PUT /register/:client_id",
	"DELETE /register/:client_id",
}

func boolPtr(b bool) *bool { return &b }

// A deployment that says nothing about dynamic registration keeps getting it,
// which is what every existing config expects.
func TestRegistrationRoutesServedByDefault(t *testing.T) {
	for _, tt := range []struct {
		name         string
		oidcProvider *model.OIDCOP
	}{
		{
			name:         "no dynamic_registration block",
			oidcProvider: &model.OIDCOP{Issuer: "https://verifier.example.com"},
		},
		{
			name: "explicitly enabled",
			oidcProvider: &model.OIDCOP{
				Issuer:              "https://verifier.example.com",
				DynamicRegistration: &model.DynamicRegistrationConfig{Enabled: boolPtr(true)},
			},
		},
		{
			name:         "no oidc_provider block at all",
			oidcProvider: nil,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			routes := registeredRoutes(registrationRouteEngine(t, tt.oidcProvider))

			for _, want := range registrationRoutes {
				assert.Contains(t, routes, want, "registration must still be served when it has not been turned off")
			}
		})
	}
}

// Closed means the routes do not exist, so gin answers 404 - not a handler
// that refuses, which would still tell a client the endpoint is there.
func TestRegistrationRoutesAbsentWhenDisabled(t *testing.T) {
	engine := registrationRouteEngine(t, &model.OIDCOP{
		Issuer:              "https://verifier.example.com",
		DynamicRegistration: &model.DynamicRegistrationConfig{Enabled: boolPtr(false)},
	})

	assert.Empty(t, registeredRoutes(engine),
		"dynamic_registration.enabled: false must leave the registration routes unregistered")

	for _, route := range []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/register"},
		{http.MethodGet, "/register/client-1"},
		{http.MethodPut, "/register/client-1"},
		{http.MethodDelete, "/register/client-1"},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, httptest.NewRequest(route.method, route.path, nil))

			assert.Equal(t, http.StatusNotFound, w.Code)
		})
	}
}

// The auth block left behind by a deployment that has since closed
// registration is inert, not a startup failure: the routes it protected are
// not there to protect.
func TestRegistrationRoutesStayClosedWithAnAuthBlockConfigured(t *testing.T) {
	engine := registrationRouteEngine(t, &model.OIDCOP{
		Issuer:              "https://verifier.example.com",
		DynamicRegistration: &model.DynamicRegistrationConfig{Enabled: boolPtr(false)},
		DynamicRegistrationAuth: &model.DynamicRegistrationAuthConfig{
			Mode:                  "static",
			StaticBearerTokenFile: "/nonexistent/registration-token",
		},
	})

	assert.Empty(t, registeredRoutes(engine))
}
