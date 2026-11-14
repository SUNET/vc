package httpserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/SUNET/vc/internal/registry/apiv1"
	pkgcache "github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/jose"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/tokenstatuslist"
	"github.com/SUNET/vc/pkg/trace"
)

// newRoutedTestService wires a Service with the real status list routes on a
// bare gin engine. It calls registerStatusListEndpoints, the same function the
// server's New uses, so the paths under test are the paths that ship.
func newRoutedTestService(t *testing.T, api *mockApiv1) *gin.Engine {
	t.Helper()

	gin.SetMode(gin.TestMode)
	log := logger.NewSimple("test")
	ctx := t.Context()

	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{Registry: &model.Registry{}}

	httpHelpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	counter, err := pkgcache.New(false, "", nil, log).NewRateLimitCounter(ctx, "test_rate_limit")
	require.NoError(t, err)

	engine := gin.New()
	s := &Service{
		cfg:                    cfg,
		log:                    log,
		apiv1:                  api,
		gin:                    engine,
		httpHelpers:            httpHelpers,
		statusListsRateLimiter: httphelpers.NewRateLimiter(counter, 600),
	}

	// Registering both ":id" and ":id/.well-known/jwks.json" in one group is
	// the thing that can go wrong here: gin panics at registration on a route
	// conflict, which would take the whole registry down at startup rather
	// than fail a request.
	s.registerStatusListEndpoints(ctx, &engine.RouterGroup)

	return engine
}

func TestStatusListJWKSRouteIsServedUnderTheListURI(t *testing.T) {
	api := &mockApiv1{jwksReply: &jose.JWKS{Keys: []jose.JWKWithMetadata{{Kty: "EC", Kid: "signer"}}}}
	engine := newRoutedTestService(t, api)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/statuslists/7/.well-known/jwks.json", nil)
	req.Header.Set("Accept", "application/json")
	engine.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "the list URI's JWKS is what a trust registry falls back to")

	var body jose.JWKS
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Len(t, body.Keys, 1)
	assert.Equal(t, "signer", body.Keys[0].Kid)

	// The ":id" wildcard still has to bind with path segments after it, or
	// every list would be answered for with section 0's keys.
	assert.Equal(t, int64(7), api.jwksSection, "the section must bind from the path, not default to zero")
}

func TestStatusListTokenRouteStillResolves(t *testing.T) {
	api := &mockApiv1{
		jwksReply:       &jose.JWKS{},
		statusListReply: &apiv1.TokenStatusListsResponse{Token: []byte("token"), ContentType: tokenstatuslist.MediaTypeJWT},
	}
	engine := newRoutedTestService(t, api)

	// The token endpoint shares the ":id" wildcard with the JWKS endpoint. If
	// the two had been registered in a way gin resolves by prefix, this would
	// land on the wrong handler.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/statuslists/7", nil)
	engine.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "the status list token endpoint must keep resolving")
	assert.Equal(t, "token", w.Body.String(), "and must keep reaching its own handler, not the JWKS one")
}
