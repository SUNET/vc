package httpserver

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUNET/vc/internal/verifier/middleware"
	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// uiInteractionRateLimitEngine registers POST /ui/interaction exactly as the
// server does, with the burst the shipped defaults give it.
func uiInteractionRateLimitEngine(t *testing.T) (*gin.Engine, int) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{
		Common:   &model.Common{},
		Verifier: &model.Verifier{PublicURL: "https://verifier.example.com"},
	}

	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	rateLimits := middleware.DefaultRateLimitConfig()

	s := &Service{
		cfg:                cfg,
		log:                log.New("httpserver"),
		tracer:             tracer,
		httpHelpers:        helpers,
		apiv1:              unimplementedApiv1{},
		interactionLimiter: middleware.NewRateLimiter(rateLimits.InteractionRequestsPerMinute, rateLimits.InteractionBurst),
	}

	engine := gin.New()
	sessionStore := cookie.NewStore(
		[]byte("12345678901234567890123456789012"),
		[]byte("1234567890123456"),
	)
	sessionStore.Options(sessions.Options{Path: "/", MaxAge: 900, HttpOnly: true})

	rg := engine.Group("/")
	rg.Use(sessions.Sessions("verifier_user_session", sessionStore))
	s.registerUIInteraction(ctx, rg.Group("/ui"))

	return engine, rateLimits.InteractionBurst
}

// postInteraction sends a body the request binding refuses, so the request is
// answered without reaching apiv1 - which is unimplemented here. What is
// under test is the middleware in front of the handler, not the handler.
func postInteraction(engine *gin.Engine) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/ui/interaction", bytes.NewBufferString("{"))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.0.2.10:1234"
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	return rec
}

func TestUIInteractionIsRateLimited(t *testing.T) {
	engine, burst := uiInteractionRateLimitEngine(t)
	require.Positive(t, burst, "a burst of zero would make this test pass without a limiter")

	for i := range burst {
		rec := postInteraction(engine)
		require.NotEqual(t, http.StatusTooManyRequests, rec.Code,
			"request %d of the burst was refused; the limit is below what a person doing this by hand would spend", i+1)
	}

	rec := postInteraction(engine)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code,
		"POST /ui/interaction authenticates no client and mints a session per call: past the burst it has to refuse")
}
