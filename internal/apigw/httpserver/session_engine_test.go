package httpserver

import (
	"context"
	"testing"

	"github.com/SUNET/vc/pkg/httphelpers"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// newSessionTestEngine builds a Service against a mock Apiv1 and returns it
// with a gin engine and a route group already behind the same session
// middleware service.go puts these endpoints behind. The caller adds its own
// seeding middleware and registers the route it is testing.
//
// Shared because every session-backed endpoint test needs the same seven
// objects assembled the same way, and two copies of that assembly are two
// copies to keep in step with Service - and are counted as duplicated source.
func newSessionTestEngine(t *testing.T, mockAPI Apiv1) (*Service, *gin.Engine, *gin.RouterGroup) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	cfg := &model.Cfg{Common: &model.Common{}, APIGW: &model.APIGW{}}
	helpers, err := httphelpers.New(ctx, tracer, cfg, log)
	require.NoError(t, err)

	s := &Service{
		cfg:         cfg,
		log:         log.New("httpserver"),
		apiv1:       mockAPI,
		tracer:      tracer,
		httpHelpers: helpers,
	}

	engine := gin.New()
	rg := engine.Group("")
	rg.Use(helpers.Middleware.UserSession("test_session",
		"0123456789abcdef0123456789abcdef", "0123456789abcdef", sessions.Options{Path: "/"}))

	return s, engine, rg
}

// seedSession returns middleware that writes fixed values into the session, so
// a test can stand in for whatever earlier step in the flow put them there.
func seedSession(values map[string]any) gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		for key, value := range values {
			session.Set(key, value)
		}
		_ = session.Save()
		c.Next()
	}
}
