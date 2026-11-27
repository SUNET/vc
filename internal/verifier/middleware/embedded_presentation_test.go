package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SUNET/vc/pkg/helpers"
	"github.com/SUNET/vc/pkg/model"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rpOrigin = "https://rp.example.com"

// engineWithEmbeddedCORS builds a server shaped like the verifier's: the CORS
// handler at engine level, the flow's endpoints registered, and a NoRoute
// handler. The last matters - a preflight for a path with no OPTIONS route
// lands there, and that is exactly where a group-scoped CORS handler would
// never run.
func engineWithEmbeddedCORS(t *testing.T, cfg *model.EmbeddedPresentationConfig) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	handler, err := EmbeddedPresentationCORS(cfg)
	require.NoError(t, err)

	engine := gin.New()
	engine.NoRoute(func(c *gin.Context) { c.Status(http.StatusNotFound) })
	if handler != nil {
		engine.Use(handler)
	}
	for path := range EmbeddedPresentationPaths {
		engine.GET(path, func(c *gin.Context) { c.Status(http.StatusOK) })
		engine.POST(path, func(c *gin.Context) { c.Status(http.StatusOK) })
	}
	engine.POST("/token", func(c *gin.Context) { c.Status(http.StatusOK) })
	engine.GET("/ui/metadata", func(c *gin.Context) { c.Status(http.StatusOK) })
	engine.GET("/ui/resume", func(c *gin.Context) { c.Status(http.StatusOK) })

	return engine
}

func requestOrigin(engine *gin.Engine, method, path, origin string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Origin", origin)
	if method == http.MethodOptions {
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	return rec
}

func TestEmbeddedPresentationCORSOmittedOrDisabled(t *testing.T) {
	for name, cfg := range map[string]*model.EmbeddedPresentationConfig{
		"omitted":  nil,
		"disabled": {Enable: false, AllowedOrigins: []string{rpOrigin}},
	} {
		t.Run(name, func(t *testing.T) {
			handler, err := EmbeddedPresentationCORS(cfg)
			require.NoError(t, err)
			assert.Nil(t, handler, "no handler is installed when the feature is off")

			engine := engineWithEmbeddedCORS(t, cfg)
			rec := requestOrigin(engine, http.MethodPost, "/ui/interaction", rpOrigin)
			assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"),
				"a disabled deployment answers no cross-origin request")
		})
	}
}

func TestEmbeddedPresentationCORSEnabledWithoutOriginsIsRefused(t *testing.T) {
	handler, err := EmbeddedPresentationCORS(&model.EmbeddedPresentationConfig{Enable: true})
	require.Error(t, err, "enabling without an origin allows nothing and must not start")
	assert.Nil(t, handler)
	assert.Contains(t, err.Error(), "allowed_origins")
}

func TestEmbeddedPresentationCORSOpensExactlyTheFlowsPaths(t *testing.T) {
	engine := engineWithEmbeddedCORS(t, &model.EmbeddedPresentationConfig{
		Enable:         true,
		AllowedOrigins: []string{rpOrigin},
	})

	for path := range EmbeddedPresentationPaths {
		t.Run("open"+path, func(t *testing.T) {
			rec := requestOrigin(engine, http.MethodGet, path, rpOrigin)
			assert.Equal(t, rpOrigin, rec.Header().Get("Access-Control-Allow-Origin"))
		})
	}

	// Every other route is left as it was. /token in particular is what
	// api_server.cors would also have opened, and is why this key exists
	// separately from it.
	for _, path := range []string{"/token", "/ui/metadata", "/ui/resume"} {
		t.Run("closed"+path, func(t *testing.T) {
			rec := requestOrigin(engine, http.MethodGet, path, rpOrigin)
			assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}

func TestEmbeddedPresentationCORSRefusesAnUnlistedOrigin(t *testing.T) {
	engine := engineWithEmbeddedCORS(t, &model.EmbeddedPresentationConfig{
		Enable:         true,
		AllowedOrigins: []string{rpOrigin},
	})

	rec := requestOrigin(engine, http.MethodPost, "/ui/interaction", "https://attacker.example.net")
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestEmbeddedPresentationCORSAnswersPreflight(t *testing.T) {
	engine := engineWithEmbeddedCORS(t, &model.EmbeddedPresentationConfig{
		Enable:         true,
		AllowedOrigins: []string{rpOrigin},
	})

	rec := requestOrigin(engine, http.MethodOptions, "/ui/interaction", rpOrigin)
	assert.Equal(t, http.StatusNoContent, rec.Code,
		"the preflight has no OPTIONS route of its own and must still be answered, not 404'd")
	assert.Equal(t, rpOrigin, rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), http.MethodPost)
}

func TestEmbeddedPresentationCORSSendsNoCredentials(t *testing.T) {
	engine := engineWithEmbeddedCORS(t, &model.EmbeddedPresentationConfig{
		Enable:         true,
		AllowedOrigins: []string{rpOrigin},
	})

	// The flow passes its session id explicitly, so the embedded page has no
	// use for verifier_user_session - and must not be able to spend one.
	rec := requestOrigin(engine, http.MethodPost, "/ui/interaction", rpOrigin)
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
}

// TestEmbeddedPresentationConfigValidationRejectsEnableWithoutOrigins pins the
// struct tag as well as the startup check above. Both exist on purpose: the
// tag refuses the file, the check refuses a configuration reaching the server
// by any other path, and a tag that silently validated nothing would leave
// only the second.
func TestEmbeddedPresentationConfigValidationRejectsEnableWithoutOrigins(t *testing.T) {
	err := helpers.CheckSimple(&model.EmbeddedPresentationConfig{Enable: true})
	require.Error(t, err, "a file that enables the feature without an origin must not load")
	assert.Contains(t, err.Error(), "allowed_origins")

	require.NoError(t, helpers.CheckSimple(
		&model.EmbeddedPresentationConfig{Enable: true, AllowedOrigins: []string{rpOrigin}}))
	require.NoError(t, helpers.CheckSimple(&model.EmbeddedPresentationConfig{}),
		"the default, off, carries no requirement")
}
