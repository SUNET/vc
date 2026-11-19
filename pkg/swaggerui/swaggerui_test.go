package swaggerui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/status"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSpec = `{"openapi":"3.1.0","info":{"title":"t","version":"1"},"paths":{}}`

func get(t *testing.T, target string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/swagger/*any", Handler([]byte(testSpec)))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, target, nil))
	return w
}

func TestServesSpecUnchanged(t *testing.T) {
	w := get(t, "/swagger/doc.json")

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, testSpec, w.Body.String())
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
}

func TestIndexAtRootAndByName(t *testing.T) {
	for _, target := range []string{"/swagger/", "/swagger/index.html"} {
		w := get(t, target)

		require.Equal(t, http.StatusOK, w.Code, target)
		assert.Contains(t, w.Header().Get("Content-Type"), "text/html", target)
		assert.Contains(t, w.Body.String(), "swagger-ui", target)
	}
}

func TestInitializerLoadsOurSpec(t *testing.T) {
	w := get(t, "/swagger/swagger-initializer.js")

	require.Equal(t, http.StatusOK, w.Code)
	assert.NotContains(t, w.Body.String(), "petstore.swagger.io")
	assert.Contains(t, w.Body.String(), `url: "doc.json"`)
}

func TestServesUIBundle(t *testing.T) {
	w := get(t, "/swagger/swagger-ui-bundle.js")

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "javascript")
	assert.NotEmpty(t, w.Body.Bytes())
}

func TestStampVersion(t *testing.T) {
	spec := `{"openapi":"3.1.0","info":{"title":"t","version":"dev"},"paths":{"/a":{}}}`

	out := stampVersion([]byte(spec), "v0.8.0")

	var doc struct {
		OpenAPI string `json:"openapi"`
		Info    struct {
			Title   string `json:"title"`
			Version string `json:"version"`
		} `json:"info"`
		Paths map[string]any `json:"paths"`
	}
	require.NoError(t, json.Unmarshal(out, &doc))
	assert.Equal(t, "v0.8.0", doc.Info.Version)
	assert.Equal(t, "t", doc.Info.Title, "other info fields survive")
	assert.Equal(t, "3.1.0", doc.OpenAPI)
	assert.Contains(t, doc.Paths, "/a")
}

func TestStampVersionLeavesSpecAloneWhen(t *testing.T) {
	spec := `{"info":{"version":"dev"}}`

	for name, tc := range map[string]struct{ spec, version string }{
		"version is unset":      {spec, ""},
		"version is undef":      {spec, "undef"},
		"spec is not JSON":      {"not json", "v1"},
		"spec has no info":      {`{"paths":{}}`, "v1"},
		"info is not an object": {`{"info":"x"}`, "v1"},
	} {
		assert.Equal(t, tc.spec, string(stampVersion([]byte(tc.spec), tc.version)), name)
	}
}

func TestHandlerServesBuildVersion(t *testing.T) {
	old := status.BuildVersion
	status.BuildVersion = "v9.9.9"
	t.Cleanup(func() { status.BuildVersion = old })

	w := get(t, "/swagger/doc.json")

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "v9.9.9", gjsonVersion(t, w.Body.Bytes()))
}

func gjsonVersion(t *testing.T, b []byte) string {
	t.Helper()
	var doc struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	require.NoError(t, json.Unmarshal(b, &doc))
	return doc.Info.Version
}

func TestUnknownAndTraversalAreNotFound(t *testing.T) {
	for _, target := range []string{"/swagger/nope.js", "/swagger/../go.mod", "/swagger/%2e%2e/go.mod"} {
		w := get(t, target)

		assert.NotEqual(t, http.StatusOK, w.Code, target)
		assert.False(t, strings.Contains(w.Body.String(), "module "), target)
	}
}
