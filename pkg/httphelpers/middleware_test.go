package httphelpers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SUNET/vc/pkg/model"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustomBranding_ServesCustomLogo(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	dir := t.TempDir()
	logoPath := filepath.Join(dir, "logo.png")
	require.NoError(t, os.WriteFile(logoPath, []byte("fake-logo"), 0644)) // #nosec G306

	branding := model.Branding{LogoPath: logoPath}
	handler := m.CustomBranding(branding)

	r := gin.New()
	r.Use(handler)
	r.GET("/static/logo.png", func(c *gin.Context) {
		c.String(http.StatusOK, "default-logo")
	})

	w := performRequest(r, "GET", "/static/logo.png", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "fake-logo", w.Body.String())
}

func TestCustomBranding_ServesCustomFavicon(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	dir := t.TempDir()
	faviconPath := filepath.Join(dir, "favicon.png")
	require.NoError(t, os.WriteFile(faviconPath, []byte("fake-favicon"), 0644)) // #nosec G306

	branding := model.Branding{FaviconPath: faviconPath}
	handler := m.CustomBranding(branding)

	r := gin.New()
	r.Use(handler)
	r.GET("/static/favicon.png", func(c *gin.Context) {
		c.String(http.StatusOK, "default-favicon")
	})

	w := performRequest(r, "GET", "/static/favicon.png", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "fake-favicon", w.Body.String())
}

func TestCustomBranding_FallsBackWhenPathEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	branding := model.Branding{} // no paths configured
	handler := m.CustomBranding(branding)

	r := gin.New()
	r.Use(handler)
	r.GET("/static/logo.png", func(c *gin.Context) {
		c.String(http.StatusOK, "default-logo")
	})

	w := performRequest(r, "GET", "/static/logo.png", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "default-logo", w.Body.String())
}

func TestCustomBranding_FallsBackWhenFileDoesNotExist(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	branding := model.Branding{LogoPath: "/nonexistent/logo.png"}
	handler := m.CustomBranding(branding)

	r := gin.New()
	r.Use(handler)
	r.GET("/static/logo.png", func(c *gin.Context) {
		c.String(http.StatusOK, "default-logo")
	})

	w := performRequest(r, "GET", "/static/logo.png", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "default-logo", w.Body.String())
}

func TestCustomBranding_FallsBackWhenPathIsDirectory(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	dir := t.TempDir()
	branding := model.Branding{LogoPath: dir}
	handler := m.CustomBranding(branding)

	r := gin.New()
	r.Use(handler)
	r.GET("/static/logo.png", func(c *gin.Context) {
		c.String(http.StatusOK, "default-logo")
	})

	w := performRequest(r, "GET", "/static/logo.png", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "default-logo", w.Body.String())
}

func TestCustomBranding_FallsBackWhenFileUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping: file permissions are not enforced when running as root")
	}
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	dir := t.TempDir()
	logoPath := filepath.Join(dir, "logo.png")
	require.NoError(t, os.WriteFile(logoPath, []byte("secret"), 0000))

	branding := model.Branding{LogoPath: logoPath}
	handler := m.CustomBranding(branding)

	r := gin.New()
	r.Use(handler)
	r.GET("/static/logo.png", func(c *gin.Context) {
		c.String(http.StatusOK, "default-logo")
	})

	w := performRequest(r, "GET", "/static/logo.png", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "default-logo", w.Body.String())
}

func TestCustomBranding_PassesThroughUnrelatedPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	dir := t.TempDir()
	logoPath := filepath.Join(dir, "logo.png")
	require.NoError(t, os.WriteFile(logoPath, []byte("fake-logo"), 0644)) // #nosec G306

	branding := model.Branding{LogoPath: logoPath}
	handler := m.CustomBranding(branding)

	r := gin.New()
	r.Use(handler)
	r.GET("/other", func(c *gin.Context) {
		c.String(http.StatusOK, "other-content")
	})

	w := performRequest(r, "GET", "/other", nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "other-content", w.Body.String())
}

// ---------- extractBodyResourcePairs tests ----------

func TestExtractBodyResourcePairs_TopLevel(t *testing.T) {
	body := []byte(`{"authentic_source":"SUNET","scope":"eduid"}`)
	pairs := extractBodyResourcePairs(body)
	require.Len(t, pairs, 1)
	assert.Equal(t, "SUNET", pairs[0].authenticSource)
	assert.Equal(t, "eduid", pairs[0].scope)
}

func TestExtractBodyResourcePairs_TopLevelNoScope(t *testing.T) {
	body := []byte(`{"authentic_source":"SUNET"}`)
	pairs := extractBodyResourcePairs(body)
	require.Len(t, pairs, 1)
	assert.Equal(t, "SUNET", pairs[0].authenticSource)
	assert.Equal(t, "", pairs[0].scope)
}

func TestExtractBodyResourcePairs_Meta(t *testing.T) {
	body := []byte(`{"meta":{"authentic_source":"LADOK","scope":"pid"}}`)
	pairs := extractBodyResourcePairs(body)
	require.Len(t, pairs, 1)
	assert.Equal(t, "LADOK", pairs[0].authenticSource)
	assert.Equal(t, "pid", pairs[0].scope)
}

func TestExtractBodyResourcePairs_NoFields(t *testing.T) {
	body := []byte(`{"name":"test","value":42}`)
	pairs := extractBodyResourcePairs(body)
	assert.Empty(t, pairs)
}

func TestExtractBodyResourcePairs_InvalidJSON(t *testing.T) {
	body := []byte(`not json`)
	pairs := extractBodyResourcePairs(body)
	assert.Nil(t, pairs)
}

func TestExtractBodyResourcePairs_Mappings(t *testing.T) {
	body := []byte(`{"mappings":{"0":{"authentic_source":"SUNET"},"1":{"authentic_source":"LADOK"}}}`)
	pairs := extractBodyResourcePairs(body)
	require.Len(t, pairs, 2)
	sources := []string{pairs[0].authenticSource, pairs[1].authenticSource}
	assert.ElementsMatch(t, []string{"SUNET", "LADOK"}, sources)
}

func TestExtractBodyResourcePairs_DocumentsMeta(t *testing.T) {
	body := []byte(`{"documents":{"doc1":{"meta":{"authentic_source":"SUNET","scope":"eduid"}},"doc2":{"meta":{"authentic_source":"LADOK","scope":"pid"}}}}`)
	pairs := extractBodyResourcePairs(body)
	require.Len(t, pairs, 2)
	sources := []string{pairs[0].authenticSource, pairs[1].authenticSource}
	assert.ElementsMatch(t, []string{"SUNET", "LADOK"}, sources)
}

func TestExtractBodyResourcePairs_TopLevelAndMeta(t *testing.T) {
	// Both top-level and meta present
	body := []byte(`{"authentic_source":"TOP","scope":"top_scope","meta":{"authentic_source":"META","scope":"meta_scope"}}`)
	pairs := extractBodyResourcePairs(body)
	require.Len(t, pairs, 2)
	assert.Equal(t, "TOP", pairs[0].authenticSource)
	assert.Equal(t, "top_scope", pairs[0].scope)
	assert.Equal(t, "META", pairs[1].authenticSource)
	assert.Equal(t, "meta_scope", pairs[1].scope)
}

func TestExtractBodyResourcePairs_EmptyBody(t *testing.T) {
	body := []byte(`{}`)
	pairs := extractBodyResourcePairs(body)
	assert.Empty(t, pairs)
}

// ---------- extractResourcePairs synthetic scope tests ----------

func TestExtractResourcePairs_IdentityMappingInjectsScope(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	var captured []resourcePair
	r.POST("/api/v1/identity/mapping", func(c *gin.Context) {
		captured = extractResourcePairs(c)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	body := `{"authentic_source":"SUNET"}`
	req := httptest.NewRequest("POST", "/api/v1/identity/mapping", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Len(t, captured, 1)
	assert.Equal(t, "SUNET", captured[0].authenticSource)
	assert.Equal(t, "identity_mapping", captured[0].scope, "scope should be injected for identity mapping endpoints")
}

func TestExtractResourcePairs_NonIdentityMapping_NoScopeInjection(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	var captured []resourcePair
	r.POST("/api/v1/datastore", func(c *gin.Context) {
		captured = extractResourcePairs(c)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	body := `{"authentic_source":"SUNET"}`
	req := httptest.NewRequest("POST", "/api/v1/datastore", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Len(t, captured, 1)
	assert.Equal(t, "SUNET", captured[0].authenticSource)
	assert.Equal(t, "", captured[0].scope, "scope should NOT be injected for non-identity-mapping endpoints")
}

func TestExtractResourcePairs_IdentityMappingWithExistingScope(t *testing.T) {
	// If someone sends a scope on an identity mapping path, don't overwrite.
	gin.SetMode(gin.TestMode)

	r := gin.New()
	var captured []resourcePair
	r.POST("/api/v1/identity/mapping", func(c *gin.Context) {
		captured = extractResourcePairs(c)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	body := `{"authentic_source":"SUNET","scope":"custom"}`
	req := httptest.NewRequest("POST", "/api/v1/identity/mapping", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Len(t, captured, 1)
	assert.Equal(t, "custom", captured[0].scope, "explicit scope should not be overwritten")
}

func TestExtractResourcePairs_QueryParams(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	var captured []resourcePair
	r.GET("/api/v1/datastore/search", func(c *gin.Context) {
		captured = extractResourcePairs(c)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest("GET", "/api/v1/datastore/search?authentic_source=SUNET&scope=eduid", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Len(t, captured, 1)
	assert.Equal(t, "SUNET", captured[0].authenticSource)
	assert.Equal(t, "eduid", captured[0].scope)
}

func TestExtractResourcePairs_IdentityMappingSearch_InjectsScope(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	var captured []resourcePair
	r.GET("/api/v1/identity/mapping/search", func(c *gin.Context) {
		captured = extractResourcePairs(c)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest("GET", "/api/v1/identity/mapping/search?authentic_source=SUNET", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	require.Len(t, captured, 1)
	assert.Equal(t, "SUNET", captured[0].authenticSource)
	assert.Equal(t, "identity_mapping", captured[0].scope)
}

// ---------- deduplicatePairs tests ----------

func TestDeduplicatePairs_NoDuplicates(t *testing.T) {
	pairs := []resourcePair{
		{authenticSource: "SUNET", scope: "eduid"},
		{authenticSource: "LADOK", scope: "pid"},
	}
	result := deduplicatePairs(pairs)
	assert.Len(t, result, 2)
}

func TestDeduplicatePairs_WithDuplicates(t *testing.T) {
	pairs := []resourcePair{
		{authenticSource: "SUNET", scope: "eduid"},
		{authenticSource: "SUNET", scope: "eduid"},
		{authenticSource: "LADOK", scope: "pid"},
	}
	result := deduplicatePairs(pairs)
	assert.Len(t, result, 2)
}

func TestDeduplicatePairs_Empty(t *testing.T) {
	result := deduplicatePairs(nil)
	assert.Nil(t, result)
}

func TestDeduplicatePairs_Single(t *testing.T) {
	pairs := []resourcePair{{authenticSource: "SUNET", scope: "eduid"}}
	result := deduplicatePairs(pairs)
	assert.Len(t, result, 1)
}

// ---------- jsonStringField tests ----------

func TestJsonStringField_Present(t *testing.T) {
	raw := map[string]json.RawMessage{
		"name": json.RawMessage(`"hello"`),
	}
	assert.Equal(t, "hello", jsonStringField(raw, "name"))
}

func TestJsonStringField_Absent(t *testing.T) {
	raw := map[string]json.RawMessage{}
	assert.Equal(t, "", jsonStringField(raw, "missing"))
}

func TestJsonStringField_NotString(t *testing.T) {
	raw := map[string]json.RawMessage{
		"count": json.RawMessage(`42`),
	}
	assert.Equal(t, "", jsonStringField(raw, "count"))
}
