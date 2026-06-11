package httphelpers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/sirosfoundation/go-spocp/pkg/sexp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------- helpers ----------

// stubCache is a simple in-memory JWKSCache for tests.
type stubCache struct {
	store map[string][]byte
}

func newStubCache() *stubCache {
	return &stubCache{store: make(map[string][]byte)}
}

func (c *stubCache) Get(_ context.Context, key string) ([]byte, bool) {
	v, ok := c.store[key]
	return v, ok
}

func (c *stubCache) Set(_ context.Context, key string, value []byte) {
	c.store[key] = value
}

// testKeyPair generates an ECDSA P-256 key pair and returns the private key
// and a JWK Set containing the public key.
func testKeyPair(t *testing.T) (*ecdsa.PrivateKey, jwk.Set) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubJWK, err := jwk.Import(priv.Public())
	require.NoError(t, err)

	require.NoError(t, pubJWK.Set(jwk.KeyIDKey, "test-kid"))
	require.NoError(t, pubJWK.Set(jwk.AlgorithmKey, jwa.ES256()))

	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pubJWK))

	return priv, set
}

// signJWT creates a signed JWT string with the given claims.
func signJWT(t *testing.T, priv *ecdsa.PrivateKey, sub, iss, aud string) string {
	t.Helper()

	privJWK, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, privJWK.Set(jwk.KeyIDKey, "test-kid"))
	require.NoError(t, privJWK.Set(jwk.AlgorithmKey, jwa.ES256()))

	tok, err := jwt.NewBuilder().
		Subject(sub).
		Issuer(iss).
		Audience([]string{aud}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5 * time.Minute)).
		Build()
	require.NoError(t, err)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), privJWK))
	require.NoError(t, err)

	return string(signed)
}

// signJWTWithEPPN creates a signed JWT that includes the eppn claim used by
// extractSPOCPSubject to identify the user in SPOCP rules.
func signJWTWithEPPN(t *testing.T, priv *ecdsa.PrivateKey, eppn, iss, aud string) string {
	t.Helper()

	privJWK, err := jwk.Import(priv)
	require.NoError(t, err)
	require.NoError(t, privJWK.Set(jwk.KeyIDKey, "test-kid"))
	require.NoError(t, privJWK.Set(jwk.AlgorithmKey, jwa.ES256()))

	tok, err := jwt.NewBuilder().
		Subject("opaque-sub-id").
		Issuer(iss).
		Audience([]string{aud}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(5*time.Minute)).
		Claim("eppn", eppn).
		Build()
	require.NoError(t, err)

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), privJWK))
	require.NoError(t, err)

	return string(signed)
}

// newTestMiddleware creates a middlewareHandler suitable for unit tests.
func newTestMiddleware(t *testing.T) *middlewareHandler {
	t.Helper()
	log, err := logger.New("test", "", false)
	require.NoError(t, err)

	ctx := context.Background()
	tracer, err := trace.NewForTesting(ctx, "test", log)
	require.NoError(t, err)

	client := &Client{
		tracer: tracer,
		log:    log,
	}
	return &middlewareHandler{client: client, log: log}
}

// jwksServer starts an httptest server that serves the given key set as JSON.
// The cache is pre-seeded so the middleware never actually needs the server, but
// we return it in case tests want to verify a cold-cache fetch.
func jwksServer(t *testing.T, set jwk.Set) (*httptest.Server, *stubCache) {
	t.Helper()

	raw, err := json.Marshal(set)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw) // #nosec G104
	}))
	t.Cleanup(srv.Close)

	cache := newStubCache()
	cache.Set(context.Background(), srv.URL, raw)

	return srv, cache
}

// performRequest executes a single request through the gin engine and returns
// the recorded response.
func performRequest(r *gin.Engine, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// ---------- buildSPOCPEngine tests ----------

func TestBuildSPOCPEngine_NoRules(t *testing.T) {
	engine, err := BuildSPOCPEngine(model.APIAuth{})
	assert.NoError(t, err)
	assert.Nil(t, engine, "should return nil when no rules configured")
}

func TestBuildSPOCPEngine_InlineRules(t *testing.T) {
	cfg := model.APIAuth{
		Rules: []string{
			"(vc (service test-svc)(method POST)(path /api/v1/upload)(subject alice)(authentic_source SUNET)(scope eduid))",
			"(vc (service test-svc)(method *)(path /api/v1/document)(subject *)(authentic_source *)(scope *))",
		},
	}

	engine, err := BuildSPOCPEngine(cfg)
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Equal(t, 2, engine.RuleCount())
}

func TestBuildSPOCPEngine_InvalidRule(t *testing.T) {
	cfg := model.APIAuth{
		Rules: []string{"not a valid s-expression"},
	}

	_, err := BuildSPOCPEngine(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid inline SPOCP rule #1")
}

func TestBuildSPOCPEngine_MissingRequiredParts(t *testing.T) {
	// Rule with only the 4 original parts; missing authentic_source and scope.
	cfg := model.APIAuth{
		Rules: []string{"(vc (service svc)(method GET)(path /api)(subject alice))"},
	}

	_, err := BuildSPOCPEngine(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "authentic_source")
	assert.Contains(t, err.Error(), "scope")
}

func TestBuildSPOCPEngine_EmptyRequiredParts(t *testing.T) {
	// All required parts present, but scope is empty (no elements).
	cfg := model.APIAuth{
		Rules: []string{"(vc (service svc)(method GET)(path /api)(subject alice)(authentic_source SUNET)(scope))"},
	}

	_, err := BuildSPOCPEngine(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty required parts")
	assert.Contains(t, err.Error(), "scope")
}

func TestBuildSPOCPEngine_RulesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.spocp")
	content := "(vc (service test-svc)(method GET)(path /health)(subject *)(authentic_source *)(scope *))\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) // #nosec G306

	cfg := model.APIAuth{
		RulesFile: path,
	}

	engine, err := BuildSPOCPEngine(cfg)
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Equal(t, 1, engine.RuleCount())
}

func TestBuildSPOCPEngine_RulesFileMissing(t *testing.T) {
	cfg := model.APIAuth{
		RulesFile: "/nonexistent/rules.spocp",
	}

	_, err := BuildSPOCPEngine(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load SPOCP rules")
}

func TestBuildSPOCPEngine_InlineAndFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.spocp")
	content := "(vc (service test-svc)(method DELETE)(path /api/v1/document)(subject admin)(authentic_source *)(scope *))\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) // #nosec G306

	cfg := model.APIAuth{
		Rules:     []string{"(vc (service test-svc)(method POST)(path /api/v1/upload)(subject alice)(authentic_source SUNET)(scope eduid))"},
		RulesFile: path,
	}

	engine, err := BuildSPOCPEngine(cfg)
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Equal(t, 2, engine.RuleCount())
}

// ---------- buildAPISPOCPQuery tests ----------

func TestBuildAPISPOCPQuery(t *testing.T) {
	q := BuildSPOCPQuery("test-svc", "POST", "/api/v1/upload", "alice", "", "")
	assert.NotNil(t, q)
	// All 6 fields are always present in the query.
	s := q.String()
	assert.Contains(t, s, "service")
	assert.Contains(t, s, "test-svc")
	assert.Contains(t, s, "method")
	assert.Contains(t, s, "POST")
	assert.Contains(t, s, "path")
	assert.Contains(t, s, "/api/v1/upload")
	assert.Contains(t, s, "subject")
	assert.Contains(t, s, "alice")
	assert.Contains(t, s, "authentic_source")
	assert.Contains(t, s, "scope")
}

func TestBuildAPISPOCPQuery_WithResourceFields(t *testing.T) {
	q := BuildSPOCPQuery("test-svc", "POST", "/api/v1/upload", "alice", "SUNET", "eduid")
	s := q.String()
	assert.Contains(t, s, "authentic_source")
	assert.Contains(t, s, "SUNET")
	assert.Contains(t, s, "scope")
	assert.Contains(t, s, "eduid")
}

// ---------- SPOCP authorization via JWTAuth middleware ----------

// Note: With the unified SPOCP model, rules without authentic_source/scope
// (4-element rules) cannot grant resource access but requests without
// resource pairs still pass through. These tests verify the auth flow with
// full 6-element rules using signJWTWithEPPN (which sets the eppn claim).

func TestJWTAuth_SPOCPAllowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	jwksCfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}
	authCfg := model.APIAuth{
		Rules: []string{
			"(vc (service test-svc)(method POST)(path /api/v1/upload)(subject alice@test)(authentic_source SUNET)(scope eduid))",
		},
	}

	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.POST("/api/v1/upload", handler, okHandler)

	// Request with matching resource pair → allowed
	token := signJWTWithEPPN(t, priv, "alice@test", "test-issuer", "test-aud")
	body := `{"authentic_source":"SUNET","scope":"eduid"}`
	req := httptest.NewRequest("POST", "/api/v1/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestJWTAuth_SPOCPDenied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	jwksCfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}
	authCfg := model.APIAuth{
		Rules: []string{
			"(vc (service test-svc)(method POST)(path /api/v1/upload)(subject alice@test)(authentic_source SUNET)(scope eduid))",
		},
	}

	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.POST("/api/v1/upload", handler, okHandler)

	// bob is not authorized
	token := signJWTWithEPPN(t, priv, "bob@test", "test-issuer", "test-aud")
	body := `{"authentic_source":"SUNET","scope":"eduid"}`
	req := httptest.NewRequest("POST", "/api/v1/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "insufficient permissions")
}

func TestJWTAuth_SPOCPWildcardSubject(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	jwksCfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}
	authCfg := model.APIAuth{
		Rules: []string{
			"(vc (service test-svc)(method POST)(path /api/v1/document)(subject *)(authentic_source *)(scope *))",
		},
	}

	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.POST("/api/v1/document", handler, okHandler)

	for _, sub := range []string{"alice@test", "bob@test", "charlie@test"} {
		token := signJWTWithEPPN(t, priv, sub, "test-issuer", "test-aud")
		body := `{"authentic_source":"ANY","scope":"any"}`
		req := httptest.NewRequest("POST", "/api/v1/document", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "subject %s should be allowed", sub)
	}
}

func TestJWTAuth_SPOCPWildcardMethod(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	jwksCfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}
	authCfg := model.APIAuth{
		Rules: []string{
			"(vc (service test-svc)(method *)(path /api/v1/upload)(subject alice@test)(authentic_source SUNET)(scope eduid))",
		},
	}

	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.POST("/api/v1/upload", handler, okHandler)
	r.PUT("/api/v1/upload", handler, okHandler)
	r.DELETE("/api/v1/upload", handler, okHandler)

	token := signJWTWithEPPN(t, priv, "alice@test", "test-issuer", "test-aud")
	for _, method := range []string{"POST", "PUT", "DELETE"} {
		body := `{"authentic_source":"SUNET","scope":"eduid"}`
		req := httptest.NewRequest(method, "/api/v1/upload", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "method %s should be allowed", method)
	}
}

func TestJWTAuth_SPOCPPrefixPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	jwksCfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}
	authCfg := model.APIAuth{
		Rules: []string{
			"(vc (service test-svc)(method *)(path /api/v1/*)(subject alice@test)(authentic_source SUNET)(scope eduid))",
		},
	}

	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.POST("/api/v1/upload", handler, okHandler)
	r.POST("/api/v1/document", handler, okHandler)

	token := signJWTWithEPPN(t, priv, "alice@test", "test-issuer", "test-aud")
	for _, path := range []string{"/api/v1/upload", "/api/v1/document"} {
		body := `{"authentic_source":"SUNET","scope":"eduid"}`
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "path %s should be allowed", path)
	}
}

func TestJWTAuth_SPOCPMultipleRules(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	jwksCfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}
	authCfg := model.APIAuth{
		Rules: []string{
			"(vc (service test-svc)(method POST)(path /api/v1/upload)(subject alice@test)(authentic_source SUNET)(scope eduid))",
			"(vc (service test-svc)(method POST)(path /api/v1/document)(subject bob@test)(authentic_source LADOK)(scope pid))",
		},
	}

	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.POST("/api/v1/upload", handler, okHandler)
	r.POST("/api/v1/document", handler, okHandler)

	tests := []struct {
		name       string
		subject    string
		path       string
		body       string
		wantStatus int
	}{
		{"alice upload SUNET/eduid", "alice@test", "/api/v1/upload", `{"authentic_source":"SUNET","scope":"eduid"}`, http.StatusOK},
		{"bob document LADOK/pid", "bob@test", "/api/v1/document", `{"authentic_source":"LADOK","scope":"pid"}`, http.StatusOK},
		{"alice wrong scope", "alice@test", "/api/v1/upload", `{"authentic_source":"SUNET","scope":"pid"}`, http.StatusForbidden},
		{"bob wrong path", "bob@test", "/api/v1/upload", `{"authentic_source":"LADOK","scope":"pid"}`, http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := signJWTWithEPPN(t, priv, tc.subject, "test-issuer", "test-aud")
			req := httptest.NewRequest("POST", tc.path, strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

func TestJWTAuth_NoSPOCPRules_AnyValidJWTPasses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	cfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
		// No rules → authn only, no authz
	}

	handler := m.JWKSAuth(context.Background(), "test-svc", cfg, cache, nil)

	r := gin.New()
	r.POST("/api/v1/anything", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"sub": c.GetString("jwt_subject")})
	})

	token := signJWT(t, priv, "anyone", "test-issuer", "test-aud")
	w := performRequest(r, "POST", "/api/v1/anything", map[string]string{
		"Authorization": "Bearer " + token,
	})
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestJWTAuth_MissingAuthHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	_, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	cfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}

	handler := m.JWKSAuth(context.Background(), "test-svc", cfg, cache, nil)

	r := gin.New()
	r.POST("/api/v1/upload", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := performRequest(r, "POST", "/api/v1/upload", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "missing authorization header")
}

func TestJWTAuth_InvalidBearerFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	_, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	cfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}

	handler := m.JWKSAuth(context.Background(), "test-svc", cfg, cache, nil)

	r := gin.New()
	r.POST("/api/v1/upload", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := performRequest(r, "POST", "/api/v1/upload", map[string]string{
		"Authorization": "Basic dXNlcjpwYXNz",
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "expected Bearer token")
}

func TestJWTAuth_InvalidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	_, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	cfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}

	handler := m.JWKSAuth(context.Background(), "test-svc", cfg, cache, nil)

	r := gin.New()
	r.POST("/api/v1/upload", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := performRequest(r, "POST", "/api/v1/upload", map[string]string{
		"Authorization": "Bearer invalid.jwt.token",
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid or expired token")
}

func TestJWTAuth_WrongIssuer(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	cfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "expected-issuer",
		Audience: "test-aud",
	}

	handler := m.JWKSAuth(context.Background(), "test-svc", cfg, cache, nil)

	r := gin.New()
	r.POST("/api/v1/upload", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Token with wrong issuer
	token := signJWT(t, priv, "alice", "wrong-issuer", "test-aud")
	w := performRequest(r, "POST", "/api/v1/upload", map[string]string{
		"Authorization": "Bearer " + token,
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuth_WrongAudience(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	cfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "expected-aud",
	}

	handler := m.JWKSAuth(context.Background(), "test-svc", cfg, cache, nil)

	r := gin.New()
	r.POST("/api/v1/upload", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Token with wrong audience
	token := signJWT(t, priv, "alice", "test-issuer", "wrong-aud")
	w := performRequest(r, "POST", "/api/v1/upload", map[string]string{
		"Authorization": "Bearer " + token,
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuth_SetsContextValues(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	cfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}

	handler := m.JWKSAuth(context.Background(), "test-svc", cfg, cache, nil)

	var capturedSubject string
	var capturedClaims any

	r := gin.New()
	r.POST("/api/v1/test", handler, func(c *gin.Context) {
		capturedSubject = c.GetString("jwt_subject")
		capturedClaims, _ = c.Get("jwt_claims")
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	token := signJWTWithEPPN(t, priv, "alice@test", "test-issuer", "test-aud")
	w := performRequest(r, "POST", "/api/v1/test", map[string]string{
		"Authorization": "Bearer " + token,
	})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "alice@test", capturedSubject)
	assert.NotNil(t, capturedClaims)
}

// ---------- APIAuth dispatcher tests ----------

func TestAPIAuth_NoneMode(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	apiAuth := model.APIAuth{} // both disabled

	handler, err := m.APIAuth(context.Background(), "test-svc", apiAuth, nil)
	require.NoError(t, err)

	r := gin.New()
	r.POST("/api/v1/test", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := performRequest(r, "POST", "/api/v1/test", nil)
	assert.Equal(t, http.StatusOK, w.Code, "no auth = open access")
}

func TestAPIAuth_JWTWithoutCacheReturnsError(t *testing.T) {
	m := newTestMiddleware(t)

	apiAuth := model.APIAuth{
		JWKS: model.APIAuthJWKS{
			Enable:  true,
			JWKSURL: "https://example.com/.well-known/jwks.json",
		},
	}

	_, err := m.APIAuth(context.Background(), "test-svc", apiAuth, nil)
	assert.Error(t, err, "should return error when JWKS enabled but no cache provided")
}

// ---------- SPOCP rules file via APIAuth ----------

func TestAPIAuth_JWTWithSPOCPRulesFile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	// Write rules to temp file
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.spocp")
	rules := "(vc (service test-svc)(method POST)(path /api/v1/upload)(subject alice@test)(authentic_source SUNET)(scope eduid))\n"
	require.NoError(t, os.WriteFile(rulesPath, []byte(rules), 0o644)) // #nosec G306

	apiAuth := model.APIAuth{
		JWKS: model.APIAuthJWKS{
			Enable:   true,
			JWKSURL:  srv.URL,
			Issuer:   "test-issuer",
			Audience: "test-aud",
		},
		RulesFile: rulesPath,
	}

	handler, err := m.APIAuth(context.Background(), "test-svc", apiAuth, cache)
	require.NoError(t, err)

	r := gin.New()
	r.POST("/api/v1/upload", handler, okHandler)

	// alice with matching resource pair: allowed
	body := `{"authentic_source":"SUNET","scope":"eduid"}`
	req := httptest.NewRequest("POST", "/api/v1/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+signJWTWithEPPN(t, priv, "alice@test", "test-issuer", "test-aud"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// bob with same resource pair: denied
	req = httptest.NewRequest("POST", "/api/v1/upload", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+signJWTWithEPPN(t, priv, "bob@test", "test-issuer", "test-aud"))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ---------- loadRulesFromFile tests ----------

func TestLoadRulesFromFile_MultipleRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.spocp")
	content := `(vc (service test-svc)(method GET)(path /health)(subject *)(authentic_source *)(scope *))
(vc (service test-svc)(method POST)(path /api/v1/upload)(subject alice)(authentic_source SUNET)(scope eduid))
(vc (service test-svc)(method DELETE)(path /api/v1/document)(subject admin)(authentic_source *)(scope *))
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) // #nosec G306

	cfg := model.APIAuth{RulesFile: path}
	engine, err := BuildSPOCPEngine(cfg)
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Equal(t, 3, engine.RuleCount())
}

func TestLoadRulesFromFile_BlankLinesAndComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.spocp")
	content := `# This is a comment
(vc (service test-svc)(method GET)(path /health)(subject *)(authentic_source *)(scope *))

# Another comment

(vc (service test-svc)(method POST)(path /api/v1/upload)(subject alice)(authentic_source SUNET)(scope eduid))

# trailing comment
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) // #nosec G306

	cfg := model.APIAuth{RulesFile: path}
	engine, err := BuildSPOCPEngine(cfg)
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Equal(t, 2, engine.RuleCount(), "only non-comment, non-blank lines count")
}

func TestLoadRulesFromFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.spocp")
	require.NoError(t, os.WriteFile(path, []byte(""), 0o644)) // #nosec G306

	cfg := model.APIAuth{RulesFile: path}
	engine, err := BuildSPOCPEngine(cfg)
	require.NoError(t, err)
	// Engine is created (file path was configured) but has no rules.
	require.NotNil(t, engine)
	assert.Equal(t, 0, engine.RuleCount())
}

func TestLoadRulesFromFile_CommentsOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.spocp")
	content := `# comment one
# comment two
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) // #nosec G306

	cfg := model.APIAuth{RulesFile: path}
	engine, err := BuildSPOCPEngine(cfg)
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Equal(t, 0, engine.RuleCount())
}

func TestLoadRulesFromFile_InvalidLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.spocp")
	content := `(vc (service test-svc)(method GET)(path /health)(subject *)(authentic_source *)(scope *))
this is not valid
(vc (service test-svc)(method POST)(path /upload)(subject bob)(authentic_source *)(scope *))
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) // #nosec G306

	cfg := model.APIAuth{RulesFile: path}
	_, err := BuildSPOCPEngine(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line 2")
}

func TestLoadRulesFromFile_StarForms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.spocp")
	content := `# Wildcard subject
(vc (service test-svc)(method GET)(path /api/v1/status)(subject *)(authentic_source *)(scope *))
# Prefix path
(vc (service test-svc)(method *)(path (* prefix /api/v1/))(subject alice)(authentic_source *)(scope *))
# Suffix path
(vc (service test-svc)(method GET)(path (* suffix .json))(subject bob)(authentic_source *)(scope *))
# Set of methods
(vc (service test-svc)(method (* set GET POST))(path /api/v1/items)(subject charlie)(authentic_source *)(scope *))
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644)) // #nosec G306

	cfg := model.APIAuth{RulesFile: path}
	engine, err := BuildSPOCPEngine(cfg)
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Equal(t, 4, engine.RuleCount())
}

// ---------- End-to-end rule-file authorization tests ----------

func TestRulesFile_E2E_MultipleUsersAndPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.spocp")
	rules := `# alice may upload, bob may read documents, admin can do everything under /api/v1/
(vc (service test-svc)(method POST)(path /api/v1/upload)(subject alice@test)(authentic_source SUNET)(scope eduid))
(vc (service test-svc)(method GET)(path /api/v1/document)(subject bob@test)(authentic_source LADOK)(scope pid))
(vc (service test-svc)(method *)(path (* prefix /api/v1/))(subject admin@test)(authentic_source *)(scope *))
`
	require.NoError(t, os.WriteFile(rulesPath, []byte(rules), 0o644)) // #nosec G306

	jwksCfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}
	authCfg := model.APIAuth{RulesFile: rulesPath}
	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.POST("/api/v1/upload", handler, okHandler)
	r.GET("/api/v1/document", handler, okHandler)
	r.DELETE("/api/v1/document", handler, okHandler)

	tests := []struct {
		name       string
		method     string
		path       string
		subject    string
		body       string
		wantStatus int
	}{
		{"alice POST upload → OK", "POST", "/api/v1/upload", "alice@test", `{"authentic_source":"SUNET","scope":"eduid"}`, http.StatusOK},
		{"alice GET document → denied", "GET", "/api/v1/document", "alice@test", `{"authentic_source":"LADOK","scope":"pid"}`, http.StatusForbidden},
		{"bob GET document → OK", "GET", "/api/v1/document", "bob@test", `{"authentic_source":"LADOK","scope":"pid"}`, http.StatusOK},
		{"bob POST upload → denied", "POST", "/api/v1/upload", "bob@test", `{"authentic_source":"SUNET","scope":"eduid"}`, http.StatusForbidden},
		{"admin POST upload → OK (prefix)", "POST", "/api/v1/upload", "admin@test", `{"authentic_source":"SUNET","scope":"eduid"}`, http.StatusOK},
		{"admin GET document → OK (prefix)", "GET", "/api/v1/document", "admin@test", `{"authentic_source":"LADOK","scope":"pid"}`, http.StatusOK},
		{"admin DELETE document → OK (prefix)", "DELETE", "/api/v1/document", "admin@test", `{"authentic_source":"LADOK","scope":"pid"}`, http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := signJWTWithEPPN(t, priv, tc.subject, "test-issuer", "test-aud")
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

func TestRulesFile_E2E_WildcardSubject(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.spocp")
	rules := "# Any authenticated user can GET /api/v1/public with any resource\n(vc (service test-svc)(method GET)(path /api/v1/public)(subject *)(authentic_source *)(scope *))\n"
	require.NoError(t, os.WriteFile(rulesPath, []byte(rules), 0o644)) // #nosec G306

	jwksCfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}
	authCfg := model.APIAuth{RulesFile: rulesPath}
	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.GET("/api/v1/public", handler, okHandler)
	r.POST("/api/v1/public", handler, okHandler)

	body := `{"authentic_source":"ANY","scope":"any"}`
	for _, sub := range []string{"alice@test", "bob@test", "stranger@test"} {
		t.Run("GET "+sub+" allowed", func(t *testing.T) {
			token := signJWTWithEPPN(t, priv, sub, "test-issuer", "test-aud")
			req := httptest.NewRequest("GET", "/api/v1/public", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		})
		t.Run("POST "+sub+" denied", func(t *testing.T) {
			token := signJWTWithEPPN(t, priv, sub, "test-issuer", "test-aud")
			req := httptest.NewRequest("POST", "/api/v1/public", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusForbidden, w.Code)
		})
	}
}

func TestRulesFile_E2E_SuffixPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.spocp")
	rules := "# alice can GET any .json path\n(vc (service test-svc)(method GET)(path (* suffix .json))(subject alice@test)(authentic_source *)(scope *))\n"
	require.NoError(t, os.WriteFile(rulesPath, []byte(rules), 0o644)) // #nosec G306

	jwksCfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}
	authCfg := model.APIAuth{RulesFile: rulesPath}
	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.GET("/api/v1/config.json", handler, okHandler)
	r.GET("/api/v1/config.yaml", handler, okHandler)

	body := `{"authentic_source":"X","scope":"y"}`
	token := signJWTWithEPPN(t, priv, "alice@test", "test-issuer", "test-aud")

	// .json suffix → allowed
	req := httptest.NewRequest("GET", "/api/v1/config.json", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// .yaml suffix → denied
	req = httptest.NewRequest("GET", "/api/v1/config.yaml", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRulesFile_E2E_MethodSet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.spocp")
	rules := "# alice may GET or POST but not DELETE on /api/v1/items\n(vc (service test-svc)(method (* set GET POST))(path /api/v1/items)(subject alice@test)(authentic_source *)(scope *))\n"
	require.NoError(t, os.WriteFile(rulesPath, []byte(rules), 0o644)) // #nosec G306

	jwksCfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}
	authCfg := model.APIAuth{RulesFile: rulesPath}
	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.GET("/api/v1/items", handler, okHandler)
	r.POST("/api/v1/items", handler, okHandler)
	r.DELETE("/api/v1/items", handler, okHandler)

	body := `{"authentic_source":"X","scope":"y"}`
	token := signJWTWithEPPN(t, priv, "alice@test", "test-issuer", "test-aud")

	tests := []struct {
		method     string
		wantStatus int
	}{
		{"GET", http.StatusOK},
		{"POST", http.StatusOK},
		{"DELETE", http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.method, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/v1/items", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

func TestRulesFile_E2E_InlinePlusFile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.spocp")
	fileRules := "(vc (service test-svc)(method DELETE)(path /api/v1/document)(subject admin@test)(authentic_source *)(scope *))\n"
	require.NoError(t, os.WriteFile(rulesPath, []byte(fileRules), 0o644)) // #nosec G306

	jwksCfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}
	authCfg := model.APIAuth{
		Rules: []string{
			"(vc (service test-svc)(method POST)(path /api/v1/upload)(subject alice@test)(authentic_source *)(scope *))",
		},
		RulesFile: rulesPath,
	}
	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)
	require.Equal(t, 2, engine.RuleCount())

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.POST("/api/v1/upload", handler, okHandler)
	r.DELETE("/api/v1/document", handler, okHandler)

	body := `{"authentic_source":"X","scope":"y"}`
	tests := []struct {
		name       string
		method     string
		path       string
		subject    string
		wantStatus int
	}{
		{"alice upload (inline rule)", "POST", "/api/v1/upload", "alice@test", http.StatusOK},
		{"admin delete (file rule)", "DELETE", "/api/v1/document", "admin@test", http.StatusOK},
		{"alice delete → denied", "DELETE", "/api/v1/document", "alice@test", http.StatusForbidden},
		{"admin upload → denied", "POST", "/api/v1/upload", "admin@test", http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := signJWTWithEPPN(t, priv, tc.subject, "test-issuer", "test-aud")
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

// okHandler is a trivial gin handler that returns 200 {"ok":true}.
func okHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ---------- extractListValues tests ----------

func TestExtractListValues_Atom(t *testing.T) {
	elem := parseAdvancedSExpT(t, "(scope eduid)")
	vals := extractListValues(elem)
	assert.Equal(t, []string{"eduid"}, vals)
}

func TestExtractListValues_Wildcard(t *testing.T) {
	elem := parseAdvancedSExpT(t, "(scope *)")
	vals := extractListValues(elem)
	assert.Equal(t, []string{"*"}, vals)
}

func TestExtractListValues_Set(t *testing.T) {
	elem := parseAdvancedSExpT(t, "(scope (* set eduid identity_mapping pid))")
	vals := extractListValues(elem)
	assert.ElementsMatch(t, []string{"eduid", "identity_mapping", "pid"}, vals)
}

func TestExtractListValues_EmptyList(t *testing.T) {
	// A non-list element should return ["*"]
	atom := sexp.NewAtom("standalone")
	vals := extractListValues(atom)
	assert.Equal(t, []string{"*"}, vals)
}

// parseAdvancedSExpT is a test helper that parses an S-expression or fails.
func parseAdvancedSExpT(t *testing.T, input string) sexp.Element {
	t.Helper()
	elem, err := parseAdvancedSExp(input)
	require.NoError(t, err)
	return elem
}

// ---------- ResolveAllowedResources tests ----------

func TestResolveAllowedResources_NilEngine(t *testing.T) {
	pairs := ResolveAllowedResources(nil, "alice@sunet.se")
	assert.Nil(t, pairs)
}

func TestResolveAllowedResources_SingleScope(t *testing.T) {
	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))",
	)
	pairs := ResolveAllowedResources(engine, "alice@sunet.se")
	require.Len(t, pairs, 1)
	assert.Equal(t, "SUNET", pairs[0].AuthenticSource)
	assert.Equal(t, "eduid", pairs[0].Scope)
}

func TestResolveAllowedResources_SetScope(t *testing.T) {
	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope (* set eduid identity_mapping)))",
	)
	pairs := ResolveAllowedResources(engine, "alice@sunet.se")
	require.Len(t, pairs, 2)
	scopes := []string{pairs[0].Scope, pairs[1].Scope}
	assert.ElementsMatch(t, []string{"eduid", "identity_mapping"}, scopes)
	assert.Equal(t, "SUNET", pairs[0].AuthenticSource)
	assert.Equal(t, "SUNET", pairs[1].AuthenticSource)
}

func TestResolveAllowedResources_WildcardScope(t *testing.T) {
	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject admin@sunet.se)(authentic_source *)(scope *))",
	)
	pairs := ResolveAllowedResources(engine, "admin@sunet.se")
	require.Len(t, pairs, 1)
	assert.Equal(t, "*", pairs[0].AuthenticSource)
	assert.Equal(t, "*", pairs[0].Scope)
}

func TestResolveAllowedResources_MultipleRules(t *testing.T) {
	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))",
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope identity_mapping))",
	)
	pairs := ResolveAllowedResources(engine, "alice@sunet.se")
	require.Len(t, pairs, 2)
}

func TestResolveAllowedResources_DifferentSubject(t *testing.T) {
	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))",
	)
	pairs := ResolveAllowedResources(engine, "bob@sunet.se")
	assert.Empty(t, pairs)
}

// ---------- AllowedScopes tests ----------

func TestAllowedScopes_NilEngine(t *testing.T) {
	result := AllowedScopes(nil, "alice@sunet.se")
	assert.Nil(t, result)
}

func TestAllowedScopes_SingleScope(t *testing.T) {
	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))",
	)
	result := AllowedScopes(engine, "alice@sunet.se")
	assert.Equal(t, []string{"eduid"}, result)
}

func TestAllowedScopes_SetScope(t *testing.T) {
	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope (* set eduid identity_mapping)))",
	)
	result := AllowedScopes(engine, "alice@sunet.se")
	assert.ElementsMatch(t, []string{"eduid", "identity_mapping"}, result)
}

func TestAllowedScopes_WildcardReturnsNil(t *testing.T) {
	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject admin@sunet.se)(authentic_source *)(scope *))",
	)
	result := AllowedScopes(engine, "admin@sunet.se")
	assert.Nil(t, result, "wildcard scope means unrestricted")
}

func TestAllowedScopes_NoMatchingRules(t *testing.T) {
	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))",
	)
	result := AllowedScopes(engine, "stranger@sunet.se")
	assert.Nil(t, result, "no matching rules = unrestricted (nil)")
}

// ---------- AllowedAuthenticSources with sets ----------

func TestAllowedAuthenticSources_SetSource(t *testing.T) {
	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source (* set SUNET LADOK))(scope eduid))",
	)
	result := AllowedAuthenticSources(engine, "alice@sunet.se")
	assert.ElementsMatch(t, []string{"SUNET", "LADOK"}, result)
}

// ---------- SPOCP resource authorization via JWTAuth ----------

func TestJWTAuth_ResourceAccess_Allowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))",
	)

	handler := m.JWKSAuth(context.Background(), "apigw", model.APIAuthJWKS{
		Enable: true, JWKSURL: srv.URL, Issuer: "test-issuer", Audience: "test-aud",
	}, cache, engine)

	r := gin.New()
	r.POST("/api/v1/datastore", handler, okHandler)

	token := signJWTWithEPPN(t, priv, "alice@sunet.se", "test-issuer", "test-aud")
	body := `{"authentic_source":"SUNET","scope":"eduid"}`
	req := httptest.NewRequest("POST", "/api/v1/datastore", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestJWTAuth_ResourceAccess_WrongScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))",
	)

	handler := m.JWKSAuth(context.Background(), "apigw", model.APIAuthJWKS{
		Enable: true, JWKSURL: srv.URL, Issuer: "test-issuer", Audience: "test-aud",
	}, cache, engine)

	r := gin.New()
	r.POST("/api/v1/datastore", handler, okHandler)

	token := signJWTWithEPPN(t, priv, "alice@sunet.se", "test-issuer", "test-aud")
	body := `{"authentic_source":"SUNET","scope":"ehic"}`
	req := httptest.NewRequest("POST", "/api/v1/datastore", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "insufficient permissions")
}

func TestJWTAuth_ResourceAccess_WrongAuthenticSource(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))",
	)

	handler := m.JWKSAuth(context.Background(), "apigw", model.APIAuthJWKS{
		Enable: true, JWKSURL: srv.URL, Issuer: "test-issuer", Audience: "test-aud",
	}, cache, engine)

	r := gin.New()
	r.POST("/api/v1/datastore", handler, okHandler)

	token := signJWTWithEPPN(t, priv, "alice@sunet.se", "test-issuer", "test-aud")
	body := `{"authentic_source":"OTHER","scope":"eduid"}`
	req := httptest.NewRequest("POST", "/api/v1/datastore", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestJWTAuth_ResourceAccess_SetScope_Allowed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope (* set eduid identity_mapping)))",
	)

	handler := m.JWKSAuth(context.Background(), "apigw", model.APIAuthJWKS{
		Enable: true, JWKSURL: srv.URL, Issuer: "test-issuer", Audience: "test-aud",
	}, cache, engine)

	r := gin.New()
	r.POST("/api/v1/datastore", handler, okHandler)

	token := signJWTWithEPPN(t, priv, "alice@sunet.se", "test-issuer", "test-aud")

	for _, scope := range []string{"eduid", "identity_mapping"} {
		t.Run(scope, func(t *testing.T) {
			body := `{"authentic_source":"SUNET","scope":"` + scope + `"}`
			req := httptest.NewRequest("POST", "/api/v1/datastore", strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

func TestJWTAuth_ResourceAccess_SetScope_Denied(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope (* set eduid identity_mapping)))",
	)

	handler := m.JWKSAuth(context.Background(), "apigw", model.APIAuthJWKS{
		Enable: true, JWKSURL: srv.URL, Issuer: "test-issuer", Audience: "test-aud",
	}, cache, engine)

	r := gin.New()
	r.POST("/api/v1/datastore", handler, okHandler)

	token := signJWTWithEPPN(t, priv, "alice@sunet.se", "test-issuer", "test-aud")
	body := `{"authentic_source":"SUNET","scope":"pid"}`
	req := httptest.NewRequest("POST", "/api/v1/datastore", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestJWTAuth_ResourceAccess_WildcardAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject admin@sunet.se)(authentic_source *)(scope *))",
	)

	handler := m.JWKSAuth(context.Background(), "apigw", model.APIAuthJWKS{
		Enable: true, JWKSURL: srv.URL, Issuer: "test-issuer", Audience: "test-aud",
	}, cache, engine)

	r := gin.New()
	r.POST("/api/v1/datastore", handler, okHandler)

	token := signJWTWithEPPN(t, priv, "admin@sunet.se", "test-issuer", "test-aud")
	body := `{"authentic_source":"ANYTHING","scope":"whatever"}`
	req := httptest.NewRequest("POST", "/api/v1/datastore", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestJWTAuth_NoResourcePairs_Allowed(t *testing.T) {
	// Request with no resource fields should pass if rule uses wildcard for authentic_source/scope.
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source *)(scope *))",
	)

	handler := m.JWKSAuth(context.Background(), "apigw", model.APIAuthJWKS{
		Enable: true, JWKSURL: srv.URL, Issuer: "test-issuer", Audience: "test-aud",
	}, cache, engine)

	r := gin.New()
	r.GET("/api/v1/status", handler, okHandler)

	token := signJWTWithEPPN(t, priv, "alice@sunet.se", "test-issuer", "test-aud")
	w := performRequest(r, "GET", "/api/v1/status", map[string]string{
		"Authorization": "Bearer " + token,
	})

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestJWTAuth_MissingEPPN_Denied(t *testing.T) {
	// JWT without eppn or email should be denied when SPOCP is active.
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))",
	)

	handler := m.JWKSAuth(context.Background(), "apigw", model.APIAuthJWKS{
		Enable: true, JWKSURL: srv.URL, Issuer: "test-issuer", Audience: "test-aud",
	}, cache, engine)

	r := gin.New()
	r.GET("/api/v1/status", handler, okHandler)

	// signJWT does NOT set eppn/email — only "sub"
	token := signJWT(t, priv, "alice", "test-issuer", "test-aud")
	w := performRequest(r, "GET", "/api/v1/status", map[string]string{
		"Authorization": "Bearer " + token,
	})

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "eppn or email")
}

func TestJWTAuth_ContextContainsAllowedScopes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope (* set eduid identity_mapping)))",
	)

	handler := m.JWKSAuth(context.Background(), "apigw", model.APIAuthJWKS{
		Enable: true, JWKSURL: srv.URL, Issuer: "test-issuer", Audience: "test-aud",
	}, cache, engine)

	var capturedSources []string
	var capturedScopes []string

	r := gin.New()
	r.GET("/api/v1/status", handler, func(c *gin.Context) {
		if v, ok := c.Get("spocp_allowed_authentic_sources"); ok {
			capturedSources = v.([]string)
		}
		if v, ok := c.Get("spocp_allowed_scopes"); ok {
			capturedScopes = v.([]string)
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	token := signJWTWithEPPN(t, priv, "alice@sunet.se", "test-issuer", "test-aud")
	body := `{"authentic_source":"SUNET","scope":"eduid"}`
	req := httptest.NewRequest("GET", "/api/v1/status", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, []string{"SUNET"}, capturedSources)
	assert.ElementsMatch(t, []string{"eduid", "identity_mapping"}, capturedScopes)
}

func TestJWTAuth_OmittedScope_Denied(t *testing.T) {
	// A datastore upload that omits scope should be denied (empty scope won't match).
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	engine := buildEngine(
		t,
		"(vc (service apigw)(method *)(path /api/v1/*)(subject alice@sunet.se)(authentic_source SUNET)(scope eduid))",
	)

	handler := m.JWKSAuth(context.Background(), "apigw", model.APIAuthJWKS{
		Enable: true, JWKSURL: srv.URL, Issuer: "test-issuer", Audience: "test-aud",
	}, cache, engine)

	r := gin.New()
	r.POST("/api/v1/datastore", handler, okHandler)

	token := signJWTWithEPPN(t, priv, "alice@sunet.se", "test-issuer", "test-aud")
	// authentic_source present but scope omitted
	body := `{"authentic_source":"SUNET"}`
	req := httptest.NewRequest("POST", "/api/v1/datastore", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ---------- helpers ----------

// buildEngine creates a SPOCP engine from one or more advanced-syntax rules.
func buildEngine(t *testing.T, rules ...string) *SafeEngine {
	t.Helper()
	cfg := model.APIAuth{Rules: rules}
	engine, err := BuildSPOCPEngine(cfg)
	require.NoError(t, err)
	require.NotNil(t, engine)
	return engine
}

// ---------- discoverJWKSURL ----------

func TestDiscoverJWKSURL_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/.well-known/openid-configuration", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"jwks_uri": "https://auth.example.com/jwks",
		})
	}))
	defer srv.Close()

	jwksURL, err := discoverJWKSURL(t.Context(), srv.URL)
	require.NoError(t, err)
	assert.Equal(t, "https://auth.example.com/jwks", jwksURL)
}

func TestDiscoverJWKSURL_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := discoverJWKSURL(t.Context(), srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "discovery endpoint returned 500")
}

func TestDiscoverJWKSURL_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := discoverJWKSURL(t.Context(), srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode discovery document")
}

func TestDiscoverJWKSURL_MissingJWKSURI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"issuer": "https://auth.example.com",
		})
	}))
	defer srv.Close()

	_, err := discoverJWKSURL(t.Context(), srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "discovery document has no jwks_uri")
}

// ---------- File-based JWKS tests ----------

// writeJWKSFile serializes the given keyset to a JSON file and returns the path.
func writeJWKSFile(t *testing.T, dir string, set jwk.Set) string {
	t.Helper()
	raw, err := json.Marshal(set)
	require.NoError(t, err)
	path := filepath.Join(dir, "jwks.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

func TestJWKSAuth_FilePath_ValidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)

	dir := t.TempDir()
	jwksPath := writeJWKSFile(t, dir, set)

	cfg := model.APIAuthJWKS{
		Enable:       true,
		JWKSFilePath: jwksPath,
		Issuer:       "test-issuer",
		Audience:     "test-aud",
	}

	handler := m.JWKSAuth(context.Background(), "test-svc", cfg, nil, nil)

	r := gin.New()
	r.GET("/api/v1/resource", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"sub": c.GetString("jwt_subject")})
	})

	token := signJWT(t, priv, "user@example.com", "test-issuer", "test-aud")
	w := performRequest(r, "GET", "/api/v1/resource", map[string]string{
		"Authorization": "Bearer " + token,
	})
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestJWKSAuth_FilePath_InvalidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	_, set := testKeyPair(t)

	dir := t.TempDir()
	jwksPath := writeJWKSFile(t, dir, set)

	cfg := model.APIAuthJWKS{
		Enable:       true,
		JWKSFilePath: jwksPath,
		Issuer:       "test-issuer",
		Audience:     "test-aud",
	}

	handler := m.JWKSAuth(context.Background(), "test-svc", cfg, nil, nil)

	r := gin.New()
	r.GET("/api/v1/resource", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := performRequest(r, "GET", "/api/v1/resource", map[string]string{
		"Authorization": "Bearer invalid.token.here",
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWKSAuth_FilePath_ReloadOnChange(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	// Generate two independent key pairs.
	priv1, set1 := testKeyPair(t)
	priv2, set2 := testKeyPair(t)

	dir := t.TempDir()
	jwksPath := writeJWKSFile(t, dir, set1)

	cfg := model.APIAuthJWKS{
		Enable:       true,
		JWKSFilePath: jwksPath,
		Issuer:       "test-issuer",
		Audience:     "test-aud",
	}

	handler := m.JWKSAuth(context.Background(), "test-svc", cfg, nil, nil)

	r := gin.New()
	r.GET("/api/v1/resource", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// Token signed with key1 should succeed.
	token1 := signJWT(t, priv1, "user1", "test-issuer", "test-aud")
	w := performRequest(r, "GET", "/api/v1/resource", map[string]string{
		"Authorization": "Bearer " + token1,
	})
	assert.Equal(t, http.StatusOK, w.Code, "key1 token should be accepted with key1 JWKS")

	// Token signed with key2 should fail (key2 not in JWKS yet).
	token2 := signJWT(t, priv2, "user2", "test-issuer", "test-aud")
	w = performRequest(r, "GET", "/api/v1/resource", map[string]string{
		"Authorization": "Bearer " + token2,
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code, "key2 token should be rejected before file update")

	// Overwrite the JWKS file with key2. Advance mtime to guarantee detection.
	raw2, err := json.Marshal(set2)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(jwksPath, raw2, 0o600))
	// Ensure mtime differs (some filesystems have 1s granularity).
	future := time.Now().Add(2 * time.Second)
	require.NoError(t, os.Chtimes(jwksPath, future, future))

	// Now token2 should succeed (file reloaded) and token1 should fail.
	w = performRequest(r, "GET", "/api/v1/resource", map[string]string{
		"Authorization": "Bearer " + token2,
	})
	assert.Equal(t, http.StatusOK, w.Code, "key2 token should be accepted after file update")

	w = performRequest(r, "GET", "/api/v1/resource", map[string]string{
		"Authorization": "Bearer " + token1,
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code, "key1 token should be rejected after file update")
}

func TestJWKSAuth_FilePath_MissingFile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	cfg := model.APIAuthJWKS{
		Enable:       true,
		JWKSFilePath: "/nonexistent/path/jwks.json",
		Issuer:       "test-issuer",
		Audience:     "test-aud",
	}

	handler := m.JWKSAuth(context.Background(), "test-svc", cfg, nil, nil)

	r := gin.New()
	r.GET("/api/v1/resource", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// The handler returned should be an error handler since the file doesn't exist.
	w := performRequest(r, "GET", "/api/v1/resource", map[string]string{
		"Authorization": "Bearer anything",
	})
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestJWKSAuth_NoSourceConfigured(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)

	cfg := model.APIAuthJWKS{
		Enable:   true,
		Issuer:   "test-issuer",
		Audience: "test-aud",
		// Neither JWKSURL nor JWKSFilePath set
	}

	handler := m.JWKSAuth(context.Background(), "test-svc", cfg, nil, nil)

	r := gin.New()
	r.GET("/api/v1/resource", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := performRequest(r, "GET", "/api/v1/resource", map[string]string{
		"Authorization": "Bearer anything",
	})
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------- Lazy-init / retry tests ----------

func TestJWKSAuth_URL_LazyRetryAfterInitFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)

	// Start with a server that returns errors.
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount++
		if requestCount <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		raw, _ := json.Marshal(set)
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw) // #nosec G104
	}))
	defer srv.Close()

	cache := newStubCache()
	cfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}

	handler := m.JWKSAuth(context.Background(), "test-svc", cfg, cache, nil)

	r := gin.New()
	r.GET("/api/v1/resource", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	token := signJWT(t, priv, "user@example.com", "test-issuer", "test-aud")

	// First request: provider not yet initialized, retry backoff not yet elapsed → 503.
	w := performRequest(r, "GET", "/api/v1/resource", map[string]string{
		"Authorization": "Bearer " + token,
	})
	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "should return 503 during backoff")
}

func TestJWKSAuth_URL_RecoverAfterInitFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)

	// Server always returns valid JWKS.
	raw, err := json.Marshal(set)
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw) // #nosec G104
	}))
	defer srv.Close()

	// Use an unreachable URL for initial construction to force lazy mode.
	cache := newStubCache()
	cfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  "http://127.0.0.1:1", // connection refused → init fails
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}

	handler := m.JWKSAuth(context.Background(), "test-svc", cfg, cache, nil)

	r := gin.New()
	r.GET("/api/v1/resource", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	token := signJWT(t, priv, "user@example.com", "test-issuer", "test-aud")

	// First request fails because we're in backoff.
	w := performRequest(r, "GET", "/api/v1/resource", map[string]string{
		"Authorization": "Bearer " + token,
	})
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	// Now point the provider at the working server by creating a new handler.
	cfg.JWKSURL = srv.URL
	handler2 := m.JWKSAuth(context.Background(), "test-svc", cfg, cache, nil)

	r2 := gin.New()
	r2.GET("/api/v1/resource", handler2, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// This should succeed immediately (eager init works with a reachable server).
	w = performRequest(r2, "GET", "/api/v1/resource", map[string]string{
		"Authorization": "Bearer " + token,
	})
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOIDCKeySetProvider_LazyDiscovery(t *testing.T) {
	gin.SetMode(gin.TestMode)

	_, set := testKeyPair(t)
	raw, err := json.Marshal(set)
	require.NoError(t, err)

	// Simulate an IdP that is initially down then comes up.
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if strings.Contains(r.URL.Path, ".well-known") {
			// Discovery endpoint
			doc := fmt.Sprintf(`{"issuer":"http://%s","jwks_uri":"http://%s/jwks"}`, r.Host, r.Host)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(doc)) // #nosec G104
			return
		}
		// JWKS endpoint
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw) // #nosec G104
	}))
	defer srv.Close()

	cache := newStubCache()
	logFn := func(msg string, args ...any) {}

	// Provider with a reachable server should succeed eagerly.
	p := newOIDCKeySetProvider(context.Background(), srv.URL, cache, logFn)
	assert.NotNil(t, p.set, "should have loaded keys eagerly")

	keys, err := p.GetKeySet(context.Background())
	require.NoError(t, err)
	assert.Greater(t, keys.Len(), 0)
}

func TestOIDCKeySetProvider_FailedDiscoveryReturnsServiceUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cache := newStubCache()
	logFn := func(msg string, args ...any) {}

	// Provider with unreachable IdP.
	p := newOIDCKeySetProvider(context.Background(), "http://127.0.0.1:1", cache, logFn)
	assert.Nil(t, p.set, "should not have loaded keys")

	// GetKeySet should return error (backoff not elapsed yet).
	_, err := p.GetKeySet(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OIDC JWKS not available")
}
