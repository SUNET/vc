package httphelpers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/trace"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
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
			"(api (service test-svc)(method POST)(path /api/v1/upload)(subject alice))",
			"(api (service test-svc)(method)(path /api/v1/document)(subject))",
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

func TestBuildSPOCPEngine_RulesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.spocp")
	content := "(api (service test-svc)(method GET)(path /health)(subject))\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0644)) // #nosec G306

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
	content := "(api (service test-svc)(method DELETE)(path /api/v1/document)(subject admin))\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0644)) // #nosec G306

	cfg := model.APIAuth{
		Rules:     []string{"(api (service test-svc)(method POST)(path /api/v1/upload)(subject alice))"},
		RulesFile: path,
	}

	engine, err := BuildSPOCPEngine(cfg)
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Equal(t, 2, engine.RuleCount())
}

// ---------- buildAPISPOCPQuery tests ----------

func TestBuildAPISPOCPQuery(t *testing.T) {
	q := buildAPISPOCPQuery("test-svc", "POST", "/api/v1/upload", "alice")
	assert.NotNil(t, q)
	// The canonical string representation should contain all four tuples.
	s := q.String()
	assert.Contains(t, s, "service")
	assert.Contains(t, s, "test-svc")
	assert.Contains(t, s, "method")
	assert.Contains(t, s, "POST")
	assert.Contains(t, s, "path")
	assert.Contains(t, s, "/api/v1/upload")
	assert.Contains(t, s, "subject")
	assert.Contains(t, s, "alice")
}

// ---------- SPOCP authorization via JWTAuth middleware ----------

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
			// Allow alice to POST /api/v1/upload
			"(api (service test-svc)(method POST)(path /api/v1/upload)(subject alice))",
		},
	}

	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.POST("/api/v1/upload", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	token := signJWT(t, priv, "alice", "test-issuer", "test-aud")
	w := performRequest(r, "POST", "/api/v1/upload", map[string]string{
		"Authorization": "Bearer " + token,
	})

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
			// Only alice can POST /api/v1/upload
			"(api (service test-svc)(method POST)(path /api/v1/upload)(subject alice))",
		},
	}

	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.POST("/api/v1/upload", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// bob is not authorized
	token := signJWT(t, priv, "bob", "test-issuer", "test-aud")
	w := performRequest(r, "POST", "/api/v1/upload", map[string]string{
		"Authorization": "Bearer " + token,
	})

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
			// Any authenticated subject can POST /api/v1/document
			"(api (service test-svc)(method POST)(path /api/v1/document)(subject))",
		},
	}

	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.POST("/api/v1/document", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"sub": c.GetString("jwt_subject")})
	})

	// Any subject should be accepted
	for _, sub := range []string{"alice", "bob", "charlie"} {
		token := signJWT(t, priv, sub, "test-issuer", "test-aud")
		w := performRequest(r, "POST", "/api/v1/document", map[string]string{
			"Authorization": "Bearer " + token,
		})
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
			// alice can use any method on /api/v1/upload
			"(api (service test-svc)(method)(path /api/v1/upload)(subject alice))",
		},
	}

	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.POST("/api/v1/upload", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	r.PUT("/api/v1/upload", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	r.DELETE("/api/v1/upload", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	token := signJWT(t, priv, "alice", "test-issuer", "test-aud")

	for _, method := range []string{"POST", "PUT", "DELETE"} {
		w := performRequest(r, method, "/api/v1/upload", map[string]string{
			"Authorization": "Bearer " + token,
		})
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
			// alice can access anything under /api/v1/
			`(api (service test-svc)(method)(path (* prefix /api/v1/))(subject alice))`,
		},
	}

	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.POST("/api/v1/upload", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	r.POST("/api/v1/document", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	r.DELETE("/api/v1/document", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	token := signJWT(t, priv, "alice", "test-issuer", "test-aud")

	for _, tc := range []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/upload"},
		{"POST", "/api/v1/document"},
		{"DELETE", "/api/v1/document"},
	} {
		w := performRequest(r, tc.method, tc.path, map[string]string{
			"Authorization": "Bearer " + token,
		})
		assert.Equal(t, http.StatusOK, w.Code, "%s %s should be allowed", tc.method, tc.path)
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
			"(api (service test-svc)(method POST)(path /api/v1/upload)(subject alice))",
			"(api (service test-svc)(method POST)(path /api/v1/document)(subject bob))",
		},
	}

	engine, err := BuildSPOCPEngine(authCfg)
	require.NoError(t, err)

	handler := m.JWKSAuth(context.Background(), "test-svc", jwksCfg, cache, engine)

	r := gin.New()
	r.POST("/api/v1/upload", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	r.POST("/api/v1/document", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// alice → upload: OK
	w := performRequest(r, "POST", "/api/v1/upload", map[string]string{
		"Authorization": "Bearer " + signJWT(t, priv, "alice", "test-issuer", "test-aud"),
	})
	assert.Equal(t, http.StatusOK, w.Code)

	// alice → document: DENIED
	w = performRequest(r, "POST", "/api/v1/document", map[string]string{
		"Authorization": "Bearer " + signJWT(t, priv, "alice", "test-issuer", "test-aud"),
	})
	assert.Equal(t, http.StatusForbidden, w.Code)

	// bob → document: OK
	w = performRequest(r, "POST", "/api/v1/document", map[string]string{
		"Authorization": "Bearer " + signJWT(t, priv, "bob", "test-issuer", "test-aud"),
	})
	assert.Equal(t, http.StatusOK, w.Code)

	// bob → upload: DENIED
	w = performRequest(r, "POST", "/api/v1/upload", map[string]string{
		"Authorization": "Bearer " + signJWT(t, priv, "bob", "test-issuer", "test-aud"),
	})
	assert.Equal(t, http.StatusForbidden, w.Code)
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

	token := signJWT(t, priv, "alice", "test-issuer", "test-aud")
	w := performRequest(r, "POST", "/api/v1/test", map[string]string{
		"Authorization": "Bearer " + token,
	})

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "alice", capturedSubject)
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
	rules := "(api (service test-svc)(method POST)(path /api/v1/upload)(subject alice))\n"
	require.NoError(t, os.WriteFile(rulesPath, []byte(rules), 0644)) // #nosec G306

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
	r.POST("/api/v1/upload", handler, func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// alice: allowed
	w := performRequest(r, "POST", "/api/v1/upload", map[string]string{
		"Authorization": "Bearer " + signJWT(t, priv, "alice", "test-issuer", "test-aud"),
	})
	assert.Equal(t, http.StatusOK, w.Code)

	// bob: denied
	w = performRequest(r, "POST", "/api/v1/upload", map[string]string{
		"Authorization": "Bearer " + signJWT(t, priv, "bob", "test-issuer", "test-aud"),
	})
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ---------- loadRulesFromFile tests ----------

func TestLoadRulesFromFile_MultipleRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.spocp")
	content := `(api (service test-svc)(method GET)(path /health)(subject))
(api (service test-svc)(method POST)(path /api/v1/upload)(subject alice))
(api (service test-svc)(method DELETE)(path /api/v1/document)(subject admin))
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0644)) // #nosec G306

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
(api (service test-svc)(method GET)(path /health)(subject))

# Another comment

(api (service test-svc)(method POST)(path /api/v1/upload)(subject alice))

# trailing comment
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0644)) // #nosec G306

	cfg := model.APIAuth{RulesFile: path}
	engine, err := BuildSPOCPEngine(cfg)
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Equal(t, 2, engine.RuleCount(), "only non-comment, non-blank lines count")
}

func TestLoadRulesFromFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.spocp")
	require.NoError(t, os.WriteFile(path, []byte(""), 0644)) // #nosec G306

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
	require.NoError(t, os.WriteFile(path, []byte(content), 0644)) // #nosec G306

	cfg := model.APIAuth{RulesFile: path}
	engine, err := BuildSPOCPEngine(cfg)
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Equal(t, 0, engine.RuleCount())
}

func TestLoadRulesFromFile_InvalidLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.spocp")
	content := `(api (service test-svc)(method GET)(path /health)(subject))
this is not valid
(api (service test-svc)(method POST)(path /upload)(subject bob))
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0644)) // #nosec G306

	cfg := model.APIAuth{RulesFile: path}
	_, err := BuildSPOCPEngine(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line 2")
}

func TestLoadRulesFromFile_StarForms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.spocp")
	content := `# Wildcard subject
(api (service test-svc)(method GET)(path /api/v1/status)(subject (*)))
# Prefix path
(api (service test-svc)(method)(path (* prefix /api/v1/))(subject alice))
# Suffix path
(api (service test-svc)(method GET)(path (* suffix .json))(subject bob))
# Set of methods
(api (service test-svc)(method (* set GET POST))(path /api/v1/items)(subject charlie))
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0644)) // #nosec G306

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
(api (service test-svc)(method POST)(path /api/v1/upload)(subject alice))
(api (service test-svc)(method GET)(path /api/v1/document)(subject bob))
(api (service test-svc)(method)(path (* prefix /api/v1/))(subject admin))
`
	require.NoError(t, os.WriteFile(rulesPath, []byte(rules), 0644)) // #nosec G306

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
		wantStatus int
	}{
		{"alice POST upload → OK", "POST", "/api/v1/upload", "alice", http.StatusOK},
		{"alice GET document → denied", "GET", "/api/v1/document", "alice", http.StatusForbidden},
		{"bob GET document → OK", "GET", "/api/v1/document", "bob", http.StatusOK},
		{"bob POST upload → denied", "POST", "/api/v1/upload", "bob", http.StatusForbidden},
		{"admin POST upload → OK (prefix)", "POST", "/api/v1/upload", "admin", http.StatusOK},
		{"admin GET document → OK (prefix)", "GET", "/api/v1/document", "admin", http.StatusOK},
		{"admin DELETE document → OK (prefix)", "DELETE", "/api/v1/document", "admin", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := signJWT(t, priv, tc.subject, "test-issuer", "test-aud")
			w := performRequest(r, tc.method, tc.path, map[string]string{
				"Authorization": "Bearer " + token,
			})
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
	rules := "# Any authenticated user can GET /api/v1/public\n(api (service test-svc)(method GET)(path /api/v1/public)(subject (*)))\n"
	require.NoError(t, os.WriteFile(rulesPath, []byte(rules), 0644)) // #nosec G306

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

	for _, sub := range []string{"alice", "bob", "stranger"} {
		t.Run("GET_"+sub+"_allowed", func(t *testing.T) {
			token := signJWT(t, priv, sub, "test-issuer", "test-aud")
			w := performRequest(r, "GET", "/api/v1/public", map[string]string{
				"Authorization": "Bearer " + token,
			})
			assert.Equal(t, http.StatusOK, w.Code)
		})
		t.Run("POST_"+sub+"_denied", func(t *testing.T) {
			token := signJWT(t, priv, sub, "test-issuer", "test-aud")
			w := performRequest(r, "POST", "/api/v1/public", map[string]string{
				"Authorization": "Bearer " + token,
			})
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
	rules := "# alice can GET any .json path\n(api (service test-svc)(method GET)(path (* suffix .json))(subject alice))\n"
	require.NoError(t, os.WriteFile(rulesPath, []byte(rules), 0644)) // #nosec G306

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

	// .json suffix → allowed
	token := signJWT(t, priv, "alice", "test-issuer", "test-aud")
	w := performRequest(r, "GET", "/api/v1/config.json", map[string]string{
		"Authorization": "Bearer " + token,
	})
	assert.Equal(t, http.StatusOK, w.Code)

	// .yaml suffix → denied
	w = performRequest(r, "GET", "/api/v1/config.yaml", map[string]string{
		"Authorization": "Bearer " + token,
	})
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRulesFile_E2E_MethodSet(t *testing.T) {
	gin.SetMode(gin.TestMode)
	m := newTestMiddleware(t)
	priv, set := testKeyPair(t)
	srv, cache := jwksServer(t, set)

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.spocp")
	rules := "# alice may GET or POST but not DELETE on /api/v1/items\n(api (service test-svc)(method (* set GET POST))(path /api/v1/items)(subject alice))\n"
	require.NoError(t, os.WriteFile(rulesPath, []byte(rules), 0644)) // #nosec G306

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

	token := signJWT(t, priv, "alice", "test-issuer", "test-aud")

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
			w := performRequest(r, tc.method, "/api/v1/items", map[string]string{
				"Authorization": "Bearer " + token,
			})
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
	fileRules := "(api (service test-svc)(method DELETE)(path /api/v1/document)(subject admin))\n"
	require.NoError(t, os.WriteFile(rulesPath, []byte(fileRules), 0644)) // #nosec G306

	jwksCfg := model.APIAuthJWKS{
		Enable:   true,
		JWKSURL:  srv.URL,
		Issuer:   "test-issuer",
		Audience: "test-aud",
	}
	authCfg := model.APIAuth{
		Rules: []string{
			"(api (service test-svc)(method POST)(path /api/v1/upload)(subject alice))",
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

	tests := []struct {
		name       string
		method     string
		path       string
		subject    string
		wantStatus int
	}{
		{"alice upload (inline rule)", "POST", "/api/v1/upload", "alice", http.StatusOK},
		{"admin delete (file rule)", "DELETE", "/api/v1/document", "admin", http.StatusOK},
		{"alice delete → denied", "DELETE", "/api/v1/document", "alice", http.StatusForbidden},
		{"admin upload → denied", "POST", "/api/v1/upload", "admin", http.StatusForbidden},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token := signJWT(t, priv, tc.subject, "test-issuer", "test-aud")
			w := performRequest(r, tc.method, tc.path, map[string]string{
				"Authorization": "Bearer " + token,
			})
			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

// okHandler is a trivial gin handler that returns 200 {"ok":true}.
func okHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
