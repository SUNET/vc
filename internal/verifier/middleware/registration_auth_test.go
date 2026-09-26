package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	registerPath     = "/register"
	issuerExampleURL = "https://issuer.example.com"
	registerAudience = "vc-verifier-register"
	jwtKid           = "kid-1"
)

func TestRegistrationAuthMiddlewareOpenMode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			Outbound: model.VerifierOutbound{OIDCProvider: &model.OIDCOP{
				DynamicRegistrationAuth: &model.DynamicRegistrationAuthConfig{Mode: "open"}},
			},
		},
	}

	mw, err := NewRegistrationAuthMiddleware(cfg, logger.NewSimple("test"))
	require.NoError(t, err)

	r := gin.New()
	r.POST(registerPath, mw, func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, registerPath, nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusNoContent, resp.Code)
}

func TestRegistrationAuthMiddlewareStaticMode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tokenFile := filepath.Join(t.TempDir(), "registration.token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("test-static-token\n"), 0o600))

	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			Outbound: model.VerifierOutbound{OIDCProvider: &model.OIDCOP{
				DynamicRegistrationAuth: &model.DynamicRegistrationAuthConfig{
					Mode:                  "static",
					StaticBearerTokenFile: tokenFile,
				},
			}},
		},
	}

	mw, err := NewRegistrationAuthMiddleware(cfg, logger.NewSimple("test"))
	require.NoError(t, err)

	r := gin.New()
	r.POST(registerPath, mw, func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	t.Run("valid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, registerPath, nil)
		req.Header.Set("Authorization", "Bearer test-static-token")
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusNoContent, resp.Code)
	})

	t.Run("missing token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, registerPath, nil)
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)
		// 400, not 401: no Authorization header at all is invalid_request
		// per RFC 6750 section 3.1, not a rejected token.
		assert.Equal(t, http.StatusBadRequest, resp.Code)
	})

	t.Run("invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, registerPath, nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})
}

func TestRegistrationAuthMiddlewareStaticModeRequiresFile(t *testing.T) {
	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			Outbound: model.VerifierOutbound{OIDCProvider: &model.OIDCOP{
				DynamicRegistrationAuth: &model.DynamicRegistrationAuthConfig{Mode: "static"}},
			},
		},
	}

	_, err := NewRegistrationAuthMiddleware(cfg, logger.NewSimple("test"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "static_bearer_token_file")
}

func TestRegistrationAuthMiddlewareJWTMode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Built here, not in the handler: httptest runs the handler on its own
	// goroutine, and require's failure path calls t.FailNow, which the
	// testing package documents as safe only from the goroutine running the
	// test. Under -race that is a data race rather than a clean failure.
	key, err := jwk.Import(privateKey.Public())
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, jwtKid))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(key))
	jwksJSON, err := json.Marshal(set)
	require.NoError(t, err)

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	defer jwksServer.Close()

	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			Outbound: model.VerifierOutbound{OIDCProvider: &model.OIDCOP{
				DynamicRegistrationAuth: &model.DynamicRegistrationAuthConfig{
					Mode: "jwt",
					JWT: &model.DynamicRegistrationJWTAuthConfig{
						JWKSURI:            jwksServer.URL,
						Issuer:             issuerExampleURL,
						Audience:           registerAudience,
						AllowedSigningAlgs: []string{"RS256"},
					},
				},
			}},
		},
	}

	mw, err := NewRegistrationAuthMiddleware(cfg, logger.NewSimple("test"))
	require.NoError(t, err)

	r := gin.New()
	r.POST(registerPath, mw, func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	validClaims := jwt.MapClaims{
		"iss": issuerExampleURL,
		"aud": registerAudience,
		"sub": "client-reg-admin",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	validToken := jwt.NewWithClaims(jwt.SigningMethodRS256, validClaims)
	validToken.Header["kid"] = jwtKid
	validTokenString, err := validToken.SignedString(privateKey)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, registerPath, nil)
	req.Header.Set("Authorization", "Bearer "+validTokenString)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusNoContent, resp.Code)

	invalidClaims := jwt.MapClaims{
		"iss": issuerExampleURL,
		"aud": "wrong-audience",
		"sub": "client-reg-admin",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	invalidToken := jwt.NewWithClaims(jwt.SigningMethodRS256, invalidClaims)
	invalidToken.Header["kid"] = jwtKid
	invalidTokenString, err := invalidToken.SignedString(privateKey)
	require.NoError(t, err)

	req2 := httptest.NewRequest(http.MethodPost, registerPath, nil)
	req2.Header.Set("Authorization", "Bearer "+invalidTokenString)
	resp2 := httptest.NewRecorder()
	r.ServeHTTP(resp2, req2)
	assert.Equal(t, http.StatusUnauthorized, resp2.Code)
}

func TestRegistrationAuthMiddlewareIntrospectionModeNotImplemented(t *testing.T) {
	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			Outbound: model.VerifierOutbound{OIDCProvider: &model.OIDCOP{
				DynamicRegistrationAuth: &model.DynamicRegistrationAuthConfig{Mode: "introspection"}},
			},
		},
	}

	_, err := NewRegistrationAuthMiddleware(cfg, logger.NewSimple("test"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")
}

func TestStaticBearerValidatorConstantTimeComparison(t *testing.T) {
	validator := &staticBearerValidator{tokenDigest: sha256.Sum256([]byte("expected-token"))}

	err := validator.Validate(t.Context(), "expected-token")
	require.NoError(t, err)

	err = validator.Validate(t.Context(), "wrong-token")
	require.Error(t, err)

	// Different length, which is the case the digest comparison exists for:
	// comparing raw tokens would have returned early on the length check.
	err = validator.Validate(t.Context(), "x")
	require.Error(t, err)

	err = validator.Validate(t.Context(), "")
	require.Error(t, err)
	var authErr *registrationAuthError
	require.ErrorAs(t, err, &authErr)
	assert.Equal(t, "invalid_token", authErr.errorCode)
}

func TestJWTBearerValidatorRequiresConfig(t *testing.T) {
	_, err := newJWTBearerValidator(nil)
	require.Error(t, err)

	_, err = newJWTBearerValidator(&model.DynamicRegistrationJWTAuthConfig{})
	require.Error(t, err)

	_, err = newJWTBearerValidator(&model.DynamicRegistrationJWTAuthConfig{
		JWKSURI:  issuerExampleURL + "/jwks",
		Issuer:   issuerExampleURL,
		Audience: registerAudience,
	})
	assert.NoError(t, err)
}

func TestExtractBearerToken(t *testing.T) {
	token, err := extractBearerToken("Bearer abc123")
	require.NoError(t, err)
	assert.Equal(t, "abc123", token)

	_, err = extractBearerToken("")
	require.Error(t, err)

	_, err = extractBearerToken("Basic abc123")
	require.Error(t, err)
}

func TestExtractBearerTokenCaseInsensitiveScheme(t *testing.T) {
	token, err := extractBearerToken("bearer token-value")
	require.NoError(t, err)
	assert.Equal(t, "token-value", token)

	token, err = extractBearerToken("BEARER token-value")
	require.NoError(t, err)
	assert.Equal(t, "token-value", token)
}

func TestRSAExponentEncodingSanity(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	assert.True(t, privateKey.PublicKey.E > 0)
	assert.True(t, privateKey.PublicKey.N.Cmp(big.NewInt(0)) > 0)
}

// TestRegistrationAuthHeaderErrorsAreInvalidRequest pins RFC 6750 section
// 3.1's split: a missing or malformed Authorization header is
// invalid_request, and only a credential that was actually judged and
// rejected is invalid_token. Answering "your token is bad" to a client that
// sent no token sends it looking in the wrong place.
func TestRegistrationAuthHeaderErrorsAreInvalidRequest(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &model.Cfg{Verifier: &model.Verifier{
		Outbound: model.VerifierOutbound{OIDCProvider: &model.OIDCOP{
			DynamicRegistrationAuth: &model.DynamicRegistrationAuthConfig{
				Mode:                  "static",
				StaticBearerTokenFile: tokenFile,
			},
		}},
	}}

	mw, err := NewRegistrationAuthMiddleware(cfg, nil)
	if err != nil {
		t.Fatalf("middleware: %v", err)
	}

	// RFC 6750 section 3.1 pairs each code with a status: invalid_request is
	// 400, invalid_token is 401. Asserting both together, since a client
	// keying off the status alone is the case that matters.
	for _, tc := range []struct {
		name       string
		header     string
		wantCode   string
		wantStatus int
	}{
		{"no header at all", "", "invalid_request", http.StatusBadRequest},
		{"not a bearer scheme", "Basic dXNlcjpwYXNz", "invalid_request", http.StatusBadRequest},
		{"bearer with no value", "Bearer", "invalid_request", http.StatusBadRequest},
		{"well-formed but wrong token", "Bearer wrong", "invalid_token", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, "/register", nil)
			if tc.header != "" {
				c.Request.Header.Set("Authorization", tc.header)
			}

			mw(c)

			if rec.Code != tc.wantStatus {
				t.Fatalf("want status %d, got %d", tc.wantStatus, rec.Code)
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode body: %v (%s)", err, rec.Body.String())
			}
			if got := body["error"]; got != tc.wantCode {
				t.Errorf("error code: want %q, got %v", tc.wantCode, got)
			}
		})
	}
}

// TestStaticBearerTokenFileContents covers the file shapes that cannot
// produce a working bearer token. Rejecting them at startup keeps the
// message about the file; left to run, they present as every registration
// attempt failing authentication.
func TestStaticBearerTokenFileContents(t *testing.T) {
	for _, tc := range []struct {
		name      string
		contents  string
		wantError string
	}{
		{name: "plain token", contents: "s3cret"},
		{name: "trailing newline is trimmed", contents: "s3cret\n"},
		{name: "surrounding whitespace is trimmed", contents: "  s3cret\t\n"},
		{name: "empty", contents: "", wantError: "empty"},
		{name: "whitespace only", contents: " \n\t ", wantError: "empty"},
		{name: "token plus a comment line", contents: "s3cret\n# the registration token\n", wantError: "whitespace inside"},
		{name: "two tokens", contents: "s3cret other\n", wantError: "whitespace inside"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(path, []byte(tc.contents), 0o600); err != nil {
				t.Fatal(err)
			}

			v, err := newStaticBearerValidator(path)
			if tc.wantError == "" {
				require.NoError(t, err)
				require.NoError(t, v.Validate(t.Context(), "s3cret"))
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantError)
		})
	}
}
