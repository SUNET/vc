package middleware

import (
	"crypto/rand"
	"crypto/rsa"
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

func TestRegistrationAuthMiddleware_OpenMode(t *testing.T) {
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
	r.POST("/register", mw, func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodPost, "/register", nil)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)

	assert.Equal(t, http.StatusNoContent, resp.Code)
}

func TestRegistrationAuthMiddleware_StaticMode(t *testing.T) {
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
	r.POST("/register", mw, func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	t.Run("valid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/register", nil)
		req.Header.Set("Authorization", "Bearer test-static-token")
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusNoContent, resp.Code)
	})

	t.Run("missing token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/register", nil)
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})

	t.Run("invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/register", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		resp := httptest.NewRecorder()
		r.ServeHTTP(resp, req)
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})
}

func TestRegistrationAuthMiddleware_StaticModeRequiresFile(t *testing.T) {
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

func TestRegistrationAuthMiddleware_JWTMode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		key, err := jwk.Import(privateKey.Public())
		require.NoError(t, err)
		require.NoError(t, key.Set(jwk.KeyIDKey, "kid-1"))

		set := jwk.NewSet()
		require.NoError(t, set.AddKey(key))

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(set))
	}))
	defer jwksServer.Close()

	cfg := &model.Cfg{
		Verifier: &model.Verifier{
			Outbound: model.VerifierOutbound{OIDCProvider: &model.OIDCOP{
				DynamicRegistrationAuth: &model.DynamicRegistrationAuthConfig{
					Mode: "jwt",
					JWT: &model.DynamicRegistrationJWTAuthConfig{
						JWKSURI:           jwksServer.URL,
						Issuer:            "https://issuer.example.com",
						Audience:          "vc-verifier-register",
						AllowedSigningAlgs: []string{"RS256"},
					},
				},
			}},
		},
	}

	mw, err := NewRegistrationAuthMiddleware(cfg, logger.NewSimple("test"))
	require.NoError(t, err)

	r := gin.New()
	r.POST("/register", mw, func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	validClaims := jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"aud": "vc-verifier-register",
		"sub": "client-reg-admin",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	validToken := jwt.NewWithClaims(jwt.SigningMethodRS256, validClaims)
	validToken.Header["kid"] = "kid-1"
	validTokenString, err := validToken.SignedString(privateKey)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/register", nil)
	req.Header.Set("Authorization", "Bearer "+validTokenString)
	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, req)
	assert.Equal(t, http.StatusNoContent, resp.Code)

	invalidClaims := jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"aud": "wrong-audience",
		"sub": "client-reg-admin",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	}
	invalidToken := jwt.NewWithClaims(jwt.SigningMethodRS256, invalidClaims)
	invalidToken.Header["kid"] = "kid-1"
	invalidTokenString, err := invalidToken.SignedString(privateKey)
	require.NoError(t, err)

	req2 := httptest.NewRequest(http.MethodPost, "/register", nil)
	req2.Header.Set("Authorization", "Bearer "+invalidTokenString)
	resp2 := httptest.NewRecorder()
	r.ServeHTTP(resp2, req2)
	assert.Equal(t, http.StatusUnauthorized, resp2.Code)
}

func TestRegistrationAuthMiddleware_IntrospectionModeNotImplemented(t *testing.T) {
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

func TestStaticBearerValidator_ConstantTimeComparison(t *testing.T) {
	validator := &staticBearerValidator{token: "expected-token"}

	err := validator.Validate(t.Context(), "expected-token")
	require.NoError(t, err)

	err = validator.Validate(t.Context(), "wrong-token")
	require.Error(t, err)
	var authErr *registrationAuthError
	require.ErrorAs(t, err, &authErr)
	assert.Equal(t, "invalid_token", authErr.errorCode)
}

func TestJWTBearerValidator_RequiresConfig(t *testing.T) {
	_, err := newJWTBearerValidator(nil)
	require.Error(t, err)

	_, err = newJWTBearerValidator(&model.DynamicRegistrationJWTAuthConfig{})
	require.Error(t, err)

	_, err = newJWTBearerValidator(&model.DynamicRegistrationJWTAuthConfig{
		JWKSURI:  "https://issuer.example.com/jwks",
		Issuer:   "https://issuer.example.com",
		Audience: "vc-verifier-register",
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

func TestExtractBearerToken_CaseInsensitiveScheme(t *testing.T) {
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
