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
	"strings"
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
		// 401 with a bare Bearer challenge: no Authorization header at all
		// is "you need to authenticate" per RFC 6750 section 3, not a
		// malformed request and not a rejected token.
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
		assert.Equal(t, "Bearer", resp.Header().Get("WWW-Authenticate"))
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

	// An absent header and a non-Bearer scheme both mean "no bearer
	// credentials were presented", which the middleware answers with a
	// challenge rather than a parse complaint. The sentinel is what carries
	// that distinction, so assert on it and not merely on "some error".
	_, err = extractBearerToken("")
	require.ErrorIs(t, err, errNoBearerCredentials)

	_, err = extractBearerToken("   ")
	require.ErrorIs(t, err, errNoBearerCredentials)

	_, err = extractBearerToken("Basic abc123")
	require.ErrorIs(t, err, errNoBearerCredentials)

	// These did use the Bearer scheme, so they are malformed requests, not
	// missing credentials.
	_, err = extractBearerToken("Bearer")
	require.Error(t, err)
	assert.NotErrorIs(t, err, errNoBearerCredentials)

	_, err = extractBearerToken("Bearer    ")
	require.Error(t, err)
	assert.NotErrorIs(t, err, errNoBearerCredentials)
}

// TestExtractBearerTokenB64TokenSyntax pins RFC 6750 section 2.1's grammar for
// the credential itself.
//
// `Bearer abc def` is the case that motivated this: the remainder is non-empty,
// so it used to reach the validator and come back as 401 invalid_token - the
// answer for a credential that was checked and refused. It is not one. No
// b64token contains a space, so the fault is in the header the client built,
// which is 400 invalid_request. The malformed and rejected cases have to stay
// distinguishable or the status code stops meaning anything.
func TestExtractBearerTokenB64TokenSyntax(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		want   string
	}{
		{"plain token", "Bearer abc123", "abc123"},
		{"jwt", "Bearer eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln", "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhIn0.c2ln"},
		{"base64 padding", "Bearer YWJjZA==", "YWJjZA=="},
		{"every allowed punctuation", "Bearer a-b.c_d~e+f/g", "a-b.c_d~e+f/g"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractBearerToken(tc.header)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	for _, tc := range []struct {
		name   string
		header string
	}{
		{"internal space", "Bearer abc def"},
		{"internal tab", "Bearer abc\tdef"},
		{"comma", "Bearer abc,def"},
		{"quoted", `Bearer "abc"`},
		{"percent", "Bearer abc%20def"},
		{"padding only", "Bearer ==="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := extractBearerToken(tc.header)
			require.Error(t, err, "a header that cannot hold a b64token is malformed, not a rejected token")
			assert.NotErrorIs(t, err, errNoBearerCredentials,
				"the Bearer scheme was used, so this is 400 invalid_request and not a challenge")
		})
	}
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

// TestRegistrationAuthHeaderErrors pins RFC 6750's three-way split, which
// this middleware previously collapsed into two.
//
//   - No bearer credentials at all (absent header, or another scheme):
//     section 3 says answer with a challenge and, explicitly, no error code.
//     401, bare `WWW-Authenticate: Bearer`, no `error` in the body. A client
//     that sent nothing has to be able to learn that a token is what it
//     needs; naming an error describes a credential it never presented.
//   - The Bearer scheme used but unparseable: invalid_request, and section
//     3.1 pairs that with 400. Not 401, which clients read as "refresh and
//     retry" and would loop on.
//   - A credential actually judged and rejected: invalid_token, 401.
func TestRegistrationAuthHeaderErrors(t *testing.T) {
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

	// Status, error code and challenge asserted together: a client keying
	// off any one of the three has to be able to tell the cases apart.
	// wantCode "" means the body must carry no error field at all.
	for _, tc := range []struct {
		name          string
		header        string
		wantCode      string
		wantStatus    int
		wantChallenge string
	}{
		{"no header at all", "", "", http.StatusUnauthorized, "Bearer"},
		{"blank header", "   ", "", http.StatusUnauthorized, "Bearer"},
		{"not a bearer scheme", "Basic dXNlcjpwYXNz", "", http.StatusUnauthorized, "Bearer"},
		{"bearer with no value", "Bearer", "invalid_request", http.StatusBadRequest, `Bearer error="invalid_request"`},
		{"bearer with blank value", "Bearer    ", "invalid_request", http.StatusBadRequest, `Bearer error="invalid_request"`},
		{"bearer with internal whitespace", "Bearer abc def", "invalid_request", http.StatusBadRequest, `Bearer error="invalid_request"`},
		{"well-formed but wrong token", "Bearer wrong", "invalid_token", http.StatusUnauthorized, `Bearer error="invalid_token"`},
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
			if got := rec.Header().Get("WWW-Authenticate"); got != tc.wantChallenge {
				t.Errorf("challenge: want %q, got %q", tc.wantChallenge, got)
			}
			if tc.wantCode == "" {
				// RFC 6750 section 3: no error code "or other error
				// information" when nothing was presented, so the
				// response carries no body at all.
				if rec.Body.Len() != 0 {
					t.Errorf("no credentials presented: response must carry no body, got %q", rec.Body.String())
				}

				return
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
		// The request parser applies RFC 6750's b64token grammar, so a file
		// holding a value outside it can never match any Authorization
		// header: the service would start, look enabled, and fail every
		// registration as invalid_request. Caught here, where the message
		// can point at the file.
		{name: "comma", contents: "abc,def\n", wantError: "b64token"},
		{name: "quotes", contents: `"s3cret"`, wantError: "b64token"},
		{name: "percent-encoded", contents: "abc%20def\n", wantError: "b64token"},
		{name: "padding only", contents: "===\n", wantError: "b64token"},
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

			// The rejection must never quote what it rejected. This error
			// is returned from New and panicked by cmd/verifier, so it
			// lands in the startup log - and the value is the registration
			// credential itself, readable by anyone who can read logs,
			// which is a far wider set than those who can read the file.
			// Asserted for every rejection case rather than the one that
			// prompted it, so a future message cannot reintroduce it.
			if trimmed := strings.TrimSpace(tc.contents); trimmed != "" {
				assert.NotContains(t, err.Error(), trimmed,
					"the startup error must not echo the token file's contents")
			}
		})
	}
}

// TestJWKSFetchRefusesNonHTTPSRedirect pins the hop the config validator
// cannot see.
//
// Requiring https on jwks_uri constrains only the first request. Go's client
// follows redirects by default, so a JWKS endpoint answering 302 to an http://
// location would have the key set - the trust root every registration token is
// judged against - fetched in the clear, with the configuration still reading
// as https.
func TestJWKSFetchRefusesNonHTTPSRedirect(t *testing.T) {
	t.Run("the redirect policy itself", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			target     string
			wantRefuse bool
		}{
			{"https to http", "http://evil.example.com/jwks.json", true},
			{"https to plain-http loopback", "http://127.0.0.1:9/jwks.json", true},
			{"https to https", "https://auth.example.com/keys.json", false},
			{"https to HTTPS uppercase", "HTTPS://auth.example.com/keys.json", false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				req, err := http.NewRequest(http.MethodGet, tc.target, nil)
				require.NoError(t, err)

				err = refuseNonHTTPSRedirect(req, nil)
				if tc.wantRefuse {
					require.Error(t, err)
					assert.Contains(t, err.Error(), "non-HTTPS")

					return
				}
				require.NoError(t, err)
			})
		}
	})

	// End to end through the client the validator actually uses, so the
	// policy cannot be correct while being wired to nothing.
	t.Run("the client refuses to follow one", func(t *testing.T) {
		final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"keys":[]}`))
		}))
		defer final.Close()

		redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, final.URL, http.StatusFound)
		}))
		defer redirector.Close()

		resp, err := newJWKSHTTPClient(nil).Get(redirector.URL)
		if resp != nil {
			_ = resp.Body.Close()
		}
		require.Error(t, err, "a redirect to a plaintext location must not be followed")
		assert.Contains(t, err.Error(), "non-HTTPS")
	})
}

// TestJWTValidateDistinguishesKeySetOutageFromBadToken pins whose fault a
// failure is.
//
// Every verification error used to come back as 401 invalid_token, including
// the ones where no verdict on the token was reached at all because the key
// set never arrived. That sends a caller off to mint a new credential that
// will fail the same way, and files a local outage under what reads as
// ordinary auth noise - so the one signal an operator would act on is the one
// that gets lost.
func TestJWTValidateDistinguishesKeySetOutageFromBadToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	key, err := jwk.Import(privateKey.Public())
	require.NoError(t, err)
	require.NoError(t, key.Set(jwk.KeyIDKey, jwtKid))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(key))
	jwksJSON, err := json.Marshal(set)
	require.NoError(t, err)

	signed := func(t *testing.T, aud string) string {
		t.Helper()
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": issuerExampleURL,
			"aud": aud,
			"sub": "client-reg-admin",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"iat": time.Now().Unix(),
		})
		token.Header["kid"] = jwtKid
		raw, err := token.SignedString(privateKey)
		require.NoError(t, err)

		return raw
	}

	validatorFor := func(t *testing.T, jwksURL string) *jwtBearerValidator {
		t.Helper()
		v, err := newJWTBearerValidator(&model.DynamicRegistrationJWTAuthConfig{
			JWKSURI:            jwksURL,
			Issuer:             issuerExampleURL,
			Audience:           registerAudience,
			AllowedSigningAlgs: []string{"RS256"},
		})
		require.NoError(t, err)

		return v
	}

	assertOutage := func(t *testing.T, err error) {
		t.Helper()
		require.Error(t, err)
		var authErr *registrationAuthError
		require.ErrorAs(t, err, &authErr)
		assert.Equal(t, http.StatusServiceUnavailable, authErr.status,
			"an unfetchable key set is this service's failure, not the caller's")
		assert.Equal(t, errCodeTemporarilyUnavailable, authErr.errorCode)
	}

	t.Run("JWKS endpoint answers 500", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer srv.Close()

		assertOutage(t, validatorFor(t, srv.URL).Validate(t.Context(), signed(t, registerAudience)))
	})

	t.Run("JWKS endpoint unreachable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(jwksJSON)
		}))
		url := srv.URL
		srv.Close() // nothing is listening any more

		assertOutage(t, validatorFor(t, url).Validate(t.Context(), signed(t, registerAudience)))
	})

	t.Run("JWKS endpoint redirects to plaintext", func(t *testing.T) {
		final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(jwksJSON)
		}))
		defer final.Close()
		redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, final.URL, http.StatusFound)
		}))
		defer redirector.Close()

		assertOutage(t, validatorFor(t, redirector.URL).Validate(t.Context(), signed(t, registerAudience)))
	})

	// HTTP 200 with a body that is not a key set. go-oidc reports this as
	// its own decode error, which is not a *url.Error - so it used to reach
	// the caller as 401 invalid_token, telling them their token was bad when
	// this service had nothing to judge it with.
	t.Run("JWKS endpoint answers 200 with malformed JSON", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys": [`))
		}))
		defer srv.Close()

		assertOutage(t, validatorFor(t, srv.URL).Validate(t.Context(), signed(t, registerAudience)))
	})

	t.Run("JWKS endpoint answers 200 with a document that is not a key set", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html>maintenance</html>`))
		}))
		defer srv.Close()

		assertOutage(t, validatorFor(t, srv.URL).Validate(t.Context(), signed(t, registerAudience)))
	})

	// `{"keys":[]}` produces NO error from the fetch at all. Verification
	// then fails for want of a matching key, which is indistinguishable from
	// a token signed by a key the issuer never published - except that here
	// the issuer published nothing, and this service has no key set.
	t.Run("JWKS endpoint answers 200 with an empty key set", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		}))
		defer srv.Close()

		assertOutage(t, validatorFor(t, srv.URL).Validate(t.Context(), signed(t, registerAudience)))
	})

	// go-oidc DROPS a JWK it cannot use and returns no error, so a key set
	// of nothing but those parses to an empty set and the verification then
	// fails as invalid_token. Counting raw entries missed exactly that: the
	// response has a key, and the verifier has none.
	for name, keys := range map[string]string{
		"only a symmetric secret":  `{"keys":[{"kty":"oct","k":"c2VjcmV0","kid":"` + jwtKid + `"}]}`,
		"only a symmetric alg":     `{"keys":[{"kty":"oct","alg":"HS256","k":"c2VjcmV0","kid":"` + jwtKid + `"}]}`,
		"an RSA key with alg none": `{"keys":[{"kty":"RSA","alg":"none","n":"AQAB","e":"AQAB","kid":"` + jwtKid + `"}]}`,
	} {
		t.Run("JWKS endpoint answers 200 with "+name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(keys))
			}))
			defer srv.Close()

			assertOutage(t, validatorFor(t, srv.URL).Validate(t.Context(), signed(t, registerAudience)))
		})
	}

	// Metadata alone is not enough. go-oidc PARSES each JWK, so an entry
	// that looks right by kty and alg and cannot actually be decoded left
	// the verifier with no key set while the caller was told invalid_token.
	for name, keys := range map[string]string{
		"an RSA key with no n or e": `{"keys":[{"kty":"RSA","alg":"RS256","kid":"` + jwtKid + `"}]}`,
		"an EC key with no curve":   `{"keys":[{"kty":"EC","alg":"ES256","kid":"` + jwtKid + `"}]}`,
		"a key usable only for an algorithm this verifier does not accept": `{"keys":[{"kty":"RSA","alg":"PS512","n":"AQAB","e":"AQAB","kid":"` + jwtKid + `"}]}`,
	} {
		t.Run("JWKS endpoint answers 200 with "+name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(keys))
			}))
			defer srv.Close()

			assertOutage(t, validatorFor(t, srv.URL).Validate(t.Context(), signed(t, registerAudience)))
		})
	}

	// And a real key alongside an ignorable one is still a key set: go-oidc
	// skips a key whose alg it does not support rather than failing the
	// whole set, so this verifier must not fail it either.
	t.Run("a usable key beside an ignorable one is still a key set", func(t *testing.T) {
		var set map[string]any
		require.NoError(t, json.Unmarshal(jwksJSON, &set))
		set["keys"] = append([]any{map[string]any{"kty": "oct", "k": "c2VjcmV0", "kid": "ignore-me"}},
			set["keys"].([]any)...)
		mixed, err := json.Marshal(set)
		require.NoError(t, err)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(mixed)
		}))
		defer srv.Close()

		require.NoError(t, validatorFor(t, srv.URL).Validate(t.Context(), signed(t, registerAudience)))
	})

	// The contrast case: the key set arrived and the token lost on its
	// merits, which must stay 401 invalid_token.
	t.Run("key set fine, token rejected", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksJSON)
		}))
		defer srv.Close()

		err := validatorFor(t, srv.URL).Validate(t.Context(), signed(t, "wrong-audience"))
		require.Error(t, err)
		var authErr *registrationAuthError
		require.ErrorAs(t, err, &authErr)
		assert.Equal(t, http.StatusUnauthorized, authErr.status)
		assert.Equal(t, errCodeInvalidToken, authErr.errorCode)
	})

	t.Run("a good token still passes", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksJSON)
		}))
		defer srv.Close()

		require.NoError(t, validatorFor(t, srv.URL).Validate(t.Context(), signed(t, registerAudience)))
	})
}
