package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
)

const (
	// RFC 6750 section 3.1 separates these: invalid_request is for a
	// malformed or missing Authorization header, invalid_token for a
	// syntactically valid credential that was rejected. Collapsing them
	// tells a client "your token is bad" when the real answer is "you did
	// not send one".
	errCodeInvalidRequest                        = "invalid_request"
	errCodeInvalidToken                          = "invalid_token"
	errDescInvalidRegistrationAuthorizationToken = "invalid registration authorization token"
	errDescMissingOrInvalidBearerToken           = "missing or invalid bearer token"
)

// jwksFetchTimeout bounds one JWKS fetch. Shorter than the per-request
// verification deadline below, so a slow endpoint fails the fetch rather
// than the request that triggered it.
const jwksFetchTimeout = 5 * time.Second

// RegistrationAuthValidator validates initial access tokens for dynamic client registration.
type RegistrationAuthValidator interface {
	Validate(ctx context.Context, token string) error
}

type registrationAuthError struct {
	status      int
	errorCode   string
	description string
}

func (e *registrationAuthError) Error() string {
	return e.errorCode + ": " + e.description
}

func unauthorizedRegistrationError(description string) *registrationAuthError {
	return &registrationAuthError{
		status:      http.StatusUnauthorized,
		errorCode:   errCodeInvalidToken,
		description: description,
	}
}

// malformedRequestError is the header-level failure: nothing was presented
// that could be judged as a token.
//
// 400, not 401, per RFC 6750 section 3.1. The distinction is not cosmetic:
// clients commonly treat 401 as "the token was rejected, refresh and retry",
// and answering that to a request whose Authorization header was missing or
// unparseable sends them into a refresh loop over a request that will never
// succeed until it is corrected.
func malformedRequestError(description string) *registrationAuthError {
	return &registrationAuthError{
		status:      http.StatusBadRequest,
		errorCode:   errCodeInvalidRequest,
		description: description,
	}
}

// NewRegistrationAuthMiddleware creates middleware for protecting POST /register.
//
// Modes:
//   - open: no auth required
//   - static: expects a fixed bearer token loaded from file
//   - jwt: expects a signed JWT validated against configured issuer/audience/JWKS
//
// Future option (not implemented): external introspection.
func NewRegistrationAuthMiddleware(cfg *model.Cfg, log *logger.Log) (gin.HandlerFunc, error) {
	passThrough := func(c *gin.Context) { c.Next() }
	authCfg := getDynamicRegistrationAuthConfig(cfg)
	if authCfg == nil {
		return passThrough, nil
	}

	mode := strings.ToLower(strings.TrimSpace(authCfg.Mode))
	if mode == "" || mode == "open" {
		return passThrough, nil
	}

	validator, err := buildRegistrationAuthValidator(mode, authCfg)
	if err != nil {
		return nil, err
	}

	if log != nil {
		log.Info("Dynamic registration authorization enabled", "mode", mode)
	}

	return func(c *gin.Context) {
		token, err := extractBearerToken(c.GetHeader("Authorization"))
		if err != nil {
			writeRegistrationAuthError(c, malformedRequestError(errDescMissingOrInvalidBearerToken))
			return
		}

		if err := validator.Validate(c.Request.Context(), token); err != nil {
			var authErr *registrationAuthError
			if errors.As(err, &authErr) {
				writeRegistrationAuthError(c, authErr)
				return
			}

			writeRegistrationAuthError(c, unauthorizedRegistrationError(errDescInvalidRegistrationAuthorizationToken))
			return
		}

		c.Next()
	}, nil
}

func getDynamicRegistrationAuthConfig(cfg *model.Cfg) *model.DynamicRegistrationAuthConfig {
	if cfg == nil || cfg.Verifier == nil || cfg.Verifier.Outbound.OIDCProvider == nil {
		return nil
	}

	return cfg.Verifier.Outbound.OIDCProvider.DynamicRegistrationAuth
}

func buildRegistrationAuthValidator(mode string, authCfg *model.DynamicRegistrationAuthConfig) (RegistrationAuthValidator, error) {
	switch mode {
	case "static":
		return newStaticBearerValidator(authCfg.StaticBearerTokenFile)
	case "jwt":
		return newJWTBearerValidator(authCfg.JWT)
	case "introspection":
		return nil, fmt.Errorf("verifier OIDC dynamic registration auth mode 'introspection' is not implemented yet")
	default:
		return nil, fmt.Errorf("unsupported verifier OIDC dynamic registration auth mode: %s", mode)
	}
}

func writeRegistrationAuthError(c *gin.Context, authErr *registrationAuthError) {
	c.Header("WWW-Authenticate", fmt.Sprintf("Bearer error=\"%s\"", authErr.errorCode))
	c.JSON(authErr.status, gin.H{
		"error":             authErr.errorCode,
		"error_description": authErr.description,
	})
	c.Abort()
}

func extractBearerToken(authHeader string) (string, error) {
	parts := strings.SplitN(strings.TrimSpace(authHeader), " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", fmt.Errorf("invalid authorization header")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", fmt.Errorf("empty bearer token")
	}

	return token, nil
}

// staticBearerValidator holds the expected token as a SHA-256 digest.
//
// subtle.ConstantTimeCompare returns early when the two slices differ in
// length, so comparing raw tokens is not constant-time in the length
// dimension - a caller can learn how long the expected token is by timing.
// Digests are always 32 bytes, so the comparison that matters runs over a
// fixed width regardless of what was presented.
type staticBearerValidator struct {
	tokenDigest [sha256.Size]byte
}

func newStaticBearerValidator(tokenFilePath string) (*staticBearerValidator, error) {
	if strings.TrimSpace(tokenFilePath) == "" {
		return nil, fmt.Errorf("static mode requires dynamic_registration_auth.static_bearer_token_file")
	}

	content, err := os.ReadFile(filepath.Clean(tokenFilePath))
	if err != nil {
		return nil, fmt.Errorf("failed to read static bearer token file: %w", err)
	}

	token := strings.TrimSpace(string(content))
	if token == "" {
		return nil, fmt.Errorf("static bearer token file is empty")
	}

	return &staticBearerValidator{tokenDigest: sha256.Sum256([]byte(token))}, nil
}

func (v *staticBearerValidator) Validate(_ context.Context, token string) error {
	presented := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(presented[:], v.tokenDigest[:]) != 1 {
		return unauthorizedRegistrationError(errDescInvalidRegistrationAuthorizationToken)
	}

	return nil
}

type jwtBearerValidator struct {
	verifier *oidc.IDTokenVerifier
}

func newJWTBearerValidator(cfg *model.DynamicRegistrationJWTAuthConfig) (*jwtBearerValidator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("jwt mode requires dynamic_registration_auth.jwt configuration")
	}

	if strings.TrimSpace(cfg.JWKSURI) == "" || strings.TrimSpace(cfg.Issuer) == "" || strings.TrimSpace(cfg.Audience) == "" {
		return nil, fmt.Errorf("jwt mode requires jwks_uri, issuer, and audience")
	}

	algs := cfg.AllowedSigningAlgs
	if len(algs) == 0 {
		algs = []string{"RS256", "ES256"}
	}

	// NOTE: Introspection mode is intentionally deferred.
	// JWT mode validates token signature and claims locally against JWKS.
	//
	// The key set gets its own client with a timeout, because the context
	// handed to NewRemoteKeySet is the one its fetches actually use.
	// go-oidc runs the JWKS refresh in a goroutine against that stored
	// context and selects on the caller's context only to return early - so
	// a per-request deadline unblocks the request and leaves the fetch
	// running. With http.DefaultClient, which has no timeout, a stalled
	// JWKS endpoint hangs that goroutine indefinitely; and since the
	// inflight request is only cleared when it finishes, every later
	// verification joins the same dead fetch and times out too.
	keySetCtx := oidc.ClientContext(context.Background(), &http.Client{Timeout: jwksFetchTimeout})
	keySet := oidc.NewRemoteKeySet(keySetCtx, cfg.JWKSURI)
	oidcCfg := &oidc.Config{
		ClientID:             cfg.Audience,
		SupportedSigningAlgs: algs,
	}
	// go-oidc has no leeway setting, so skew is applied by moving the clock
	// it reads. That one clock serves both time checks, in opposite
	// directions: a token that expired within the tolerance is still
	// accepted, and go-oidc's fixed five-minute nbf leeway shrinks by the
	// same amount. See ClockSkewSeconds' own doc comment.
	if cfg.ClockSkewSeconds > 0 {
		skew := time.Duration(cfg.ClockSkewSeconds) * time.Second
		oidcCfg.Now = func() time.Time { return time.Now().Add(-skew) }
	}
	verifier := oidc.NewVerifier(cfg.Issuer, keySet, oidcCfg)

	return &jwtBearerValidator{verifier: verifier}, nil
}

func (v *jwtBearerValidator) Validate(ctx context.Context, token string) error {
	verifyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if _, err := v.verifier.Verify(verifyCtx, token); err != nil {
		return unauthorizedRegistrationError(errDescInvalidRegistrationAuthorizationToken)
	}

	return nil
}
