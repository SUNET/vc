package middleware

import (
	"context"
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
	errCodeInvalidToken                            = "invalid_token"
	errDescInvalidRegistrationAuthorizationToken   = "invalid registration authorization token"
	errDescMissingOrInvalidBearerToken            = "missing or invalid bearer token"
)

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
			writeRegistrationAuthError(c, unauthorizedRegistrationError(errDescMissingOrInvalidBearerToken))
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

type staticBearerValidator struct {
	token string
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

	return &staticBearerValidator{token: token}, nil
}

func (v *staticBearerValidator) Validate(_ context.Context, token string) error {
	if subtle.ConstantTimeCompare([]byte(token), []byte(v.token)) != 1 {
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
	keySet := oidc.NewRemoteKeySet(context.Background(), cfg.JWKSURI)
	verifier := oidc.NewVerifier(cfg.Issuer, keySet, &oidc.Config{
		ClientID:             cfg.Audience,
		SupportedSigningAlgs: algs,
	})

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
